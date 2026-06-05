import subprocess
import asyncio
import logging
import threading
import ipaddress
import collections
import time
import structlog
from typing import Dict, Set, List, Any, Optional
import redis

from common.config import (
    REPUTATION_LIMIT, REPUTATION_TEMP_BLOCK, REPUTATION_PERM_BLOCK,
    BLOCK_TTL, RATE_LIMIT_PER_SEC, get_protected_ips,
    REDIS_HOST, REDIS_PORT, REDIS_DB,
    SDN_ENABLED, SDN_CONTROLLER_HOST, SDN_CONTROLLER_PORT, SDN_FALLBACK_TO_IPSET,
    SDN_HONEYPOT_IP, EBPF_ENABLED, EBPF_INTERFACE
)
from ml_engine.sdn_client import SDNClient
from ml_engine.ebpf_mitigation import EBPFMitigationManager
from common.metrics import PROM_REPUTATION, PROM_BLOCKED, PROM_TEMP_BLOCKED, PROM_MITIGATIONS_TOTAL

logger = structlog.get_logger(__name__)

class ActiveFirewall:
    """
    Adaptive Mitigation System (IPS).
    Handles Reputation scoring, TTL-based blocking, and Decay logic.
    Supports dual-mode: legacy (ipset/iptables) and sdn (Ryu Controller).
    """
    
    _lock: Optional[asyncio.Lock] = None
    _protected_ips: Set[str] = set()
    _redis_client: Optional[redis.Redis] = None
    _sdn_client: Optional[SDNClient] = None
    _ebpf_manager: Optional[EBPFMitigationManager] = None
    _initialized = False
    _backend = "legacy" # Default to legacy
    _decay_task: Optional[asyncio.Task] = None
    _kernel_sets_initialized = False
    
    # Redis Keys
    REDIS_REPUTATION_KEY = "sentinel_reputation"
    
    # ipset set names (legacy mode)
    SET_BLOCKS = "sentinel_blocks"
    SET_LIMITED = "sentinel_limited"
    SET_BLOCKS_V6 = "sentinel_blocks_v6"
    SET_LIMITED_V6 = "sentinel_limited_v6"


    @classmethod
    async def _initialize(cls):
        """Setup backend and background decay task."""
        if cls._lock is None:
            cls._lock = asyncio.Lock()
            
        async with cls._lock:
            if cls._initialized: return
            cls._protected_ips = get_protected_ips()
            
            # Determine backend
            if SDN_ENABLED:
                cls._backend = "sdn"
                cls._sdn_client = SDNClient(f"http://{SDN_CONTROLLER_HOST}:{SDN_CONTROLLER_PORT}")
                logger.info("Mitigation Backend set to SDN", controller=f"{SDN_CONTROLLER_HOST}:{SDN_CONTROLLER_PORT}")
            else:
                cls._backend = "legacy"
                logger.info("Mitigation Backend set to LEGACY (ipset/iptables)")
            
            # Setup eBPF manager if enabled
            if EBPF_ENABLED:
                cls._ebpf_manager = EBPFMitigationManager(interface=EBPF_INTERFACE)
                loop = asyncio.get_running_loop()
                success = await loop.run_in_executor(None, cls._ebpf_manager.load_xdp)
                if success:
                    logger.info("eBPF/XDP mitigation backend enabled", interface=EBPF_INTERFACE)
                else:
                    logger.warning("eBPF/XDP mitigation backend failed to load, falling back to standard mechanisms")
            
            # ALWAYS setup kernel sets for fallback reliability
            await cls._ensure_kernel_sets()
            
            # Initialize Redis connection for shared reputation
            try:
                cls._redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
            except Exception as e:
                logger.error("Failed to connect to Redis for reputation", error=str(e))
            
            cls._initialized = True
            
            # Start decay task instead of thread
            cls._decay_task = asyncio.create_task(cls._decay_loop())
            
            # Cold-start: Load existing high-reputation offenders from Redis into backend
            await cls._repopulate_from_reputation()
            
            logger.info("IPS Firewall initialized", shared_reputation=True, protected_count=len(cls._protected_ips))

    @classmethod
    async def close(cls):
        """Release long-lived mitigation resources when shutting down."""
        if cls._lock is None: return
        
        async with cls._lock:
            if cls._decay_task:
                cls._decay_task.cancel()
                try:
                    await cls._decay_task
                except asyncio.CancelledError:
                    pass
                cls._decay_task = None

            if cls._ebpf_manager is not None:
                try:
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(None, cls._ebpf_manager.unload_xdp)
                except Exception as e:
                    logger.warning("Failed to unload eBPF XDP program cleanly", error=str(e))
                finally:
                    cls._ebpf_manager = None

            if cls._sdn_client is None:
                return

            try:
                await cls._sdn_client.close()
            except Exception as e:
                logger.warning("Failed to close SDN client cleanly", error=str(e))
            finally:
                cls._sdn_client = None

    @classmethod
    def _setup_kernel_sets(cls):
        """Initialize ipset sets and the custom iptables/ip6tables chains (Legacy mode)."""
        try:
            # 1. Create ipset sets with timeout support
            def create_set_safe(name, params):
                res = subprocess.run(["sudo", "ipset", "create", name] + params + ["-!"], capture_output=True)
                if res.returncode != 0:
                    logger.warning(f"ipset {name} creation failed. Flushing iptables/ip6tables and recreating...", error=res.stderr.decode())
                    subprocess.run(["sudo", "iptables", "-F", "SENTINEL_IPS"], check=False)
                    subprocess.run(["sudo", "ip6tables", "-F", "SENTINEL_IPS_V6"], check=False)
                    subprocess.run(["sudo", "ipset", "destroy", name], check=False)
                    subprocess.run(["sudo", "ipset", "create", name] + params + ["-!"], check=True)

            create_set_safe(cls.SET_BLOCKS, ["hash:ip", "timeout", "0"])
            create_set_safe(cls.SET_LIMITED, ["hash:ip", "timeout", "3600"])
            create_set_safe(cls.SET_BLOCKS_V6, ["hash:ip", "family", "inet6", "timeout", "0"])
            create_set_safe(cls.SET_LIMITED_V6, ["hash:ip", "family", "inet6", "timeout", "3600"])

            # 2. Ensure iptables chain exists and rules are present (IPv4)
            CHAIN_NAME = "SENTINEL_IPS"
            subprocess.run(["sudo", "iptables", "-N", CHAIN_NAME], check=False)
            subprocess.run(["sudo", "iptables", "-F", CHAIN_NAME], check=True)

            subprocess.run(["sudo", "iptables", "-A", CHAIN_NAME, "-m", "set", "--match-set", cls.SET_BLOCKS, "src", "-j", "DROP"], check=True)
            subprocess.run([
                "sudo", "iptables", "-A", CHAIN_NAME, 
                "-m", "set", "--match-set", cls.SET_LIMITED, "src",
                "-m", "hashlimit", "--hashlimit-upto", f"{RATE_LIMIT_PER_SEC}/sec", 
                "--hashlimit-burst", "10", "--hashlimit-mode", "srcip", 
                "--hashlimit-name", "sentinel_rl", "-j", "RETURN"
            ], check=True)
            subprocess.run(["sudo", "iptables", "-A", CHAIN_NAME, "-m", "set", "--match-set", cls.SET_LIMITED, "src", "-j", "DROP"], check=True)

            # 2_v6. Ensure ip6tables chain exists and rules are present (IPv6)
            CHAIN_NAME_V6 = "SENTINEL_IPS_V6"
            subprocess.run(["sudo", "ip6tables", "-N", CHAIN_NAME_V6], check=False)
            subprocess.run(["sudo", "ip6tables", "-F", CHAIN_NAME_V6], check=True)

            subprocess.run(["sudo", "ip6tables", "-A", CHAIN_NAME_V6, "-m", "set", "--match-set", cls.SET_BLOCKS_V6, "src", "-j", "DROP"], check=True)
            subprocess.run([
                "sudo", "ip6tables", "-A", CHAIN_NAME_V6, 
                "-m", "set", "--match-set", cls.SET_LIMITED_V6, "src",
                "-m", "hashlimit", "--hashlimit-upto", f"{RATE_LIMIT_PER_SEC}/sec", 
                "--hashlimit-burst", "10", "--hashlimit-mode", "srcip", 
                "--hashlimit-name", "sentinel_rl_v6", "-j", "RETURN"
            ], check=True)
            subprocess.run(["sudo", "ip6tables", "-A", CHAIN_NAME_V6, "-m", "set", "--match-set", cls.SET_LIMITED_V6, "src", "-j", "DROP"], check=True)

            # 2b. Ensure SENTINEL_MICRO and SENTINEL_MICRO_V6 chains exist
            MICRO_CHAIN = "SENTINEL_MICRO"
            subprocess.run(["sudo", "iptables", "-N", MICRO_CHAIN], check=False)

            MICRO_CHAIN_V6 = "SENTINEL_MICRO_V6"
            subprocess.run(["sudo", "ip6tables", "-N", MICRO_CHAIN_V6], check=False)

            # 3. Hook into INPUT/FORWARD for IPv4 (iptables)
            for target in ["INPUT", "FORWARD"]:
                hook_check = subprocess.run(["sudo", "iptables", "-C", target, "-j", CHAIN_NAME], capture_output=True)
                if hook_check.returncode != 0:
                    subprocess.run(["sudo", "iptables", "-I", target, "1", "-j", CHAIN_NAME], check=True)
                micro_check = subprocess.run(["sudo", "iptables", "-C", target, "-j", MICRO_CHAIN], capture_output=True)
                if micro_check.returncode != 0:
                    subprocess.run(["sudo", "iptables", "-I", target, "1", "-j", MICRO_CHAIN], check=True)

            # 3_v6. Hook into INPUT/FORWARD for IPv6 (ip6tables)
            for target in ["INPUT", "FORWARD"]:
                hook_check_v6 = subprocess.run(["sudo", "ip6tables", "-C", target, "-j", CHAIN_NAME_V6], capture_output=True)
                if hook_check_v6.returncode != 0:
                    subprocess.run(["sudo", "ip6tables", "-I", target, "1", "-j", CHAIN_NAME_V6], check=True)
                micro_check_v6 = subprocess.run(["sudo", "ip6tables", "-C", target, "-j", MICRO_CHAIN_V6], capture_output=True)
                if micro_check_v6.returncode != 0:
                    subprocess.run(["sudo", "ip6tables", "-I", target, "1", "-j", MICRO_CHAIN_V6], check=True)
                
            cls._kernel_sets_initialized = True
            logger.info("Kernel firewall rules synchronized (Dual Stack IPv4/IPv6)", chain=CHAIN_NAME, chain_v6=CHAIN_NAME_V6)
        except Exception as e:
            cls._kernel_sets_initialized = False
            logger.error("Failed to setup kernel firewall", error=str(e))

    @classmethod
    async def _ensure_kernel_sets(cls):
        """Ensures that kernel sets are initialized. Retries if not yet initialized."""
        if not cls._kernel_sets_initialized:
            logger.info("Kernel firewall rules not initialized. Retrying setup...")
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, cls._setup_kernel_sets)


    @classmethod
    async def _repopulate_from_reputation(cls):
        """On startup, read Redis reputation and re-block active offenders."""
        if not cls._redis_client: return
        try:
            loop = asyncio.get_running_loop()
            reputation = await loop.run_in_executor(None, cls._redis_client.hgetall, cls.REDIS_REPUTATION_KEY)
            
            count = 0
            for ip, score in reputation.items():
                s = float(score)
                if s >= REPUTATION_PERM_BLOCK:
                    await cls.block(ip, ttl=0)
                    count += 1
                elif s >= REPUTATION_TEMP_BLOCK:
                    await cls.block(ip, ttl=BLOCK_TTL)
                    count += 1
            if count > 0:
                logger.info("Firewall cold-start complete", reblocked_count=count)
        except Exception as e:
            logger.error("Failed to repopulate firewall from Redis", error=str(e))

    @classmethod
    async def _decay_loop(cls):
        """Decays reputation scores every minute."""
        while True:
            await asyncio.sleep(60)
            if not cls._redis_client: continue
            
            try:
                loop = asyncio.get_running_loop()
                lua_decay = """
                local key = KEYS[1]
                local cursor = "0"
                local rehab = {}
                repeat
                    local res = redis.call("HSCAN", key, cursor)
                    cursor = res[1]
                    local data = res[2]
                    for i = 1, #data, 2 do
                        local ip, score = data[i], tonumber(data[i+1])
                        local new_score = score * tonumber(ARGV[1])
                        if score >= tonumber(ARGV[3]) and new_score < tonumber(ARGV[3]) then
                            table.insert(rehab, ip)
                        end
                        if new_score < tonumber(ARGV[2]) then
                            redis.call("HDEL", key, ip)
                        else
                            redis.call("HSET", key, ip, new_score)
                        end
                    end
                until cursor == "0"
                return rehab
                """
                rehabilitated_ips = await loop.run_in_executor(
                    None, 
                    lambda: cls._redis_client.register_script(lua_decay)(
                        keys=[cls.REDIS_REPUTATION_KEY], 
                        args=[0.9, 0.1, REPUTATION_TEMP_BLOCK]
                    )
                )
                for ip in rehabilitated_ips:
                    is_final = False
                    if cls._redis_client:
                        is_final = await loop.run_in_executor(None, cls._redis_client.sismember, "sentinel_final_blocks", ip)
                    if is_final:
                        logger.info("IP rehabilitation skipped (manually finalized block)", ip=ip)
                    else:
                        logger.info("IP rehabilitated via atomic decay", ip=ip)
                        await cls.unblock(ip)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Decay loop failed", error=str(e))

    @classmethod
    async def is_banning_disabled(cls) -> bool:
        """Checks if automatic banning is disabled via Redis key 'sentinel_banning_disabled'."""
        if not cls._initialized: await cls._initialize()
        if not cls._redis_client: return False
        try:
            loop = asyncio.get_running_loop()
            val = await loop.run_in_executor(None, cls._redis_client.get, "sentinel_banning_disabled")
            return val == "true"
        except Exception as e:
            logger.error("Failed to check if banning is disabled", error=str(e))
            return False

    @classmethod
    async def set_banning_disabled(cls, disabled: bool) -> bool:
        """Sets automatic banning state in Redis."""
        if not cls._initialized: await cls._initialize()
        if not cls._redis_client: return False
        try:
            loop = asyncio.get_running_loop()
            val = "true" if disabled else "false"
            await loop.run_in_executor(None, cls._redis_client.set, "sentinel_banning_disabled", val)
            logger.info("Banning status updated dynamically", disabled=disabled)
            return True
        except Exception as e:
            logger.error("Failed to set banning status", error=str(e))
            return False

    @classmethod
    async def process_incident(cls, src_ip: str, delta: float) -> str:
        """
        Updates IP reputation and triggers mitigation if thresholds reached.
        Returns: action taken
        """
        if not cls._initialized: await cls._initialize()
        
        if src_ip in cls._protected_ips:
            return "skipped"

        if cls._redis_client:
            loop = asyncio.get_running_loop()
            is_whitelisted = await loop.run_in_executor(None, cls._redis_client.sismember, "sentinel_whitelisted_ips", src_ip)
            if is_whitelisted:
                logger.info("Incident Processing Bypassed: IP is dynamically whitelisted", ip=src_ip)
                return "skipped"

        if not cls._redis_client: return "logged"
        
        try:
            loop = asyncio.get_running_loop()
            new_score = await loop.run_in_executor(None, cls._redis_client.hincrbyfloat, cls.REDIS_REPUTATION_KEY, src_ip, delta)
            
            if new_score < 0: 
                await loop.run_in_executor(None, cls._redis_client.hset, cls.REDIS_REPUTATION_KEY, src_ip, 0)
                return "logged"

            if new_score >= REPUTATION_PERM_BLOCK:
                if await cls.is_banning_disabled():
                    logger.info("Mitigation Bypassed: permanent_block threshold reached but banning is disabled", ip=src_ip, score=new_score)
                    return "logged"
                success = await cls.block(src_ip, ttl=0)
                if success:
                    PROM_MITIGATIONS_TOTAL.labels(action="permanent_block").inc()
                    return "permanent_block" if delta > 0 else "logged"
                else:
                    return "logged"
            elif new_score >= REPUTATION_TEMP_BLOCK:
                if await cls.is_banning_disabled():
                    logger.info("Mitigation Bypassed: temp_block threshold reached but banning is disabled", ip=src_ip, score=new_score)
                    return "logged"
                success = await cls.block(src_ip, ttl=BLOCK_TTL)
                if success:
                    PROM_MITIGATIONS_TOTAL.labels(action="temp_block").inc()
                    return "temp_block" if delta > 0 else "logged"
                else:
                    return "logged"
            elif new_score >= REPUTATION_LIMIT:
                if await cls.is_banning_disabled():
                    logger.info("Mitigation Bypassed: rate_limit threshold reached but banning is disabled", ip=src_ip, score=new_score)
                    return "logged"
                success = await cls.rate_limit(src_ip)
                if success:
                    PROM_MITIGATIONS_TOTAL.labels(action="rate_limit").inc()
                    return "rate_limit" if delta > 0 else "logged"
                else:
                    return "logged"
            
            return "logged"
        except Exception as e:
            logger.error("Reputation update failed", ip=src_ip, error=str(e))
            return "logged"

    @classmethod
    async def block(cls, ip: str, ttl: int = 0) -> bool:
        """Adds IP to block set or installs SDN flow."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error("Invalid IP address format", ip=ip)
            return False
        
        if not cls._initialized: await cls._initialize()
        if cls._redis_client:
            loop = asyncio.get_running_loop()
            is_whitelisted = await loop.run_in_executor(None, cls._redis_client.sismember, "sentinel_whitelisted_ips", ip)
            if is_whitelisted:
                logger.info("Mitigation Block Bypassed: IP is dynamically whitelisted", ip=ip)
                return False

        cls._status_cache = {}
        cls._status_cache_time = 0
        
        success = False
        
        # 1. Apply eBPF block if enabled
        if EBPF_ENABLED and cls._ebpf_manager:
            loop = asyncio.get_running_loop()
            ebpf_success = await loop.run_in_executor(None, cls._ebpf_manager.block_ip, ip)
            if ebpf_success:
                success = True

        # 2. Apply backend block
        if cls._backend == "sdn" and cls._sdn_client:
            try:
                sdn_success = await cls._sdn_client.block(ip, ttl)
                if sdn_success:
                    success = True
            except Exception as e:
                logger.error("SDN block failed", error=str(e))
                if SDN_FALLBACK_TO_IPSET:
                    logger.warning("Falling back to ipset for block", ip=ip)
                    legacy_success = await cls._legacy_block(ip, ttl)
                    if legacy_success:
                        success = True
        else:
            legacy_success = await cls._legacy_block(ip, ttl)
            if legacy_success:
                success = True
            
        if success and ttl == 0 and cls._redis_client:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, cls._redis_client.hset, cls.REDIS_REPUTATION_KEY, ip, REPUTATION_PERM_BLOCK)
        
        return success

    @classmethod
    async def _legacy_block(cls, ip: str, ttl: int = 0) -> bool:
        try:
            await cls._ensure_kernel_sets()
            ip_obj = ipaddress.ip_address(ip)
            is_v6 = ip_obj.version == 6
            target_set = cls.SET_BLOCKS_V6 if is_v6 else cls.SET_BLOCKS

            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, lambda: subprocess.run(["sudo", "ipset", "add", target_set, ip, "timeout", str(ttl), "-!"], check=True))
            logger.warning(f"Legacy {'IPv6 ' if is_v6 else ''}Block (ipset)", ip=ip, ttl=ttl)
            return True
        except Exception as e:
            logger.error("Legacy block failed", ip=ip, error=str(e))
            return False

    @classmethod
    async def rate_limit(cls, ip: str):
        """Adds IP to rate-limited set."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            is_v6 = ip_obj.version == 6
            target_set = cls.SET_LIMITED_V6 if is_v6 else cls.SET_LIMITED
        except ValueError:
            logger.error("Invalid IP address format", ip=ip)
            return False
        
        if not cls._initialized: await cls._initialize()
        if cls._redis_client:
            loop = asyncio.get_running_loop()
            is_whitelisted = await loop.run_in_executor(None, cls._redis_client.sismember, "sentinel_whitelisted_ips", ip)
            if is_whitelisted:
                logger.info("Mitigation Rate Limit Bypassed: IP is dynamically whitelisted", ip=ip)
                return False

        await cls._ensure_kernel_sets()
        cls._status_cache = {}
        cls._status_cache_time = 0
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, lambda: subprocess.run(["sudo", "ipset", "add", target_set, ip, "-!"], check=True))
            logger.warning(f"IP {'IPv6 ' if is_v6 else ''}Rate Limited", ip=ip)
            return True
        except Exception as e:
            logger.error("Rate limit operation failed", ip=ip, error=str(e))
            return False

    @classmethod
    async def unblock(cls, ip: str):
        """Removes IP from both blocks and clears shared reputation."""
        if not cls._initialized: await cls._initialize()
        await cls._ensure_kernel_sets()
        cls._status_cache = {}
        cls._status_cache_time = 0
        
        # Remove from eBPF map if enabled
        if EBPF_ENABLED and cls._ebpf_manager:
            try:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, cls._ebpf_manager.unblock_ip, ip)
            except Exception as e:
                logger.error("eBPF unblock failed", error=str(e))
        
        if cls._backend == "sdn" and cls._sdn_client:
            try:
                await cls._sdn_client.unblock(ip)
            except Exception as e:
                logger.error("SDN unblock failed", error=str(e))
        
        try:
            try:
                ip_obj = ipaddress.ip_address(ip)
                is_v6 = ip_obj.version == 6
                blocks_set = cls.SET_BLOCKS_V6 if is_v6 else cls.SET_BLOCKS
                limited_set = cls.SET_LIMITED_V6 if is_v6 else cls.SET_LIMITED
            except ValueError:
                logger.error("Invalid IP address format during unblock", ip=ip)
                return

            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, lambda: subprocess.run(["sudo", "ipset", "del", blocks_set, ip, "-!"], check=False))
            await loop.run_in_executor(None, lambda: subprocess.run(["sudo", "ipset", "del", limited_set, ip, "-!"], check=False))
            
            if cls._redis_client:
                await loop.run_in_executor(None, cls._redis_client.hdel, cls.REDIS_REPUTATION_KEY, ip)
            logger.info("IP Unblocked manually", ip=ip)
        except Exception as e:
            logger.error("Unblock operation failed", ip=ip, error=str(e))

    @classmethod
    async def is_blocked(cls, ip: str) -> bool:
        """Checks if an IP is currently in the block set (permanent or temporary)."""
        if not cls._initialized: await cls._initialize()
        
        # Check eBPF map if enabled
        if EBPF_ENABLED and cls._ebpf_manager:
            loop = asyncio.get_running_loop()
            if await loop.run_in_executor(None, cls._ebpf_manager.is_blocked, ip):
                return True

        await cls._ensure_kernel_sets()
        try:
            ip_obj = ipaddress.ip_address(ip)
            is_v6 = ip_obj.version == 6
            target_set = cls.SET_BLOCKS_V6 if is_v6 else cls.SET_BLOCKS

            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["sudo", "ipset", "test", target_set, ip],
                    capture_output=True,
                    check=False
                )
            )
            return result.returncode == 0
        except Exception:
            return False


    # Caching for detailed status
    _status_cache: Dict[str, Any] = {}
    _status_cache_time: float = 0
    _status_cache_ttl: int = 5
    _status_lock = asyncio.Lock()

    @classmethod
    async def get_status(cls) -> Dict[str, Any]:
        """Returns summary counts."""
        detailed = await cls.get_detailed_status()
        return {
            "backend": cls._backend,
            "permanent": len(detailed["permanent_ips"]),
            "temporary": len(detailed["temporary_ips"]),
            "reputation_tracked": len(detailed["reputation"]),
            "banning_disabled": await cls.is_banning_disabled()
        }

    @classmethod
    async def get_detailed_status(cls) -> Dict[str, Any]:
        """Returns actual list of IPs with TTL-based caching."""
        await cls._ensure_kernel_sets()
        async with cls._status_lock:
            now = time.time()
            if cls._status_cache and (now - cls._status_cache_time) < cls._status_cache_ttl:
                return cls._status_cache

            perm = []
            temp = []
            reputation = {}
            final_blocked = []
            whitelisted = []
            
            if cls._redis_client:
                try:
                    loop = asyncio.get_running_loop()
                    reputation = await loop.run_in_executor(None, cls._redis_client.hgetall, cls.REDIS_REPUTATION_KEY)
                    reputation = {k: float(v) for k, v in reputation.items()}
                    
                    # Fetch dynamic whitelist
                    wl_set = await loop.run_in_executor(None, cls._redis_client.smembers, "sentinel_whitelisted_ips")
                    whitelisted = sorted([str(i) for i in wl_set]) if wl_set else []

                    # Fetch operator finalized blocks
                    fb_set = await loop.run_in_executor(None, cls._redis_client.smembers, "sentinel_final_blocks")
                    final_blocked = sorted([str(i) for i in fb_set]) if fb_set else []
                except Exception as e:
                    logger.error("Failed to fetch Redis blocks/whitelist", error=str(e))

            if cls._backend == "sdn" and cls._sdn_client:
                try:
                    sdn_flows = await cls._sdn_client.get_flows()
                    perm.extend(sdn_flows.get("blocked_ips", []))
                except Exception as e:
                    logger.error("SDN flow fetch failed", error=str(e))

            def _parse_ipset(set_name):
                ips = {"perm": [], "temp": []}
                try:
                    result = subprocess.run(["sudo", "ipset", "list", set_name], capture_output=True, text=True)
                    if result.returncode == 0:
                        lines = result.stdout.splitlines()
                        in_members = False
                        for line in lines:
                            if line.startswith("Members:"):
                                in_members = True
                                continue
                            if in_members and line.strip():
                                parts = line.split()
                                ip = parts[0]
                                # ipset list format: "1.2.3.4 timeout 123" or "fe80:: timeout 123"
                                timeout = 0
                                if "timeout" in parts:
                                    try:
                                        t_idx = parts.index("timeout")
                                        timeout = int(parts[t_idx+1])
                                    except (ValueError, IndexError):
                                        timeout = 0
                                if timeout == 0: ips["perm"].append(ip)
                                else: ips["temp"].append(ip)
                except Exception as e:
                    logger.error(f"Failed to list ipset members for {set_name}", error=str(e))
                return ips

            loop = asyncio.get_running_loop()
            sets_data = await loop.run_in_executor(None, lambda: [
                _parse_ipset(cls.SET_BLOCKS), 
                _parse_ipset(cls.SET_LIMITED),
                _parse_ipset(cls.SET_BLOCKS_V6),
                _parse_ipset(cls.SET_LIMITED_V6)
            ])
            
            perm.extend(sets_data[0]["perm"])
            perm.extend(sets_data[2]["perm"]) # IPv6 permanent
            
            temp.extend(sets_data[0]["temp"])
            temp.extend(sets_data[2]["temp"]) # IPv6 temporary
            
            temp.extend(sets_data[1]["perm"]) # Limited is temporary by nature
            temp.extend(sets_data[1]["temp"])
            temp.extend(sets_data[3]["perm"]) # IPv6 limited is temporary by nature
            temp.extend(sets_data[3]["temp"])
            
            # Deduplicate and sort
            perm = sorted(list(set(perm) - set(final_blocked)))
            temp = sorted(list(set(temp)))
            
            result = {
                "permanent_ips": perm,
                "temporary_ips": temp,
                "reputation": reputation,
                "final_blocked_ips": final_blocked,
                "whitelisted_ips": whitelisted
            }
            
            # Update Prometheus Gauges
            PROM_BLOCKED.set(len(perm) + len(final_blocked))
            PROM_TEMP_BLOCKED.set(len(temp))
            PROM_REPUTATION.set(len(reputation))
            
            cls._status_cache = result
            cls._status_cache_time = now
            return result

    @classmethod
    async def micro_block(cls, ip: str, protocol: str, dport: int, ttl: int = 300) -> bool:
        """Adds a fine-grained block (IP, protocol, port) to the SENTINEL_MICRO or SENTINEL_MICRO_V6 chains."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error("Invalid IP address format for microblock", ip=ip)
            return False

        if not cls._initialized: await cls._initialize()
        cls._status_cache = {}
        cls._status_cache_time = 0

        success = False
        if cls._backend == "sdn" and cls._sdn_client:
            try:
                success = await cls._sdn_client.block_shape(ip, protocol, dport, ttl)
            except Exception as e:
                logger.error("SDN micro block failed", error=str(e))
                if SDN_FALLBACK_TO_IPSET:
                    logger.warning("Falling back to legacy micro block", ip=ip)
                    success = await cls._legacy_micro_block(ip, protocol, dport, ttl)
        else:
            success = await cls._legacy_micro_block(ip, protocol, dport, ttl)

        return success

    @classmethod
    async def _legacy_micro_block(cls, ip: str, protocol: str, dport: int, ttl: int = 300) -> bool:
        try:
            await cls._ensure_kernel_sets()
            ip_obj = ipaddress.ip_address(ip)
            is_v6 = ip_obj.version == 6
            iptables_cmd = "ip6tables" if is_v6 else "iptables"
            micro_chain = "SENTINEL_MICRO_V6" if is_v6 else "SENTINEL_MICRO"

            loop = asyncio.get_running_loop()
            proto = protocol.lower()
            # Install dynamic drop rule
            await loop.run_in_executor(
                None, 
                lambda: subprocess.run(
                    ["sudo", iptables_cmd, "-A", micro_chain, "-s", ip, "-p", proto, "--dport", str(dport), "-j", "DROP"], 
                    check=True
                )
            )
            logger.warning(f"Legacy {'IPv6 ' if is_v6 else ''}Micro-Block applied", ip=ip, proto=proto, port=dport, ttl=ttl)

            # Schedule asynchronous background deletion
            if ttl > 0:
                async def cleanup():
                    await asyncio.sleep(ttl)
                    try:
                        loop = asyncio.get_running_loop()
                        await loop.run_in_executor(
                            None,
                            lambda: subprocess.run(
                                ["sudo", iptables_cmd, "-D", micro_chain, "-s", ip, "-p", proto, "--dport", str(dport), "-j", "DROP"],
                                check=False
                            )
                        )
                        logger.info(f"Legacy {'IPv6 ' if is_v6 else ''}Micro-Block expired and deleted", ip=ip, proto=proto, port=dport)
                    except Exception as err:
                        logger.error("Failed to delete expired legacy micro-block rule", error=str(err))
                
                asyncio.create_task(cleanup())
            return True
        except Exception as e:
            logger.error("Legacy micro block failed", ip=ip, error=str(e))
            return False

    @classmethod
    async def redirect_to_honeypot(cls, ip: str, ttl: int = 300) -> bool:
        """Redirects all traffic from a source IP to the honeypot decoy IP."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error("Invalid IP address format for honeypot redirect", ip=ip)
            return False

        if not cls._initialized: await cls._initialize()
        cls._status_cache = {}
        cls._status_cache_time = 0

        success = False
        if cls._backend == "sdn" and cls._sdn_client:
            try:
                success = await cls._sdn_client.redirect_to_honeypot(ip, SDN_HONEYPOT_IP, ttl)
            except Exception as e:
                logger.error("SDN honeypot redirect failed", error=str(e))
                if SDN_FALLBACK_TO_IPSET:
                    logger.warning("Falling back to legacy honeypot redirect", ip=ip)
                    success = await cls._legacy_redirect_to_honeypot(ip, ttl)
        else:
            success = await cls._legacy_redirect_to_honeypot(ip, ttl)

        return success

    @classmethod
    async def _legacy_redirect_to_honeypot(cls, ip: str, ttl: int = 300) -> bool:
        try:
            await cls._ensure_kernel_sets()
            if ipaddress.ip_address(ip).version == 6:
                logger.warning("Skipping IPv6 redirect (not yet supported)", ip=ip)
                return False

            loop = asyncio.get_running_loop()
            
            # Setup dynamic DNAT rule in the PREROUTING chain of the nat table
            await loop.run_in_executor(
                None, 
                lambda: subprocess.run(
                    ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-s", ip, "-j", "DNAT", "--to-destination", SDN_HONEYPOT_IP], 
                    check=True
                )
            )
            logger.warning("Legacy Honeypot DNAT Redirection applied", ip=ip, destination=SDN_HONEYPOT_IP, ttl=ttl)

            # Schedule asynchronous background deletion
            if ttl > 0:
                async def cleanup():
                    await asyncio.sleep(ttl)
                    try:
                        loop = asyncio.get_running_loop()
                        await loop.run_in_executor(
                            None,
                            lambda: subprocess.run(
                                ["sudo", "iptables", "-t", "nat", "-D", "PREROUTING", "-s", ip, "-j", "DNAT", "--to-destination", SDN_HONEYPOT_IP],
                                check=False
                            )
                        )
                        logger.info("Legacy Honeypot DNAT Redirection expired and deleted", ip=ip)
                    except Exception as err:
                        logger.error("Failed to delete expired legacy DNAT redirection rule", error=str(err))
                
                asyncio.create_task(cleanup())
            return True
        except Exception as e:
            logger.error("Legacy honeypot redirect failed", ip=ip, error=str(e))
            return False

    @classmethod
    async def quarantine_host(cls, ip: str, vlan_id: Optional[int] = None, ttl: int = 300) -> bool:
        """Quarantines a host into a VLAN isolation sandbox using SDN."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error("Invalid IP address format for quarantine", ip=ip)
            return False

        if not cls._initialized: await cls._initialize()
        cls._status_cache = {}
        cls._status_cache_time = 0

        success = False
        if cls._backend == "sdn" and cls._sdn_client:
            try:
                success = await cls._sdn_client.quarantine_host(ip, vlan_id, ttl)
            except Exception as e:
                logger.error("SDN quarantine steering failed", error=str(e))
        else:
            logger.warning("Quarantine steering requested but SDN backend is not active.", ip=ip)

        return success
