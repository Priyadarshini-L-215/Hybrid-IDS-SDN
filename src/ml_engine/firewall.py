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
    SDN_ENABLED, SDN_CONTROLLER_HOST, SDN_CONTROLLER_PORT, SDN_FALLBACK_TO_IPSET
)
from ml_engine.sdn_client import SDNClient

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
    _initialized = False
    _backend = "legacy" # Default to legacy
    _decay_task: Optional[asyncio.Task] = None
    
    # Redis Keys
    REDIS_REPUTATION_KEY = "sentinel_reputation"
    
    # ipset set names (legacy mode)
    SET_BLOCKS = "sentinel_blocks"
    SET_LIMITED = "sentinel_limited"

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
            
            # ALWAYS setup kernel sets for fallback reliability
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, cls._setup_kernel_sets)
            
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
        """Initialize ipset sets and the custom iptables chain (Legacy mode)."""
        try:
            # 1. Create ipset sets with timeout support
            def create_set_safe(name, params):
                res = subprocess.run(["sudo", "ipset", "create", name] + params + ["-!"], capture_output=True)
                if res.returncode != 0:
                    logger.warning(f"ipset {name} creation failed. Flushing iptables and recreating...", error=res.stderr.decode())
                    subprocess.run(["sudo", "iptables", "-F", "SENTINEL_IPS"], check=False)
                    subprocess.run(["sudo", "ipset", "destroy", name], check=False)
                    subprocess.run(["sudo", "ipset", "create", name] + params + ["-!"], check=True)

            create_set_safe(cls.SET_BLOCKS, ["hash:ip", "timeout", "0"])
            create_set_safe(cls.SET_LIMITED, ["hash:ip", "timeout", "3600"])

            # 2. Ensure iptables chain exists and rules are present
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

            # 3. Hook into INPUT/FORWARD
            for target in ["INPUT", "FORWARD"]:
                hook_check = subprocess.run(["sudo", "iptables", "-C", target, "-j", CHAIN_NAME], capture_output=True)
                if hook_check.returncode != 0:
                    subprocess.run(["sudo", "iptables", "-I", target, "1", "-j", CHAIN_NAME], check=True)
                
            logger.info("Kernel firewall rules synchronized", chain=CHAIN_NAME)
        except Exception as e:
            logger.error("Failed to setup kernel firewall", error=str(e))

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
                def do_decay():
                    pipe = cls._redis_client.pipeline()
                    rehabilitated = []
                    for ip, score in cls._redis_client.hscan_iter(cls.REDIS_REPUTATION_KEY):
                        val = float(score)
                        new_score = val * 0.9
                        
                        if val >= REPUTATION_TEMP_BLOCK and new_score < REPUTATION_TEMP_BLOCK:
                            rehabilitated.append(ip)
                        
                        if new_score < 0.1:
                            pipe.hdel(cls.REDIS_REPUTATION_KEY, ip)
                        else:
                            pipe.hset(cls.REDIS_REPUTATION_KEY, ip, new_score)
                    
                    pipe.execute()
                    return rehabilitated
                
                rehabilitated_ips = await loop.run_in_executor(None, do_decay)
                for ip in rehabilitated_ips:
                    logger.info("IP rehabilitated via decay", ip=ip)
                    await cls.unblock(ip)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Decay loop failed", error=str(e))

    @classmethod
    async def process_incident(cls, src_ip: str, delta: float) -> str:
        """
        Updates IP reputation and triggers mitigation if thresholds reached.
        Returns: action taken
        """
        if not cls._initialized: await cls._initialize()
        
        if src_ip in cls._protected_ips:
            return "skipped"

        if not cls._redis_client: return "logged"
        
        try:
            loop = asyncio.get_running_loop()
            new_score = await loop.run_in_executor(None, cls._redis_client.hincrbyfloat, cls.REDIS_REPUTATION_KEY, src_ip, delta)
            
            if new_score < 0: 
                await loop.run_in_executor(None, cls._redis_client.hset, cls.REDIS_REPUTATION_KEY, src_ip, 0)
                return "logged"

            if new_score >= REPUTATION_PERM_BLOCK:
                await cls.block(src_ip, ttl=0)
                return "permanent_block"
            elif new_score >= REPUTATION_TEMP_BLOCK:
                await cls.block(src_ip, ttl=BLOCK_TTL)
                return "temp_block"
            elif new_score >= REPUTATION_LIMIT:
                await cls.rate_limit(src_ip)
                return "rate_limit"
            
            return "logged"
        except Exception as e:
            logger.error("Reputation update failed", ip=src_ip, error=str(e))
            return "logged"

    @classmethod
    async def block(cls, ip: str, ttl: int = 0):
        """Adds IP to block set or installs SDN flow."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error("Invalid IP address format", ip=ip)
            return False
        
        if not cls._initialized: await cls._initialize()
        
        success = False
        if cls._backend == "sdn" and cls._sdn_client:
            try:
                success = await cls._sdn_client.block(ip, ttl)
            except Exception as e:
                logger.error("SDN block failed", error=str(e))
                if SDN_FALLBACK_TO_IPSET:
                    logger.warning("Falling back to ipset for block", ip=ip)
                    await cls._legacy_block(ip, ttl)
                    success = True
        else:
            await cls._legacy_block(ip, ttl)
            success = True
            
        if success and ttl == 0 and cls._redis_client:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, cls._redis_client.hset, cls.REDIS_REPUTATION_KEY, ip, REPUTATION_PERM_BLOCK)
        
        return success

    @classmethod
    async def _legacy_block(cls, ip: str, ttl: int = 0):
        try:
            if ipaddress.ip_address(ip).version == 6:
                logger.warning("Skipping IPv6 block (not yet supported by legacy backend)", ip=ip)
                return

            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, subprocess.run, ["sudo", "ipset", "add", cls.SET_BLOCKS, ip, "timeout", str(ttl), "-!"], True)
            logger.warning("Legacy Block (ipset)", ip=ip, ttl=ttl)
        except Exception as e:
            logger.error("Legacy block failed", ip=ip, error=str(e))

    @classmethod
    async def rate_limit(cls, ip: str):
        """Adds IP to rate-limited set."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error("Invalid IP address format", ip=ip)
            return False
        
        if not cls._initialized: await cls._initialize()
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, subprocess.run, ["sudo", "ipset", "add", cls.SET_LIMITED, ip, "-!"], True)
            logger.warning("IP Rate Limited", ip=ip)
        except Exception as e:
            logger.error("Rate limit operation failed", ip=ip, error=str(e))

    @classmethod
    async def unblock(cls, ip: str):
        """Removes IP from both blocks and clears shared reputation."""
        if not cls._initialized: await cls._initialize()
        
        if cls._backend == "sdn" and cls._sdn_client:
            try:
                await cls._sdn_client.unblock(ip)
            except Exception as e:
                logger.error("SDN unblock failed", error=str(e))
        
        try:
            try:
                if ipaddress.ip_address(ip).version == 6:
                    if cls._redis_client:
                        loop = asyncio.get_running_loop()
                        await loop.run_in_executor(None, cls._redis_client.hdel, cls.REDIS_REPUTATION_KEY, ip)
                    return
            except ValueError:
                pass

            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, subprocess.run, ["sudo", "ipset", "del", cls.SET_BLOCKS, ip, "-!"], False)
            await loop.run_in_executor(None, subprocess.run, ["sudo", "ipset", "del", cls.SET_LIMITED, ip, "-!"], False)
            
            if cls._redis_client:
                await loop.run_in_executor(None, cls._redis_client.hdel, cls.REDIS_REPUTATION_KEY, ip)
            logger.info("IP Unblocked manually", ip=ip)
        except Exception as e:
            logger.error("Unblock operation failed", ip=ip, error=str(e))

    @classmethod
    async def is_blocked(cls, ip: str) -> bool:
        """Checks if an IP is currently in the block set (permanent or temporary)."""
        if not cls._initialized: await cls._initialize()
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, subprocess.run, ["sudo", "ipset", "test", cls.SET_BLOCKS, ip], False, True, True)
            return result.returncode == 0
        except Exception:
            return False

    @classmethod
    async def get_status(cls) -> Dict[str, Any]:
        """Returns summary counts."""
        detailed = await cls.get_detailed_status()
        return {
            "backend": cls._backend,
            "permanent": len(detailed["permanent_ips"]),
            "temporary": len(detailed["temporary_ips"]),
            "reputation_tracked": len(detailed["reputation"])
        }

    @classmethod
    async def get_detailed_status(cls) -> Dict[str, Any]:
        """Returns actual list of IPs."""
        perm = []
        temp = []
        reputation = {}
        
        if cls._redis_client:
            try:
                loop = asyncio.get_running_loop()
                reputation = await loop.run_in_executor(None, cls._redis_client.hgetall, cls.REDIS_REPUTATION_KEY)
                reputation = {k: float(v) for k, v in reputation.items()}
            except Exception as e:
                logger.error("Failed to fetch shared reputation", error=str(e))

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
                            timeout = int(parts[2]) if len(parts) >= 3 else 0
                            if timeout == 0: ips["perm"].append(ip)
                            else: ips["temp"].append(ip)
            except Exception as e:
                logger.error(f"Failed to list ipset members for {set_name}", error=str(e))
            return ips

        loop = asyncio.get_running_loop()
        blocks = await loop.run_in_executor(None, _parse_ipset, cls.SET_BLOCKS)
        limited = await loop.run_in_executor(None, _parse_ipset, cls.SET_LIMITED)

        perm.extend(blocks["perm"])
        temp.extend(blocks["temp"])
        temp.extend(limited["perm"]) # Limited is always temporary in sense of timeout 3600
        temp.extend(limited["temp"])

        # Deduplicate
        perm = list(set(perm))
        temp = list(set(temp))

        return {
            "permanent_ips": perm,
            "temporary_ips": temp,
            "reputation": reputation
        }

