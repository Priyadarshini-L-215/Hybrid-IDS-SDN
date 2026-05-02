import subprocess
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
    
    _lock = threading.Lock()
    _protected_ips: Set[str] = set()
    _redis_client: Optional[redis.Redis] = None
    _sdn_client: Optional[SDNClient] = None
    _initialized = False
    _backend = "legacy" # Default to legacy
    
    # Redis Keys
    REDIS_REPUTATION_KEY = "sentinel_reputation"
    
    # ipset set names (legacy mode)
    SET_BLOCKS = "sentinel_blocks"
    SET_LIMITED = "sentinel_limited"

    @classmethod
    def _initialize(cls):
        """Setup backend and background decay task."""
        with cls._lock:
            if cls._initialized: return
            cls._protected_ips = get_protected_ips()
            
            # Determine backend
            if SDN_ENABLED:
                cls._backend = "sdn"
                cls._sdn_client = SDNClient(f"http://{SDN_CONTROLLER_HOST}:{SDN_CONTROLLER_PORT}")
                logger.info("Mitigation Backend set to SDN", controller=f"{SDN_CONTROLLER_HOST}:{SDN_CONTROLLER_PORT}")
            else:
                cls._backend = "legacy"
                cls._setup_kernel_sets()
                logger.info("Mitigation Backend set to LEGACY (ipset/iptables)")
            
            # Initialize Redis connection for shared reputation
            try:
                cls._redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
            except Exception as e:
                logger.error("Failed to connect to Redis for reputation", error=str(e))
            
            cls._initialized = True
            
            # Start decay thread
            threading.Thread(target=cls._decay_loop, daemon=True).start()
            
            # Cold-start: Load existing high-reputation offenders from Redis into backend
            cls._repopulate_from_reputation()
            
            logger.info("IPS Firewall initialized", shared_reputation=True, protected_count=len(cls._protected_ips))

    @classmethod
    def close(cls):
        """Release long-lived mitigation resources when shutting down."""
        with cls._lock:
            if cls._sdn_client is None:
                return

            try:
                import asyncio
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None

                if loop and loop.is_running():
                    loop.create_task(cls._sdn_client.close())
                else:
                    asyncio.run(cls._sdn_client.close())
            except Exception as e:
                logger.warning("Failed to close SDN client cleanly", error=str(e))
            finally:
                cls._sdn_client = None

    @classmethod
    def _setup_kernel_sets(cls):
        """Initialize ipset sets and the custom iptables chain (Legacy mode)."""
        try:
            # 1. Create ipset sets with timeout support
            subprocess.run(["sudo", "ipset", "create", cls.SET_BLOCKS, "hash:ip", "timeout", "0", "-!"], check=True)
            subprocess.run(["sudo", "ipset", "create", cls.SET_LIMITED, "hash:ip", "-!"], check=True)

            # 2. Ensure iptables chain exists
            CHAIN_NAME = "SENTINEL_IPS"
            subprocess.run(["sudo", "iptables", "-N", CHAIN_NAME], stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "iptables", "-F", CHAIN_NAME], check=True)

            # 3. Add rules to the chain
            subprocess.run(["sudo", "iptables", "-A", CHAIN_NAME, "-m", "set", "--match-set", cls.SET_BLOCKS, "src", "-j", "DROP"], check=True)
            
            # Rule 2: Rate limit
            subprocess.run([
                "sudo", "iptables", "-A", CHAIN_NAME, 
                "-m", "set", "--match-set", cls.SET_LIMITED, "src",
                "-m", "hashlimit", "--hashlimit-upto", f"{RATE_LIMIT_PER_SEC}/sec", 
                "--hashlimit-burst", "10", "--hashlimit-mode", "srcip", 
                "--hashlimit-name", "sentinel_rl", "-j", "RETURN"
            ], check=True)
            subprocess.run(["sudo", "iptables", "-A", CHAIN_NAME, "-m", "set", "--match-set", cls.SET_LIMITED, "src", "-j", "DROP"], check=True)

            # 4. Jump from INPUT to our chain
            check_jump = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-j", CHAIN_NAME], stderr=subprocess.DEVNULL)
            if check_jump.returncode != 0:
                subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-j", CHAIN_NAME], check=True)
                
            logger.info("Kernel firewall rules synchronized", chain=CHAIN_NAME)
        except Exception as e:
            logger.error("Failed to setup kernel firewall", error=str(e))

    @classmethod
    def _repopulate_from_reputation(cls):
        """On startup, read Redis reputation and re-block active offenders."""
        if not cls._redis_client: return
        try:
            reputation = cls._redis_client.hgetall(cls.REDIS_REPUTATION_KEY)
            count = 0
            for ip, score in reputation.items():
                s = float(score)
                if s >= REPUTATION_PERM_BLOCK:
                    cls.block(ip, ttl=0)
                    count += 1
                elif s >= REPUTATION_TEMP_BLOCK:
                    cls.block(ip, ttl=BLOCK_TTL)
                    count += 1
            if count > 0:
                logger.info("Firewall cold-start complete", reblocked_count=count)
        except Exception as e:
            logger.error("Failed to repopulate firewall from Redis", error=str(e))

    @classmethod
    def _decay_loop(cls):
        """Decays reputation scores every minute."""
        while True:
            time.sleep(60)
            if not cls._redis_client: continue
            
            try:
                pipe = cls._redis_client.pipeline()
                count = 0
                for ip, score in cls._redis_client.hscan_iter(cls.REDIS_REPUTATION_KEY):
                    new_score = float(score) * 0.9
                    if new_score < 0.1:
                        pipe.hdel(cls.REDIS_REPUTATION_KEY, ip)
                    else:
                        pipe.hset(cls.REDIS_REPUTATION_KEY, ip, new_score)
                    
                    count += 1
                    if count % 500 == 0:
                        pipe.execute()
                        pipe = cls._redis_client.pipeline()
                
                pipe.execute()
            except Exception as e:
                logger.error("Decay loop failed", error=str(e))

    @classmethod
    def process_incident(cls, src_ip: str, delta: float) -> str:
        """
        Updates IP reputation and triggers mitigation if thresholds reached.
        Returns: action taken
        """
        if not cls._initialized: cls._initialize()
        
        if src_ip in cls._protected_ips:
            return "skipped"

        if not cls._redis_client: return "logged"
        
        try:
            new_score = cls._redis_client.hincrbyfloat(cls.REDIS_REPUTATION_KEY, src_ip, delta)
            
            if new_score < 0: 
                cls._redis_client.hset(cls.REDIS_REPUTATION_KEY, src_ip, 0)
                return "logged"

            if new_score >= REPUTATION_PERM_BLOCK:
                cls.block(src_ip, ttl=0)
                return "permanent_block"
            elif new_score >= REPUTATION_TEMP_BLOCK:
                cls.block(src_ip, ttl=BLOCK_TTL)
                return "temp_block"
            elif new_score >= REPUTATION_LIMIT:
                cls.rate_limit(src_ip)
                return "rate_limit"
            
            return "logged"
        except Exception as e:
            logger.error("Reputation update failed", ip=src_ip, error=str(e))
            return "logged"

    @classmethod
    def block(cls, ip: str, ttl: int = 0):
        """Adds IP to block set or installs SDN flow."""
        if not cls._initialized: cls._initialize()
        
        success = False
        if cls._backend == "sdn" and cls._sdn_client:
            # Try SDN block
            try:
                success = cls._sdn_client.block_sync(ip, ttl)
            except Exception as e:
                logger.error("SDN block failed", error=str(e))
                if SDN_FALLBACK_TO_IPSET:
                    logger.warn("Falling back to ipset for block", ip=ip)
                    cls._legacy_block(ip, ttl)
                    success = True
        else:
            cls._legacy_block(ip, ttl)
            success = True
            
        if success and ttl == 0 and cls._redis_client:
            cls._redis_client.hset(cls.REDIS_REPUTATION_KEY, ip, REPUTATION_PERM_BLOCK)

    @classmethod
    def _legacy_block(cls, ip: str, ttl: int = 0):
        try:
            subprocess.run(["sudo", "ipset", "add", cls.SET_BLOCKS, ip, "timeout", str(ttl), "-!"], check=True)
            logger.warning("Legacy Block (ipset)", ip=ip, ttl=ttl)
        except Exception as e:
            logger.error("Legacy block failed", ip=ip, error=str(e))

    @classmethod
    def rate_limit(cls, ip: str):
        """Adds IP to rate-limited set."""
        if not cls._initialized: cls._initialize()
        try:
            subprocess.run(["sudo", "ipset", "add", cls.SET_LIMITED, ip, "-!"], check=True)
            logger.warning("IP Rate Limited", ip=ip)
        except Exception as e:
            logger.error("Rate limit operation failed", ip=ip, error=str(e))

    @classmethod
    def unblock(cls, ip: str):
        """Removes IP from both blocks and clears shared reputation."""
        if not cls._initialized: cls._initialize()
        
        if cls._backend == "sdn" and cls._sdn_client:
            try:
                cls._sdn_client.unblock_sync(ip)
            except Exception as e:
                logger.error("SDN unblock failed", error=str(e))
        
        # Always try legacy unblock just in case
        try:
            subprocess.run(["sudo", "ipset", "del", cls.SET_BLOCKS, ip, "-!"], check=True)
            subprocess.run(["sudo", "ipset", "del", cls.SET_LIMITED, ip, "-!"], check=True)
            if cls._redis_client:
                cls._redis_client.hdel(cls.REDIS_REPUTATION_KEY, ip)
            logger.info("IP Unblocked manually", ip=ip)
        except Exception as e:
            logger.error("Unblock operation failed", ip=ip, error=str(e))

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        """Returns summary counts."""
        detailed = cls.get_detailed_status()
        return {
            "backend": cls._backend,
            "permanent": len(detailed["permanent_ips"]),
            "temporary": len(detailed["temporary_ips"]),
            "reputation_tracked": len(detailed["reputation"])
        }

    @classmethod
    def get_detailed_status(cls) -> Dict[str, Any]:
        """Returns actual list of IPs."""
        perm = []
        temp = []
        reputation = {}
        
        if cls._redis_client:
            try:
                reputation = cls._redis_client.hgetall(cls.REDIS_REPUTATION_KEY)
                reputation = {k: float(v) for k, v in reputation.items()}
            except Exception as e:
                logger.error("Failed to fetch shared reputation", error=str(e))

        # Merge results from both backends if possible
        if cls._backend == "sdn" and cls._sdn_client:
            try:
                sdn_flows = cls._sdn_client.get_flows_sync()
                # For now SDN only returns blocked IPs
                perm.extend(sdn_flows.get("blocked_ips", []))
            except Exception as e:
                logger.error("SDN flow fetch failed", error=str(e))

        try:
            result = subprocess.run(["sudo", "ipset", "list", cls.SET_BLOCKS], capture_output=True, text=True)
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
                        if ip in perm: continue # Avoid duplicates
                        timeout = int(parts[2]) if len(parts) >= 3 else 0
                        if timeout == 0: perm.append(ip)
                        else: temp.append(ip)
        except Exception as e:
            logger.error("Failed to list ipset members", error=str(e))

        return {
            "permanent_ips": perm,
            "temporary_ips": temp,
            "reputation": reputation
        }
