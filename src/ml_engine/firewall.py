import subprocess
import logging
import threading
import ipaddress
import collections
import time
import structlog
from typing import Dict, Set, List, Any, Optional
from common.config import (
    REPUTATION_LIMIT, REPUTATION_TEMP_BLOCK, REPUTATION_PERM_BLOCK,
    BLOCK_TTL, RATE_LIMIT_PER_SEC, get_protected_ips,
    REDIS_HOST, REDIS_PORT, REDIS_DB
)
import redis

logger = structlog.get_logger(__name__)

class ActiveFirewall:
    """
    Adaptive Mitigation System (IPS).
    Handles Reputation scoring, TTL-based blocking, and Decay logic.
    Utilizes ipset + iptables for high-performance mitigation.
    """
    
    _lock = threading.Lock()
    _protected_ips: Set[str] = set()
    _redis_client: Optional[redis.Redis] = None
    _initialized = False
    
    # Redis Keys
    REDIS_REPUTATION_KEY = "sentinel_reputation"
    
    # ipset set names
    SET_BLOCKS = "sentinel_blocks"
    SET_LIMITED = "sentinel_limited"

    @classmethod
    def _initialize(cls):
        """Setup sets and background decay task."""
        with cls._lock:
            if cls._initialized: return
            cls._protected_ips = get_protected_ips()
            cls._setup_kernel_sets()
            
            # Initialize Redis connection for shared reputation
            try:
                cls._redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
            except Exception as e:
                logger.error("Failed to connect to Redis for reputation", error=str(e))
            
            cls._initialized = True
            
            # Start decay thread
            threading.Thread(target=cls._decay_loop, daemon=True).start()
            
            # Cold-start: Load existing high-reputation offenders from Redis into kernel
            cls._repopulate_from_reputation()
            
            logger.info("IPS Firewall initialized", shared_reputation=True, protected_count=len(cls._protected_ips))

    @classmethod
    def _setup_kernel_sets(cls):
        """Initialize ipset sets and the custom iptables chain."""
        try:
            # 1. Create ipset sets with timeout support
            # hash:ip allows O(1) lookups
            subprocess.run(["sudo", "ipset", "create", cls.SET_BLOCKS, "hash:ip", "timeout", "0", "-!"], check=True)
            subprocess.run(["sudo", "ipset", "create", cls.SET_LIMITED, "hash:ip", "-!"], check=True)

            # 2. Ensure iptables chain exists
            CHAIN_NAME = "SENTINEL_IPS"
            subprocess.run(["sudo", "iptables", "-N", CHAIN_NAME], stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "iptables", "-F", CHAIN_NAME], check=True)

            # 3. Add rules to the chain
            # Rule 1: Drop everything in the blocks set
            subprocess.run(["sudo", "iptables", "-A", CHAIN_NAME, "-m", "set", "--match-set", cls.SET_BLOCKS, "src", "-j", "DROP"], check=True)
            
            # Rule 2: Rate limit everything in the limited set
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
        """Decays reputation scores every minute (Section 8.6)."""
        while True:
            time.sleep(60)
            if not cls._redis_client: continue
            
            try:
                # 1. Get all reputation scores using scan to avoid blocking Redis with HGETALL
                pipe = cls._redis_client.pipeline()
                count = 0
                
                # hscan_iter is much safer for large datasets
                for ip, score in cls._redis_client.hscan_iter(cls.REDIS_REPUTATION_KEY):
                    new_score = float(score) * 0.9
                    if new_score < 0.1:
                        pipe.hdel(cls.REDIS_REPUTATION_KEY, ip)
                    else:
                        pipe.hset(cls.REDIS_REPUTATION_KEY, ip, new_score)
                    
                    count += 1
                    # Execute in chunks to avoid massive pipelines
                    if count % 500 == 0:
                        pipe.execute()
                        pipe = cls._redis_client.pipeline()
                
                pipe.execute()
                if count > 0:
                    logger.debug("Shared reputation scores decayed", count=count)
            except Exception as e:
                logger.error("Decay loop failed", error=str(e))

    @classmethod
    def process_incident(cls, src_ip: str, delta: float) -> str:
        """
        Updates IP reputation and triggers mitigation if thresholds reached.
        Returns: action taken (permanent_block, temp_block, rate_limit, logged)
        """
        if not cls._initialized: cls._initialize()
        
        if src_ip in cls._protected_ips:
            return "skipped"

        if not cls._redis_client: return "logged"
        
        try:
            # Atomic increment in Redis
            new_score = cls._redis_client.hincrbyfloat(cls.REDIS_REPUTATION_KEY, src_ip, delta)
            
            if new_score < 0: 
                cls._redis_client.hset(cls.REDIS_REPUTATION_KEY, src_ip, 0)
                return "logged"

            # Check Thresholds (Section 8.6)
            if new_score >= REPUTATION_PERM_BLOCK:
                cls.block(src_ip, ttl=0) # Permanent
                return "permanent_block"
            elif new_score >= REPUTATION_TEMP_BLOCK:
                cls.block(src_ip, ttl=BLOCK_TTL) # Temporary (default 300s)
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
        """Adds IP to block set with optional TTL."""
        if not cls._initialized: cls._initialize()
        try:
            # ipset handles TTL natively. timeout 0 means permanent.
            subprocess.run(["sudo", "ipset", "add", cls.SET_BLOCKS, ip, "timeout", str(ttl), "-!"], check=True)
            
            # If manual/perm block, set shared reputation to max
            if ttl == 0 and cls._redis_client:
                cls._redis_client.hset(cls.REDIS_REPUTATION_KEY, ip, REPUTATION_PERM_BLOCK)
            logger.warning("IP Blocked", ip=ip, ttl="permanent" if ttl == 0 else f"{ttl}s")
        except Exception as e:
            logger.error("Block operation failed", ip=ip, error=str(e))

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
        """Removes IP from both blocks and limited sets."""
        if not cls._initialized: cls._initialize()
        try:
            subprocess.run(["sudo", "ipset", "del", cls.SET_BLOCKS, ip, "-!"], check=True)
            subprocess.run(["sudo", "ipset", "del", cls.SET_LIMITED, ip, "-!"], check=True)
            
            if cls._redis_client:
                cls._redis_client.hdel(cls.REDIS_REPUTATION_KEY, ip) # Clear shared reputation
            logger.info("IP Unblocked manually (Shared State)", ip=ip)
        except Exception as e:
            logger.error("Unblock operation failed", ip=ip, error=str(e))

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        """Returns summary counts of blocked/tracked IPs."""
        detailed = cls.get_detailed_status()
        return {
            "permanent": len(detailed["permanent_ips"]),
            "temporary": len(detailed["temporary_ips"]),
            "reputation_tracked": len(detailed["reputation"])
        }

    @classmethod
    def get_detailed_status(cls) -> Dict[str, Any]:
        """Returns actual list of IPs from kernel ipset."""
        perm = []
        temp = []
        reputation = {}
        
        if cls._redis_client:
            try:
                reputation = cls._redis_client.hgetall(cls.REDIS_REPUTATION_KEY)
                reputation = {k: float(v) for k, v in reputation.items()}
            except Exception as e:
                logger.error("Failed to fetch shared reputation", error=str(e))

        try:
            # Parse ipset list output
            result = subprocess.run(["sudo", "ipset", "list", cls.SET_BLOCKS], capture_output=True, text=True)
            if result.returncode == 0:
                # Find the members section
                lines = result.stdout.splitlines()
                in_members = False
                for line in lines:
                    if line.startswith("Members:"):
                        in_members = True
                        continue
                    if in_members and line.strip():
                        # Format: IP timeout SECONDS
                        parts = line.split()
                        ip = parts[0]
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

