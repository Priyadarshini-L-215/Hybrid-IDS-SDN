import time
import logging
from typing import Optional
from ml_engine import redis_client as rc

logger = logging.getLogger(__name__)

class FalsePositiveStore:
    """
    Redis-backed store for false positive suppression.
    Allows the detection pipeline to skip alerts that have been marked as FP by analysts.
    """
    PREFIX = "sentinel:suppress:"
    DEFAULT_TTL = 86400  # 24 hours

    def __init__(self):
        # NOTE: Do NOT bind rc.async_redis_client here — it is None at import time.
        # Use the lazy property below so Redis is resolved at call time.
        pass

    @property
    def redis(self):
        """Lazily resolves the async Redis client at call time."""
        return rc.async_redis_client

    async def add_suppression(self, src_ip: str, alert_sig: str, ttl: int = DEFAULT_TTL):
        """
        Adds an IP+Signature pair to the suppression set.
        """
        if not self.redis:
            logger.warning("Redis client not available for FP suppression")
            return
            
        key = f"{self.PREFIX}{src_ip}:{alert_sig}"
        try:
            await self.redis.setex(key, ttl, "1")
            logger.info(f"Added FP suppression for {src_ip} [{alert_sig}] for {ttl}s")
        except Exception as e:
            logger.error(f"Failed to add FP suppression: {e}")

    async def is_suppressed(self, src_ip: str, alert_sig: str) -> bool:
        """
        Checks if an IP+Signature pair is currently suppressed.
        """
        if not self.redis:
            return False
            
        key = f"{self.PREFIX}{src_ip}:{alert_sig}"
        try:
            val = await self.redis.get(key)
            return val is not None
        except Exception as e:
            logger.error(f"Failed to check FP suppression: {e}")
            return False

# Global singleton
# Note: In worker_pool, we need to ensure rc.async_redis_client is initialized before using this.
fp_store = FalsePositiveStore()
