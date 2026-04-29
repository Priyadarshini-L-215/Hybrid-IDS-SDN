"""
Redis Client & Connection Pool
Handles connection to Redis for message queuing and caching.
"""

import redis
import logging
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.config import REDIS_HOST, REDIS_PORT, REDIS_DB

logger = logging.getLogger(__name__)

# Connection pool for efficiency
try:
    redis_pool = redis.ConnectionPool(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        decode_responses=True,
        max_connections=10,
        socket_connect_timeout=5,
        socket_keepalive=True,
        retry_on_timeout=True
    )
    redis_client = redis.Redis(connection_pool=redis_pool)
except Exception as e:
    logger.error(f"[Redis] Failed to create connection pool: {e}")
    redis_client = None

# Async client for high-performance non-blocking queue consumption
async_redis_client = None

async def init_async_redis():
    """Initialize async Redis client."""
    global async_redis_client
    try:
        import redis.asyncio as async_redis
        async_redis_client = async_redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            decode_responses=True,
            socket_connect_timeout=5,
        )
        return True
    except Exception as e:
        logger.error(f"[Redis] Failed to create async client: {e}")
        return False


def test_redis():
    """Test Redis connection; return True if OK, False otherwise."""
    if redis_client is None:
        logger.error("[Redis] Client not initialized")
        return False
    
    try:
        result = redis_client.ping()
        logger.info(f"[Redis] Connection OK (PING response: {result})")
        return True
    except Exception as e:
        logger.error(f"[Redis] Connection test failed: {e}")
        return False

async def test_async_redis():
    """Test async Redis connection."""
    if async_redis_client is None:
        await init_async_redis()
    
    if async_redis_client is None:
        return False
        
    try:
        result = await async_redis_client.ping()
        logger.info(f"[Redis] Async Connection OK (PING response: {result})")
        return True
    except Exception as e:
        logger.error(f"[Redis] Async Connection test failed: {e}")
        return False


def get_queue_depth(queue_name):
    """Get current depth of a queue (handles both Lists and Streams)."""
    if redis_client is None:
        return -1
    try:
        ktype = redis_client.type(queue_name)
        if ktype == "list":
            return redis_client.llen(queue_name)
        elif ktype == "stream":
            return redis_client.xlen(queue_name)
        elif ktype == "none":
            return 0
        return -1
    except Exception as e:
        logger.error(f"[Redis] Failed to get queue depth: {e}")
        return -1

def sanitize_stream_key(key_name):
    """Ensures a key is either a stream or deleted if it's the wrong type."""
    if redis_client is None: return
    try:
        ktype = redis_client.type(key_name)
        if ktype != "stream" and ktype != "none":
            logger.warning(f"[Redis] Removing key {key_name} (Type mismatch: expected stream, got {ktype})")
            redis_client.delete(key_name)
    except Exception:
        pass


def flush_queue(queue_name):
    """Clear all items from a queue (debug only)."""
    if redis_client is None:
        return False
    try:
        redis_client.delete(queue_name)
        logger.info(f"[Redis] Queue '{queue_name}' flushed")
        return True
    except Exception as e:
        logger.error(f"[Redis] Failed to flush queue: {e}")
        return False


def get_redis_info():
    """Get Redis server info (for monitoring)."""
    if redis_client is None:
        return {}
    try:
        info = redis_client.info()
        return {
            "version": info.get("redis_version", "unknown"),
            "used_memory_mb": info.get("used_memory", 0) / (1024 * 1024),
            "connected_clients": info.get("connected_clients", 0),
            "total_commands_processed": info.get("total_commands_processed", 0)
        }
    except Exception as e:
        logger.error(f"[Redis] Failed to get info: {e}")
        return {}
