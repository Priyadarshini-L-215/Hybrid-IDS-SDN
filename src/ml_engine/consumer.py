import asyncio
import signal
import structlog
from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.config import setup_logging, WORKER_COUNT
from ml_engine.worker_pool import WorkerPool
from ml_engine.engine import MLEngine
from ml_engine import redis_client as rc

# Initialize structured logging
setup_logging("consumer")
logger = structlog.get_logger("consumer")

_RUNNING = True

async def main():
    global _RUNNING
    logger.info("Sentinel ML Engine starting...")
    
    # 1. Initialize Components
    from ml_engine.redis_client import sanitize_stream_key
    from common.config import REDIS_ALERT_STREAM
    sanitize_stream_key(REDIS_ALERT_STREAM)
    
    engine = MLEngine()
    
    # Define broadcast function for the worker pool
    async def broadcast_to_redis(alert_json: str):
        if rc.async_redis_client:
            try:
                await rc.async_redis_client.xadd(
                    "sentinel_alerts_stream", 
                    {"alert": alert_json}, 
                    maxlen=1000
                )
            except Exception as e:
                logger.error("Failed to broadcast to Redis", error=str(e))

    pool = WorkerPool(worker_count=WORKER_COUNT, ml_engine=engine, broadcast_func=broadcast_to_redis)
    
    # 2. Setup termination handling
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(pool)))

    # 3. Start workers
    await pool.start()
    
    logger.info("ML Engine is ACTIVE and monitoring Redis Stream", broadcast="Redis Stream (sentinel_alerts_stream)")

    
    # Keep main alive
    while _RUNNING:
        await asyncio.sleep(1)

async def shutdown(pool):
    global _RUNNING
    logger.info("Shutdown signal received")
    _RUNNING = False
    pool.stop()
    logger.info("ML Engine shut down gracefully")
    sys.exit(0)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.critical("Fatal crash in consumer", error=str(e))
        sys.exit(1)
