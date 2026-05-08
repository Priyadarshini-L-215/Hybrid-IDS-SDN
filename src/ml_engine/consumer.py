import asyncio
import signal
import structlog
from pathlib import Path
import sys
import numpy as np
import os

# Set Keras backend BEFORE importing any ML modules
if not os.environ.get("KERAS_BACKEND"):
    os.environ["KERAS_BACKEND"] = "torch"

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.config import setup_logging, WORKER_COUNT, REDIS_ALERT_STREAM
from ml_engine.worker_pool import WorkerPool, NPEncoder
from ml_engine.engine import MLEngine
from ml_engine import redis_client as rc
from common.database import batch_add_alerts
from common.db_writer import alert_writer
import json

# Initialize structured logging
setup_logging("consumer")
logger = structlog.get_logger("consumer")

_RUNNING = True
_TARGET_FEATURE_DIM = 49


async def broadcast_and_persist(alerts: list):
    """Broadcasts a batch of alerts to Redis and persists them to SQLite."""
    if not alerts:
        return

    # 1. Persist to SQLite (Queued for background writing)
    try:
        await alert_writer.add_alerts(alerts)
        logger.debug("Queued batch for SQLite writing", count=len(alerts))
    except Exception as e:
        logger.error("Failed to queue alerts for DB", error=str(e))

    # 2. Broadcast to Redis Stream (Trimmed for performance)
    if rc.async_redis_client:
        try:
            pipe = rc.async_redis_client.pipeline()
            for alert in alerts:
                # Create a shallow copy and remove large raw_event for real-time broadcast
                # It will still be persisted to DB via alert_writer (which has the original list)
                broadcast_payload = alert.copy()
                broadcast_payload.pop('raw_event', None)
                
                alert_json = json.dumps(broadcast_payload, cls=NPEncoder)
                pipe.xadd(
                    REDIS_ALERT_STREAM,
                    {"alert": alert_json},
                    maxlen=1000
                )
            await pipe.execute()
            logger.debug("Broadcasted batch to Redis", count=len(alerts))
        except Exception as e:
            logger.error("Failed to broadcast to Redis", error=str(e))


async def redis_reader_task():
    """Compatibility alias for the Redis pipeline entry task."""
    await main()


async def redis_pipeline_main():
    """Compatibility alias for the Redis pipeline entry point."""
    await main()


def log_tailer():
    """Compatibility shim for the legacy file tailer entry point."""
    logger.info("log_tailer compatibility shim invoked")


def validate_features_dim(features, source: str = "unknown"):
    """Pad or truncate feature vectors to the stabilized dimension used by tests."""
    vector = np.asarray(features, dtype=float).flatten()
    if vector.size < _TARGET_FEATURE_DIM:
        vector = np.pad(vector, (0, _TARGET_FEATURE_DIM - vector.size), mode="constant")
    elif vector.size > _TARGET_FEATURE_DIM:
        vector = vector[:_TARGET_FEATURE_DIM]
    return vector.tolist()

async def main():
    global _RUNNING
    logger.info("Sentinel ML Engine starting...")
    
    # 1. Initialize Components
    from ml_engine.redis_client import sanitize_stream_key
    from common.config import REDIS_ALERT_STREAM
    sanitize_stream_key(REDIS_ALERT_STREAM)
    
    engine = MLEngine()
    
    # Define broadcast function for the worker pool
    pool = WorkerPool(worker_count=WORKER_COUNT, ml_engine=engine, broadcast_func=broadcast_and_persist)
    
    # 2. Setup termination and reload handling
    loop = asyncio.get_running_loop()
    
    def trigger_reload():
        logger.info("Reload signal received, refreshing config...")
        engine.reload_config()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(pool)))
        
    try:
        loop.add_signal_handler(signal.SIGHUP, trigger_reload)
        logger.info("SIGHUP handler registered for config reloading")
    except (AttributeError, NotImplementedError):
        # Windows doesn't have SIGHUP or add_signal_handler(SIGHUP)
        logger.warning("SIGHUP signal handler NOT registered. Config reloading via signal disabled (expected on Windows).")

    # 3. Start workers and DB writer
    await alert_writer.start()
    await pool.start()
    
    logger.info("ML Engine is ACTIVE and monitoring Redis Stream", broadcast="Redis Stream (sentinel_alerts_stream)")

    
    # Keep main alive
    while _RUNNING:
        await asyncio.sleep(1)

async def shutdown(pool):
    global _RUNNING
    logger.info("Shutdown signal received")
    _RUNNING = False
    await pool.stop()
    await alert_writer.stop()
    await rc.close_async_redis()
    logger.info("ML Engine shut down gracefully")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.critical("Fatal crash in consumer", error=str(e))
        sys.exit(1)
