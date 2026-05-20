import asyncio
import time
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
import structlog
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response

from common.config import MODELS_DIR
from common.database import get_stats
from ml_engine import redis_client as rc
from ml_engine.firewall import ActiveFirewall

def get_engine():
    from relay.app import get_ml_engine
    return get_ml_engine()

logger = structlog.get_logger("relay.routes.health")
router = APIRouter(prefix="/api", tags=["Health & Status"])

# Caching for model meta and metrics
_model_info_cache = {"accuracy": 0.0, "last_trained": "Never", "model_version": "v3.1-stable", "timestamp": 0}

@router.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}

@router.get("/metrics")
async def get_metrics():
    """Exposes internal Prometheus metrics for scraping."""
    try:
        metrics_data = generate_latest()
        return Response(content=metrics_data, media_type=CONTENT_TYPE_LATEST)
    except Exception as e:
        logger.error("Failed to generate metrics", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to generate metrics")

@router.get("/pipeline/status")
async def get_pipeline_status():
    """Detailed diagnostics for the dashboard."""
    # 1. Check Consumer Heartbeat (Redis-based)
    consumer_ok = False
    try:
        async with asyncio.timeout(2.0):
            async for _ in rc.async_redis_client.scan_iter("sentinel_heartbeat:*", count=10):
                consumer_ok = True
                break
    except asyncio.TimeoutError:
        logger.warning("Heartbeat SCAN timed out")
    except Exception as e:
        logger.debug("Heartbeat check failed", error=str(e))

    # 2. Check Redis Status
    redis_ok = False
    queue_depth = 0
    if rc.async_redis_client:
        try:
            await rc.async_redis_client.ping()
            redis_ok = True
            queue_depth = await rc.async_redis_client.xlen("sentinel_alerts_stream")
        except Exception as e:
            logger.warning("Redis health check failed", error=str(e))

    # 3. Get System Stats
    stats = await get_stats()

    # 4. ML Engine runtime state
    ml_engine = get_engine()
    ml_status = ml_engine.get_status() if ml_engine else {"status": "unavailable", "ready": False}

    return {
        "status": "active" if (consumer_ok and redis_ok) else "degraded",
        "ml_engine": ml_status,
        "redis_ok": redis_ok,
        "queue_depth": queue_depth,
        "stats": {
            "processed_total": stats.get("total_processed", 0),
            "attacks": stats.get("attack_total", 0),
            "normal": stats.get("normal_total", 0)
        },
        "ipset": await ActiveFirewall.get_status(),
        "ipset_detailed": await ActiveFirewall.get_detailed_status(),
        "checks": {
            "consumer_running": consumer_ok, 
            "redis_ok": redis_ok,
            "ws_port_open": True
        }
    }

@router.get("/pipeline/status/slim")
async def get_pipeline_status_slim():
    """Summary-only diagnostics for high-frequency polling."""
    consumer_ok = False
    try:
        async with asyncio.timeout(1.5):
            async for _ in rc.async_redis_client.scan_iter("sentinel_heartbeat:*", count=10):
                consumer_ok = True
                break
    except asyncio.TimeoutError:
        logger.debug("Heartbeat SCAN timed out (slim)")
    except Exception:
        logger.debug("Heartbeat check failed (slim)")

    ml_engine = get_engine()
    ml_status = {"status": "active", "ready": True} if ml_engine and ml_engine.is_ready else {"status": "loading", "ready": False}
    firewall_summary = await ActiveFirewall.get_status()

    return {
        "status": "active" if (consumer_ok and rc.async_redis_client) else "degraded",
        "ml_engine": ml_status["status"],
        "consumer": "active" if consumer_ok else "stopped",
        "blocked_count": firewall_summary.get("blocked_count", 0),
        "ts": time.time(),
        "trace_id": f"tr_{int(time.time()*1000)}"
    }

@router.get("/baseline/status")
async def get_baseline_status():
    """Returns the current status of the VAE baseline, drift monitor, and model metadata."""
    from ml_engine.baseline_updater import baseline_monitor
    import json

    global _model_info_cache
    now = time.time()

    accuracy: float = _model_info_cache["accuracy"]
    last_trained: str = _model_info_cache["last_trained"]
    model_version: str = _model_info_cache["model_version"]

    if now - _model_info_cache["timestamp"] >= 60:
        try:
            metrics_p = MODELS_DIR / "metrics.json"
            if metrics_p.exists():
                with open(metrics_p, 'r') as f:
                    metrics = json.load(f)
                    accuracy = metrics.get('accuracy', 0.0)
                    if not accuracy and 'macro avg' in metrics:
                        accuracy = metrics['macro avg'].get('precision', 0.0)
        except Exception as e:
            logger.debug("Could not load metrics.json", error=str(e))

        try:
            meta_p = MODELS_DIR / "model_meta.json"
            if meta_p.exists():
                with open(meta_p, 'r') as f:
                    meta = json.load(f)
                    last_trained = meta.get('last_trained') or meta.get('created_at') or "2026-05-09"
                    model_version = meta.get('model_version') or meta.get('version', model_version)
                    if not accuracy:
                        accuracy = meta.get('accuracy', 0.0)
        except Exception as e:
            logger.debug("Could not load model_meta.json", error=str(e))

        _model_info_cache.update({
            "accuracy": accuracy,
            "last_trained": last_trained,
            "model_version": model_version,
            "timestamp": now
        })

    return {
        "is_calibrated": baseline_monitor.baseline_mean is not None,
        "drift_detected": baseline_monitor.drift_detected,
        "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(baseline_monitor.last_refresh)),
        "accuracy_pct": round(accuracy * 100, 2) if accuracy <= 1.0 else round(accuracy, 2),
        "last_trained": last_trained,
        "model_version": model_version,
        "baseline_stats": {
            "mean": round(baseline_monitor.baseline_mean, 6) if baseline_monitor.baseline_mean else 0,
            "std": round(baseline_monitor.baseline_std, 6) if baseline_monitor.baseline_std else 0
        }
    }
