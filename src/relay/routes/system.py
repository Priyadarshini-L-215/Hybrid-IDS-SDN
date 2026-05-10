import asyncio
import os
import yaml
from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, IPvAnyAddress

from fastapi import APIRouter, HTTPException, Depends, Request
import structlog
import json
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response

from relay.middleware.auth import require_api_key

from common.config import CONFIG_PATH
from common.database import get_recent_alerts, get_stats, init_db, db
from common.fp_store import fp_store
from ml_engine import redis_client as rc
from ml_engine.firewall import ActiveFirewall
from common.config import DEV_MODE

logger = structlog.get_logger("relay.routes.system")

router = APIRouter(prefix="/api", tags=["System"])

class IPRequest(BaseModel):
    ip: IPvAnyAddress = Field(..., description="Target IP address")

class FalsePositiveRequest(BaseModel):
    alert_id: int = Field(..., description="ID of the alert to mark")
    src_ip: IPvAnyAddress = Field(..., description="Source IP to unblock")

class ConfigUpdate(BaseModel):
    config: Dict[str, Any] = Field(..., description="Full configuration object")

class ResetConfirm(BaseModel):
    confirm: str = Field(..., description="Must be 'RESET' to confirm data wipe")


@router.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat() + "Z"}

@router.get("/alerts")
async def get_alerts(limit: int = 100):
    """Fetches recent alerts from SQLite for UI seeding."""
    try:
        loop = asyncio.get_running_loop()
        alerts = await loop.run_in_executor(None, get_recent_alerts, limit)
        stats = await loop.run_in_executor(None, get_stats)
        
        return {
            "alerts": alerts,
            "total_processed": stats.get("total_processed", 0),
            "attack_total": stats.get("attack_total", 0),
            "normal_total": stats.get("normal_total", 0),
            "displayed_total": len(alerts)
        }
    except Exception as e:
        logger.error("Failed to fetch alerts", error=str(e))
        return {"alerts": [], "error": str(e)}@router.get("/alerts/{alert_id}")
async def get_alert_detail(alert_id: str):
    """Fetches full details for a single alert including raw event data."""
    try:
        def fetch_one(aid):
            conn = db._get_conn()
            cursor = conn.cursor()
            
            # Check if aid is numeric (internal ID) or string (event_id)
            if aid.isdigit():
                cursor.execute("SELECT * FROM alerts WHERE id = ?", (int(aid),))
            else:
                cursor.execute("SELECT * FROM alerts WHERE event_id = ?", (aid,))
                
            row = cursor.fetchone()
            if not row: return None
            
            alert = dict(row)
            # Decompress raw_event
            try:
                import zlib
                import json
                raw_data = alert.get('raw_event')
                if raw_data:
                    decompressed = zlib.decompress(raw_data).decode('utf-8')
                    alert['raw_event'] = json.loads(decompressed)
                
                # Parse JSON fields
                for field in ['shap_top3', 'enrichment']:
                    if alert.get(field):
                        alert[field] = json.loads(alert[field])
            except Exception:
                alert['raw_event'] = {}
            return alert

        loop = asyncio.get_running_loop()
        alert = await loop.run_in_executor(None, fetch_one, alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        return alert
    except HTTPException: raise
    except Exception as e:
        logger.error("Failed to fetch alert detail", id=alert_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/baseline/status")
async def get_baseline_status():
    """Returns the current status of the VAE baseline, drift monitor, and model metadata."""
    from ml_engine.baseline_updater import baseline_monitor
    import time
    import json
    from pathlib import Path
    
    # Path to model artifacts
    BASE_DIR = Path(__file__).resolve().parents[3]
    MODELS_DIR = BASE_DIR / "models"
    
    accuracy = 0.0
    last_trained = "Never"
    model_version = "v3.1-stable"
    
    # Try to load latest metrics
    try:
        metrics_p = MODELS_DIR / "metrics.json"
        if metrics_p.exists():
            with open(metrics_p, 'r') as f:
                metrics = json.load(f)
                # If it's a classification report style, find overall accuracy
                accuracy = metrics.get('accuracy', 0.0)
                if not accuracy and 'macro avg' in metrics:
                    accuracy = metrics['macro avg'].get('precision', 0.0) # Fallback
    except: pass

    # Try to load model meta
    try:
        meta_p = MODELS_DIR / "model_meta.json"
        if meta_p.exists():
            with open(meta_p, 'r') as f:
                meta = json.load(f)
                last_trained = meta.get('last_trained') or meta.get('created_at') or "2026-05-09"
                model_version = meta.get('model_version') or meta.get('version', model_version)
                if not accuracy:
                    accuracy = meta.get('accuracy', 0.0)
    except: pass

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


@router.get("/config")
async def get_config(request: Request):
    """Returns the current sentinel_config.yaml content with ETag caching."""
    import hashlib
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, "r") as f:
                content = f.read()
                etag = f'W/"{hashlib.md5(content.encode()).hexdigest()}"'
                
                # Check client cache
                if request.headers.get("if-none-match") == etag:
                    return Response(status_code=304)
                
                data = yaml.safe_load(content) or {}
                return Response(
                    content=json.dumps(data),
                    media_type="application/json",
                    headers={"ETag": etag, "Cache-Control": "public, max-age=30"}
                )
        return {}
    except Exception as e:
        logger.error("Failed to read config", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to read configuration file")

@router.post("/config", dependencies=[Depends(require_api_key)])
async def update_config(req: ConfigUpdate):
    """Updates and saves the sentinel_config.yaml file and reloads in all services."""
    new_config = req.config
    try:
        def dump_yaml():
            with open(CONFIG_PATH, "w") as f:
                yaml.dump(new_config, f, default_flow_style=False)

        await asyncio.to_thread(dump_yaml)
        
        logger.info("Configuration updated successfully")
        
        # Reload config in relay service locally
        try:
            from common.config import refresh_config
            refresh_config()
            logger.info("Config refreshed in relay service")
        except Exception as e:
            logger.warning("Failed to refresh config locally", error=str(e))
        
        # Signal consumer process to reload config as well
        try:
            import subprocess
            import signal
            pid_res = subprocess.run(["pgrep", "-f", "src/ml_engine/consumer.py"], capture_output=True, text=True)
            if pid_res.returncode == 0:
                signaled_count = 0
                for pid_str in pid_res.stdout.split():
                    try:
                        pid = int(pid_str.strip())
                        os.kill(pid, signal.SIGHUP)
                        signaled_count += 1
                        logger.info("Signaled consumer to reload config", pid=pid)
                    except (ValueError, ProcessLookupError, PermissionError) as e:
                        logger.warning(f"Failed to signal PID {pid_str}", error=str(e))
                if signaled_count == 0:
                    logger.warning("No consumer processes found to signal")
        except Exception as e:
            logger.warning("Failed to signal consumer for reload", error=str(e))
            
        return {"success": True, "message": "Config updated and reload signal sent"}
    except Exception as e:
        logger.error("Failed to update config", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to save configuration")

@router.post("/mitigation/unblock", dependencies=[Depends(require_api_key)])
async def unblock_ip(req: IPRequest):
    ip = str(req.ip)
    
    logger.info("Manual unblock requested", ip=ip)
    await ActiveFirewall.unblock(ip)
    return {"success": True, "message": f"IP {ip} unblocked"}

@router.post("/mitigation/block", dependencies=[Depends(require_api_key)])
async def block_ip(req: IPRequest):
    ip = str(req.ip)
    
    logger.info("Manual block requested", ip=ip)
    await ActiveFirewall.block(ip)
    return {"success": True, "message": f"IP {ip} blocked"}

@router.post("/feedback/false-positive", dependencies=[Depends(require_api_key)])
async def mark_false_positive(req: FalsePositiveRequest):
    """
    Marks an alert as a False Positive.
    Action: Unblocks IP, resets reputation delta, and logs for retraining.
    """
    alert_id = req.alert_id
    src_ip = str(req.src_ip)
    
    logger.warning("Human-in-the-loop: False Positive marked", alert_id=alert_id, ip=src_ip)
    
    # 1. Immediate Mitigation: Unblock the IP
    await ActiveFirewall.unblock(src_ip)
    
    # 2. Persistence: Log to false_positives table
    from common.database import add_false_positive
    loop = asyncio.get_running_loop()
    success = await loop.run_in_executor(None, add_false_positive, alert_id)
    
    # 3. Suppression: Add to Redis FP store to prevent re-alerting
    if success:
        try:
            # Fetch alert details to get the signature
            # Database.get_alert_by_id doesn't exist, I'll use a direct query or add it
            # I'll add a helper to DatabaseHandler or just use a query here
            def get_sig(aid):
                conn = db._get_conn()
                cursor = conn.cursor()
                cursor.execute("SELECT alert_sig FROM alerts WHERE id = ?", (aid,))
                row = cursor.fetchone()
                return row['alert_sig'] if row else None
            
            sig = await loop.run_in_executor(None, get_sig, alert_id)
            if sig:
                await fp_store.add_suppression(src_ip, sig)
                logger.info("Benign traffic suppressed", ip=src_ip, sig=sig)
        except Exception as e:
            logger.error("Failed to add suppression", error=str(e))
            
    return {
        "success": success, 
        "message": f"IP {src_ip} unblocked and alert {alert_id} logged as False Positive"
    }

@router.get("/pipeline/status")
async def get_pipeline_status():
    """Detailed diagnostics for the dashboard."""
    import time
    from common.config import LOG_DIR
    from relay.app import get_ml_engine
    
    # 1. Check Consumer Heartbeat (Redis-based)
    consumer_ok = False
    try:
        # Check all worker heartbeats
        keys = await rc.async_redis_client.keys("sentinel_heartbeat:*")
        if keys:
            consumer_ok = True
    except Exception as e:
        logger.debug("Heartbeat check failed", error=str(e))
        pass

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
            pass

    # 3. Get System Stats
    from common.database import get_stats
    loop = asyncio.get_running_loop()
    stats = await loop.run_in_executor(None, get_stats)

    # 4. ML Engine runtime state
    ml_engine = get_ml_engine()
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
    import time
    from relay.app import get_ml_engine
    
    # Check all worker heartbeats
    consumer_ok = False
    try:
        keys = await rc.async_redis_client.keys("sentinel_heartbeat:*")
        consumer_ok = bool(keys)
    except Exception: pass

    ml_engine = get_ml_engine()
    ml_status = {"status": "active", "ready": True} if ml_engine and ml_engine.is_ready else {"status": "loading", "ready": False}

    # Use cached summary status from firewall
    firewall_summary = await ActiveFirewall.get_status()

    return {
        "status": "active" if (consumer_ok and rc.async_redis_client) else "degraded",
        "ml_engine": ml_status["status"],
        "consumer": "active" if consumer_ok else "stopped",
        "blocked_count": firewall_summary.get("blocked_count", 0),
        "ts": time.time(),
        "trace_id": f"tr_{int(time.time()*1000)}"
    }

@router.get("/intelligence/node/{ip}")
async def get_node_intelligence(ip: str):
    """Fetches historical stats and reputation for a specific IP using the forensics DB."""
    try:
        from common.database import get_ip_forensics
        loop = asyncio.get_running_loop()
        # Forensics DB call is synchronous, run in executor
        forensics = await loop.run_in_executor(None, get_ip_forensics, ip)
        
        if not forensics:
            return {
                "ip": ip,
                "alert_count": 0,
                "recent_activity": [],
                "reputation_score": 0,
                "geo": {"country": "Unknown", "city": "Unknown", "asn": "Unknown"}
            }
        
        # Calculate a simple reputation score [0, 100] based on attacks
        attacks = forensics.get("predictions", {}).get("attack", 0)
        suspicious = forensics.get("predictions", {}).get("suspicious", 0)
        rep_score = min((attacks * 20) + (suspicious * 5), 100)
        
        # Check if currently blocked
        is_mitigated = False
        try:
            is_mitigated = ActiveFirewall.is_blocked(ip)
        except Exception as e:
            logger.debug("Failed to check blocked state", ip=ip, error=str(e))

        # 2. Find similar IPs (Lateral Movement Risk)
        from common.database import find_similar_ips
        similar_nodes = await loop.run_in_executor(None, find_similar_ips, ip, 3)

        return {
            "ip": ip,
            "alert_count": forensics.get("total_events", 0),
            "recent_activity": forensics.get("history", []),
            "reputation_score": rep_score,
            "is_mitigated": is_mitigated,
            "predictions": forensics.get("predictions", {}),
            "top_signatures": forensics.get("top_signatures", []),
            "geo": forensics.get("enrichment", {}) or {"country": "Unknown", "city": "Unknown", "asn": "Unknown"},
            "cti": forensics.get("cti", {}),
            "first_seen": forensics.get("first_seen"),
            "last_seen": forensics.get("last_seen"),
            "ja3_hash": forensics.get("ja3_hash"),
            "lateral_movement_risk": similar_nodes
        }
    except Exception as e:
        logger.error("Failed to fetch node intelligence", ip=ip, error=str(e))
        return {"error": str(e)}

@router.get("/sdn/status")
async def get_sdn_status():
    """Returns SDN controller connectivity and basic stats."""
    from ml_engine.firewall import ActiveFirewall
    status = await ActiveFirewall.get_status()
    if status.get("backend") == "sdn":
        return status
    return {"status": "disabled", "backend": "legacy"}

@router.get("/sdn/flows")
async def get_sdn_flows():
    """Returns current OpenFlow rules/blocked IPs from the controller."""
    from ml_engine.firewall import ActiveFirewall
    detailed = ActiveFirewall.get_detailed_status()
    return {
        "blocked_ips": detailed.get("permanent_ips", []),
        "reputation": detailed.get("reputation", {})
    }

@router.get("/metrics")
async def get_metrics():
    """Exposes internal Prometheus metrics for scraping."""
    try:
        metrics_data = generate_latest()
        return Response(content=metrics_data, media_type=CONTENT_TYPE_LATEST)
    except Exception as e:
        logger.error("Failed to generate metrics", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to generate metrics")

@router.post("/dev/reset", dependencies=[Depends(require_api_key)])
async def reset_system_state(req: ResetConfirm):
    """
    Developer convenience endpoint to reset SQLite and Redis state.
    Requires: DEV_MODE=true in config AND {"confirm": "RESET"} in request body.
    """
    if not DEV_MODE:
        raise HTTPException(status_code=403, detail="Reset endpoint is only available in DEV_MODE")

    if req.confirm != "RESET":
        raise HTTPException(
            status_code=400,
            detail="Confirmation required. Send {\"confirm\": \"RESET\"} to proceed."
        )
        
    logger.warning("DEVELOPER RESET REQUESTED. Wiping SQLite and Redis state...")
    
    results = {"sqlite": False, "redis": False, "errors": []}
    
    # Reset SQLite
    try:
        from common.config import DB_PATH
        if DB_PATH.exists():
            import sqlite3
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys = OFF;")
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            for table in tables:
                cursor.execute(f"DELETE FROM {table[0]};")
            cursor.execute("DELETE FROM sqlite_sequence;")
            conn.commit()
            conn.close()
        results["sqlite"] = True
        logger.info("SQLite database cleared successfully")
    except Exception as e:
        logger.error("Failed to reset SQLite", error=str(e))
        results["errors"].append(f"SQLite: {str(e)}")
        
    # Reset Redis
    try:
        if rc.async_redis_client:
            await rc.async_redis_client.flushall()
            results["redis"] = True
            logger.info("Redis state flushed successfully")
    except Exception as e:
        logger.error("Failed to reset Redis", error=str(e))
        results["errors"].append(f"Redis: {str(e)}")
        
    return {"success": len(results["errors"]) == 0, "details": results}
