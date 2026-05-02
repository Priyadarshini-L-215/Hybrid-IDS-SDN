import asyncio
import os
import yaml
from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, HTTPException
import structlog
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response

from common.config import CONFIG_PATH
from common.database import get_recent_alerts, get_stats, init_db
from ml_engine import redis_client as rc
from ml_engine.firewall import ActiveFirewall
from common.config import DEV_MODE

logger = structlog.get_logger("relay.routes.system")

router = APIRouter(prefix="/api", tags=["System"])

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
        return {"alerts": [], "error": str(e)}


@router.get("/config")
async def get_config():
    """Returns the current sentinel_config.yaml content."""
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, "r") as f:
                return yaml.safe_load(f) or {}
        return {}
    except Exception as e:
        logger.error("Failed to read config", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to read configuration file")

@router.post("/config")
async def update_config(new_config: Dict[str, Any]):
    """Updates and saves the sentinel_config.yaml file."""
    try:
        with open(CONFIG_PATH, "w") as f:
            yaml.dump(new_config, f, default_flow_style=False)
        
        logger.info("Configuration updated successfully")
        
        try:
            import subprocess
            import signal
            pid_res = subprocess.run(["pgrep", "-f", "src/ml_engine/consumer.py"], capture_output=True, text=True)
            if pid_res.returncode == 0:
                for pid in pid_res.stdout.split():
                    os.kill(int(pid), signal.SIGHUP)
                logger.info("Signaled consumer to reload config")
        except Exception as e:
            logger.warning("Failed to signal consumer for reload", error=str(e))
            
        return {"success": True, "message": "Config updated and reload signal sent"}
    except Exception as e:
        logger.error("Failed to update config", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to save configuration")

@router.post("/mitigation/unblock")
async def unblock_ip(request: Dict[str, Any]):
    ip = request.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="IP address required")
    
    logger.info("Manual unblock requested", ip=ip)
    ActiveFirewall.unblock(ip)
    return {"success": True, "message": f"IP {ip} unblocked"}

@router.post("/mitigation/block")
async def block_ip(request: Dict[str, Any]):
    ip = request.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="IP address required")
    
    logger.info("Manual block requested", ip=ip)
    ActiveFirewall.block(ip)
    return {"success": True, "message": f"IP {ip} blocked"}

@router.post("/feedback/false-positive")
async def mark_false_positive(request: Dict[str, Any]):
    """
    Marks an alert as a False Positive.
    Action: Unblocks IP, resets reputation delta, and logs for retraining.
    """
    alert_id = request.get("alert_id")
    src_ip = request.get("src_ip")
    
    if not alert_id or not src_ip:
        raise HTTPException(status_code=400, detail="alert_id and src_ip required")
    
    logger.warning("Human-in-the-loop: False Positive marked", alert_id=alert_id, ip=src_ip)
    
    # 1. Immediate Mitigation: Unblock the IP
    ActiveFirewall.unblock(src_ip)
    
    # 2. Persistence: Log to false_positives table
    # success = db.add_false_positive(alert_id) # Fix: db is not defined, should use database module
    from common.database import add_false_positive
    success = add_false_positive(alert_id)
    
    return {
        "success": success, 
        "message": f"IP {src_ip} unblocked and alert {alert_id} logged as False Positive"
    }

@router.get("/pipeline/status")
async def get_pipeline_status():
    """Detailed diagnostics for the dashboard."""
    import time
    from common.config import LOG_DIR
    
    # 1. Check Consumer Heartbeat (Redis-based)
    consumer_ok = False
    try:
        # Check all worker heartbeats
        keys = await rc.async_redis_client.keys("sentinel_heartbeat:*")
        if keys:
            consumer_ok = True
    except Exception:
        pass

    # 2. Check Redis Status
    redis_ok = False
    queue_depth = 0
    if rc.async_redis_client:
        try:
            await rc.async_redis_client.ping()
            redis_ok = True
            queue_depth = await rc.async_redis_client.xlen("sentinel_alerts_stream")
        except Exception:
            pass

    return {
        "status": "active" if (consumer_ok and redis_ok) else "degraded",
        "redis_ok": redis_ok,
        "queue_depth": queue_depth,
        "ipset": ActiveFirewall.get_status(),
        "ipset_detailed": ActiveFirewall.get_detailed_status(),
        "checks": {
            "consumer_running": consumer_ok, 
            "redis_ok": redis_ok,
            "ws_port_open": True
        }
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
        except Exception: pass

        return {
            "ip": ip,
            "alert_count": forensics.get("total_events", 0),
            "recent_activity": forensics.get("history", [])[:5],
            "reputation_score": rep_score,
            "is_mitigated": is_mitigated,
            "predictions": forensics.get("predictions", {}),
            "top_signatures": forensics.get("top_signatures", []),
            "geo": forensics.get("enrichment", {}) or {"country": "Unknown", "city": "Unknown", "asn": "Unknown"},
            "cti": forensics.get("cti", {}),
            "first_seen": forensics.get("first_seen"),
            "last_seen": forensics.get("last_seen"),
            "ja3_hash": forensics.get("ja3_hash")
        }
    except Exception as e:
        logger.error("Failed to fetch node intelligence", ip=ip, error=str(e))
        return {"error": str(e)}

@router.get("/sdn/status")
async def get_sdn_status():
    """Returns SDN controller connectivity and basic stats."""
    from ml_engine.firewall import ActiveFirewall
    status = ActiveFirewall.get_status()
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

@router.post("/dev/reset")
async def reset_system_state():
    """
    Developer convenience endpoint to reset SQLite and Redis state.
    Requires DEV_MODE to be true in config.
    """
    if not DEV_MODE:
        raise HTTPException(status_code=403, detail="Reset endpoint is only available in DEV_MODE")
        
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
