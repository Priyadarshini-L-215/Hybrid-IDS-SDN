import asyncio
import aiofiles
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel
from relay.middleware.auth import require_api_key
import structlog
import json
import time
from pathlib import Path
from common.config import LOG_DIR

router = APIRouter(prefix="/api/forensics", tags=["Forensics"])
logger = structlog.get_logger(__name__)

FEEDBACK_LOG = LOG_DIR / "analyst_feedback.jsonl"

class AlertFeedback(BaseModel):
    alert_id: str
    src_ip: str
    prediction: str
    correction: str # "TP" (True Positive), "FP" (False Positive)
    notes: str = ""
    raw_event: dict = {}

@router.post("/feedback")
async def submit_feedback(feedback: AlertFeedback):
    """
    Submits analyst feedback for an alert to be used in future model retraining.
    """
    try:
        feedback_entry = {
            "ts": time.time(),
            "alert_id": feedback.alert_id,
            "src_ip": feedback.src_ip,
            "original_prediction": feedback.prediction,
            "analyst_correction": feedback.correction,
            "notes": feedback.notes,
            "raw_features": feedback.raw_event.get("raw_event", {})
        }
        
        # Ensure log dir exists
        await asyncio.to_thread(FEEDBACK_LOG.parent.mkdir, parents=True, exist_ok=True)
        
        async with aiofiles.open(FEEDBACK_LOG, "a") as f:
            await f.write(json.dumps(feedback_entry) + "\n")
            
        logger.info("Analyst feedback recorded", alert_id=feedback.alert_id, correction=feedback.correction)
        return {"status": "success", "message": "Feedback recorded for retraining pipeline"}
        
    except Exception as e:
        logger.error("Failed to save feedback", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error saving feedback")

@router.get("/ip/{ip_address}")
async def get_ip_forensics_details(ip_address: str):
    """
    Returns the full IP timeline, reputation score, and GeoIP data for the drill-down panel.
    """
    from common.database import db
    from ml_engine.firewall import ActiveFirewall
    try:
        # 1. Get base forensics from DB
        forensics = await db.get_ip_forensics(ip_address)
        
        if not forensics:
            return {
                "ip": ip_address,
                "alert_count": 0,
                "history": [],
                "reputation_score": 0,
                "geo": {"country": "Unknown", "city": "Unknown", "asn": "Unknown"}
            }

        # 2. Get current firewall status
        is_mitigated = False
        try:
            is_mitigated = await ActiveFirewall.is_blocked(ip_address)
        except Exception: pass

        # 3. Find similar IPs for correlation
        similar_nodes = await db.find_similar_ips(ip_address, 3)

        # 4. Calculate stats
        preds = forensics.get("predictions", {})
        attacks = preds.get("attack", 0) + preds.get("anomaly", 0)
        susp = preds.get("suspicious", 0)
        total = forensics.get("total_events", 1)
        rep_score = int(min(100, ((attacks * 1.0 + susp * 0.5) / total) * 100))
        
        # 5. Extract latest Geo data
        geo = {"country": "Unknown", "city": "Unknown", "asn": "Unknown"}
        history = forensics.get("history", [])
        if history:
            latest = history[0]
            if "enrichment" in latest and latest["enrichment"]:
                geo = latest["enrichment"]

        # 6. Aggregate results
        return {
            **forensics,
            "alert_count": forensics.get("total_events", 0),
            "reputation_score": rep_score,
            "geo": geo,
            "is_mitigated": is_mitigated,
            "lateral_movement_risk": similar_nodes
        }
    except Exception as e:
        logger.error("Failed to fetch IP forensics", ip=ip_address, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

class CustomAlertRequest(BaseModel):
    event_id: str
    timestamp: str
    event_type: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    alert_sig: str
    prediction: str
    confidence: float
    severity: int
    category: str
    mitigation: str
    is_mitigated: int

@router.post("/alert/external", dependencies=[Depends(require_api_key)])
async def inject_external_alert(alert: CustomAlertRequest):
    try:
        from common.database import db
        from ml_engine import redis_client as rc
        from common.config import REDIS_ALERT_STREAM
        
        # 1. Build alert data matching the database insertion schema
        alert_data = alert.model_dump()
        alert_data["shap_top3"] = []
        alert_data["xai_explanation"] = ""
        alert_data["enrichment"] = {}
        alert_data["mitre_id"] = None
        alert_data["anomaly_score"] = 0.0
        alert_data["correlation_id"] = None
        alert_data["raw_event"] = {}
        
        # 2. Add to database
        await db.add_alert(alert_data)
        
        # 3. Broadcast to Redis Stream for UI WebSockets
        if rc.async_redis_client:
            payload = alert_data.copy()
            payload.pop("raw_event", None)
            alert_json = json.dumps(payload)
            await rc.async_redis_client.xadd(REDIS_ALERT_STREAM, {"alert": alert_json})
            await rc.async_redis_client.xtrim(REDIS_ALERT_STREAM, maxlen=1000)
            
        logger.info("External alert ingested", alert_id=alert.event_id, sig=alert.alert_sig)
        return {"status": "success", "message": "External alert ingested successfully"}
    except Exception as e:
        logger.error("Failed to ingest external alert", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error ingesting alert")
