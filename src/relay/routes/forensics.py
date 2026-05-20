import asyncio
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
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
        FEEDBACK_LOG.parent.mkdir(parents=True, exist_ok=True)
        
        with open(FEEDBACK_LOG, "a") as f:
            f.write(json.dumps(feedback_entry) + "\n")
            
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

        # 4. Aggregate results
        return {
            **forensics,
            "is_mitigated": is_mitigated,
            "lateral_movement_risk": similar_nodes
        }
    except Exception as e:
        logger.error("Failed to fetch IP forensics", ip=ip_address, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
