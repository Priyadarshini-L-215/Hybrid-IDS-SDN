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

@router.get("/trail/{alert_id}")
async def get_forensic_trail(alert_id: str):
    """
    Retrieves deep forensic data for a specific alert by reconstructing the IP's activity trail.
    """
    from common.database import db
    try:
        # 1. Get the alert details to find the source IP
        conn = db._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT src_ip FROM alerts WHERE id = ?", (alert_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        ip = row['src_ip']
        
        # 2. Get full forensics for this IP
        forensics = db.get_ip_forensics(ip)
        if not forensics:
            return {"alert_id": alert_id, "ip": ip, "status": "Limited forensic history"}
            
        # 3. Find similar IPs
        similar_nodes = db.find_similar_ips(ip, limit=3)
        
        return {
            "alert_id": alert_id,
            "target_ip": ip,
            "node_intelligence": {
                "total_events": forensics.get("total_events"),
                "first_seen": forensics.get("first_seen"),
                "last_seen": forensics.get("last_seen"),
                "ja3_hash": forensics.get("ja3_hash"),
                "avg_latency": forensics.get("avg_latency_ms")
            },
            "timeline": forensics.get("history", []),
            "threat_enrichment": forensics.get("cti"),
            "lateral_movement_risk": similar_nodes
        }
    except Exception as e:
        logger.error("Forensics reconstruction failed", error=str(e))
        raise HTTPException(status_code=500, detail="Forensic engine error")
