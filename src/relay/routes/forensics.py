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
    Retrieves deep forensic data for a specific alert.
    (Placeholder for future expansion)
    """
    return {"alert_id": alert_id, "status": "Forensic trail reconstruction not yet fully implemented"}
