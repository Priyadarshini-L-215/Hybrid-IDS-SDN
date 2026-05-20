from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field, IPvAnyAddress
import structlog

from relay.middleware.auth import require_api_key
from ml_engine.firewall import ActiveFirewall
from common.database import add_false_positive, get_alert_signature
from common.fp_store import fp_store

logger = structlog.get_logger("relay.routes.mitigation")
router = APIRouter(prefix="/api", tags=["Mitigation"])

class IPRequest(BaseModel):
    ip: IPvAnyAddress = Field(..., description="Target IP address")

class FalsePositiveRequest(BaseModel):
    alert_id: int = Field(..., description="ID of the alert to mark")
    src_ip: IPvAnyAddress = Field(..., description="Source IP to unblock")

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
    Unblocks IP, persists to DB, and adds to suppression store.
    """
    alert_id = req.alert_id
    src_ip = str(req.src_ip)

    logger.warning("Human-in-the-loop: False Positive marked", alert_id=alert_id, ip=src_ip)

    # 1. Immediate Mitigation: Unblock the IP
    await ActiveFirewall.unblock(src_ip)

    # 2. Persistence: Log to false_positives table
    success = await add_false_positive(alert_id)

    # 3. Suppression: Add to Redis FP store to prevent re-alerting
    if success:
        try:
            sig = await get_alert_signature(alert_id)
            if sig:
                await fp_store.add_suppression(src_ip, sig)
                logger.info("Benign traffic suppressed", ip=src_ip, sig=sig)
        except Exception:
            logger.exception("Failed to add FP suppression", ip=src_ip, alert_id=alert_id)

    return {
        "success": success,
        "message": f"IP {src_ip} unblocked and alert {alert_id} logged as False Positive"
    }
