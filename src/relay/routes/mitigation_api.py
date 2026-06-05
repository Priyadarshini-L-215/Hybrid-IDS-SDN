import asyncio
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
    if ActiveFirewall._redis_client:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, ActiveFirewall._redis_client.srem, "sentinel_final_blocks", ip)
    return {"success": True, "message": f"IP {ip} unblocked"}

@router.post("/mitigation/block", dependencies=[Depends(require_api_key)])
async def block_ip(req: IPRequest):
    ip = str(req.ip)
    logger.info("Manual block requested", ip=ip)
    await ActiveFirewall.block(ip)
    if ActiveFirewall._redis_client:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, ActiveFirewall._redis_client.sadd, "sentinel_final_blocks", ip)
    return {"success": True, "message": f"IP {ip} blocked"}

@router.post("/mitigation/block-final", dependencies=[Depends(require_api_key)])
async def block_ip_final(req: IPRequest):
    ip = str(req.ip)
    logger.info("Manual final block requested", ip=ip)
    await ActiveFirewall.block(ip, ttl=0)
    if ActiveFirewall._redis_client:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, ActiveFirewall._redis_client.sadd, "sentinel_final_blocks", ip)
    return {"success": True, "message": f"IP {ip} blocked permanently by operator"}

@router.post("/mitigation/whitelist", dependencies=[Depends(require_api_key)])
async def whitelist_ip(req: IPRequest):
    ip = str(req.ip)
    logger.info("Manual whitelist requested", ip=ip)
    await ActiveFirewall.unblock(ip)
    if ActiveFirewall._redis_client:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, ActiveFirewall._redis_client.sadd, "sentinel_whitelisted_ips", ip)
        await loop.run_in_executor(None, ActiveFirewall._redis_client.srem, "sentinel_final_blocks", ip)
    return {"success": True, "message": f"IP {ip} added to dynamic whitelist"}

@router.post("/mitigation/unwhitelist", dependencies=[Depends(require_api_key)])
async def unwhitelist_ip(req: IPRequest):
    ip = str(req.ip)
    logger.info("Manual remove from whitelist requested", ip=ip)
    if ActiveFirewall._redis_client:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, ActiveFirewall._redis_client.srem, "sentinel_whitelisted_ips", ip)
    return {"success": True, "message": f"IP {ip} removed from dynamic whitelist"}

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

class ToggleBanningRequest(BaseModel):
    banning_disabled: bool = Field(..., description="True to stop automatic banning, False to resume")

@router.post("/mitigation/toggle", dependencies=[Depends(require_api_key)])
async def toggle_banning(req: ToggleBanningRequest):
    success = await ActiveFirewall.set_banning_disabled(req.banning_disabled)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update banning status in Redis")
    state_str = "stopped" if req.banning_disabled else "resumed"
    return {"success": True, "message": f"IP banning {state_str} successfully", "banning_disabled": req.banning_disabled}

@router.post("/baseline/freeze", dependencies=[Depends(require_api_key)])
async def freeze_baseline_route():
    from relay.app import get_ml_engine
    ml_engine = get_ml_engine()
    if not ml_engine or not ml_engine.anomaly_scorer:
        raise HTTPException(status_code=503, detail="ML Engine / Anomaly Scorer not active")
    ml_engine.anomaly_scorer.freeze_baseline()
    return {"success": True, "message": "Zero-Trust ML: Baseline updates manually FROZEN"}

@router.post("/baseline/unfreeze", dependencies=[Depends(require_api_key)])
async def unfreeze_baseline_route():
    from relay.app import get_ml_engine
    ml_engine = get_ml_engine()
    if not ml_engine or not ml_engine.anomaly_scorer:
        raise HTTPException(status_code=503, detail="ML Engine / Anomaly Scorer not active")
    ml_engine.anomaly_scorer.unfreeze_baseline()
    return {"success": True, "message": "Zero-Trust ML: Baseline updates manually UNFROZEN"}
