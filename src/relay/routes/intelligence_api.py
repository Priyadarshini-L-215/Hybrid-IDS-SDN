import asyncio
from typing import Optional, List, Dict, Any, Union
from fastapi import APIRouter, HTTPException
import structlog

from common.database import (
    get_recent_alerts,
    get_stats,
    get_alert_by_id,
    get_ip_forensics,
    find_similar_ips,
    search_alerts,
    get_mitre_stats,
    get_geo_stats
)
from ml_engine.firewall import ActiveFirewall

logger = structlog.get_logger("relay.routes.intelligence")
router = APIRouter(prefix="/api", tags=["Intelligence"])

@router.get("/alerts")
async def get_alerts(limit: int = 100):
    """Fetches recent alerts from SQLite for UI seeding."""
    try:
        alerts, stats = await asyncio.gather(
            get_recent_alerts(limit),
            get_stats(),
        )
        return {
            "alerts": alerts,
            "total_processed": stats.get("total_processed", 0),
            "attack_total": stats.get("attack_total", 0),
            "normal_total": stats.get("normal_total", 0),
            "displayed_total": len(alerts)
        }
    except Exception:
        logger.exception("Failed to fetch alerts")
        return {"alerts": [], "error": "Internal error fetching alerts"}

@router.get("/alerts/{alert_id}")
async def get_alert_detail(alert_id: str):
    """Fetches full details for a single alert."""
    try:
        alert = await get_alert_by_id(alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        return alert
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to fetch alert detail", id=alert_id)
        raise HTTPException(status_code=500, detail="Internal error fetching alert")

@router.get("/intelligence/node/{ip}")
async def get_node_intelligence(ip: str):
    """Fetches historical stats and reputation for a specific IP."""
    try:
        forensics = await get_ip_forensics(ip)
        if not forensics:
            return {
                "ip": ip,
                "alert_count": 0,
                "recent_activity": [],
                "reputation_score": 0,
                "geo": {"country": "Unknown", "city": "Unknown", "asn": "Unknown"}
            }

        attacks = forensics.get("predictions", {}).get("attack", 0)
        suspicious = forensics.get("predictions", {}).get("suspicious", 0)
        rep_score = min((attacks * 20) + (suspicious * 5), 100)

        is_mitigated = False
        try:
            is_mitigated = await ActiveFirewall.is_blocked(ip)
        except Exception as e:
            logger.debug("Failed to check blocked state", ip=ip, error=str(e))

        similar_nodes = await find_similar_ips(ip, 3)

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
    except Exception:
        logger.exception("Failed to fetch node intelligence", ip=ip)
        return {"ip": ip, "error": "Internal error fetching node intelligence"}

@router.get("/sdn/status")
async def get_sdn_status():
    """Returns SDN controller connectivity and basic stats."""
    status = await ActiveFirewall.get_status()
    if status.get("backend") == "sdn":
        return status
    return {"status": "disabled", "backend": "legacy"}

@router.get("/sdn/flows")
async def get_sdn_flows():
    """Returns current OpenFlow rules/blocked IPs from the controller."""
    detailed = await ActiveFirewall.get_detailed_status()
    return {
        "blocked_ips": detailed.get("permanent_ips", []),
        "reputation": detailed.get("reputation", {})
    }

@router.get("/search")
async def search(
    src_ip: Optional[str] = None,
    prediction: Optional[str] = None,
    severity: Optional[int] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    protocol: Optional[str] = None,
    limit: int = 100
):
    """Advanced historical search across the forensic database."""
    params = {
        "src_ip": src_ip,
        "prediction": prediction,
        "severity": severity,
        "start_time": start_time,
        "end_time": end_time,
        "protocol": protocol,
        "limit": limit
    }
    try:
        results = await search_alerts(params)
        return {"results": results, "count": len(results)}
    except Exception as e:
        logger.error("API Search failed", error=str(e))
        raise HTTPException(status_code=500, detail="Search failed")

@router.get("/stats/mitre")
async def mitre_stats():
    """Aggregates detections by MITRE ATT&CK tactics."""
    try:
        stats = await get_mitre_stats()
        return {"stats": stats}
    except Exception as e:
        logger.error("API MITRE stats failed", error=str(e))
        raise HTTPException(status_code=500, detail="Stats failed")

@router.get("/stats/geo")
async def geo_stats():
    """Returns threat origin density for map visualization."""
    try:
        stats = await get_geo_stats()
        return {"stats": stats}
    except Exception as e:
        logger.error("API Geo stats failed", error=str(e))
        raise HTTPException(status_code=500, detail="Stats failed")
