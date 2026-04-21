import json
import logging
import os
from datetime import datetime, timezone
import sys
from pathlib import Path

# Setup path for sibling/parent imports
CURRENT_DIR = Path(__file__).resolve().parent
SRC_DIR = CURRENT_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

from common.config import EVE_LOG, ML_ALERTS_LOG, HEARTBEAT_LOG, ALERT_CACHE_SIZE, DATA_SERVICE_PORT
import requests
from common.database import query_alerts, get_stats

def tail_ml_alerts(cache_size=ALERT_CACHE_SIZE):
    """
    Fetch alerts and stats from the internal Bridge (WSL) or local DB.
    """
    try:
        # Check platform - if Windows, we hit the WSL Data Service
        if sys.platform == "win32":
            try:
                # 1. Fetch alerts from Bridge
                resp = requests.get(f"http://127.0.0.1:{DATA_SERVICE_PORT}/api/alerts", timeout=2)
                db_alerts = resp.json()
                
                # 2. Fetch stats from Bridge
                resp_s = requests.get(f"http://127.0.0.1:{DATA_SERVICE_PORT}/api/stats", timeout=2)
                stats = resp_s.json()
            except Exception as e:
                logger.warning(f"WSL Data Service unreachable ({e}), falling back to direct DB access...")
                db_alerts = query_alerts(limit=500)
                stats = get_stats()
        else:
            # Native Linux execution
            db_alerts = query_alerts(limit=500)
            stats = get_stats()
        
        # Mapping for dashboard format
        alerts = []
        for a in db_alerts:
            if a['event_type'] == 'flow' and a['prediction'].lower() == 'normal':
                continue

            alerts.append({
                "prediction": a['prediction'].capitalize(),
                "confidence": a['confidence'],
                "src_ip": a['src_ip'],
                "src_port": a['src_port'],
                "dest_ip": a['dest_ip'],
                "dest_port": a['dest_port'],
                "protocol": a['protocol'],
                "timestamp": a['timestamp'],
                "alert_sig": a['alert_sig'],
                "severity": a['severity'],
                "category": a['category'],
                "event_type": a['event_type']
            })

        return (
            alerts[:cache_size], 
            stats['total_processed'], 
            len(alerts), 
            stats['attack_total'], 
            stats['normal_total']
        )
    except Exception as e:
        logger.error(f"Error seeding data: {e}")
        return ([], 0, 0, 0, 0)


def get_consumer_heartbeat():
    """Read the consumer heartbeat file and report current liveness."""
    if not HEARTBEAT_LOG.exists():
        return {"alive": False, "last_seen": None, "seconds_ago": None}

    try:
        stamp = HEARTBEAT_LOG.read_text(encoding="utf-8").strip()
        if not stamp:
            return {"alive": False, "last_seen": None, "seconds_ago": None}

        seen_at = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if seen_at.tzinfo is None:
            seen_at = seen_at.replace(tzinfo=timezone.utc)
        seconds_ago = int((datetime.now(timezone.utc) - seen_at).total_seconds())
        return {
            "alive": seconds_ago <= 30,
            "last_seen": seen_at.isoformat(),
            "seconds_ago": max(seconds_ago, 0),
        }
    except Exception as e:
        logger.warning(f"Failed to read heartbeat file: {e}")
        return {"alive": False, "last_seen": None, "seconds_ago": None}
