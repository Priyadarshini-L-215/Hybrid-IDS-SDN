import json
import logging
import os
import time
from datetime import datetime, timezone
import sys
from pathlib import Path

# Setup path for sibling/parent imports
CURRENT_DIR = Path(__file__).resolve().parent
SRC_DIR = CURRENT_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

logger = logging.getLogger(__name__)

from common.config import HEARTBEAT_LOG, ALERT_CACHE_SIZE
from common.database import query_alerts, get_stats


def tail_ml_alerts(cache_size=ALERT_CACHE_SIZE):
    """
    Fetch alerts and stats from the local SQLite database.
    """
    try:
        db_alerts = query_alerts(limit=cache_size)
        stats = get_stats()
        
        # Mapping for dashboard format
        alerts = []
        skipped = 0
        for a in db_alerts:
            # Skip pure noise: low-confidence normal flow events
            pred = a.get('prediction', '').lower()
            if a.get('event_type') == 'flow' and pred == 'normal' and a.get('confidence', 0) < 50:
                skipped += 1
                continue

            alerts.append({
                "prediction": pred.capitalize(),
                "confidence": a.get('confidence', 0),
                "src_ip": a.get('src_ip'),
                "src_port": a.get('src_port'),
                "dest_ip": a.get('dest_ip'),
                "dest_port": a.get('dest_port'),
                "protocol": a.get('protocol'),
                "timestamp": a.get('timestamp'),
                "alert_sig": a.get('alert_sig'),
                "severity": a.get('severity', 4),
                "category": a.get('category', 'Network'),
                "event_type": a.get('event_type')
            })

        logger.info(f"[Integration] Seeded {len(alerts)} alerts (skipped {skipped} noise items)")
        
        return (
            alerts[:cache_size], 
            stats.get('total_processed', 0), 
            len(alerts), 
            stats.get('attack_total', 0), 
            stats.get('normal_total', 0)
        )
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, OSError) as exc:
        logger.error(f"Error seeding data: {exc}")
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
    except (OSError, ValueError) as exc:
        logger.warning(f"Failed to read heartbeat file: {exc}")
        return {"alive": False, "last_seen": None, "seconds_ago": None}
