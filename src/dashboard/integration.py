import json
import logging
import os
import subprocess
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


def _get_data_service_hosts():
    """Return bridge host candidates in priority order."""
    hosts = ["127.0.0.1"]
    try:
        out = subprocess.check_output(["wsl", "hostname", "-I"], text=True, timeout=1.5).strip()
        if out:
            wsl_ip = out.split()[0]
            if wsl_ip not in hosts:
                hosts.append(wsl_ip)
    except Exception:
        pass
    return hosts


def _fetch_bridge_payload(path):
    """Fetch JSON payload from WSL bridge using fast-fail host fallback."""
    timeout_sec = 0.6
    last_exc = None
    for host in _get_data_service_hosts():
        url = f"http://{host}:{DATA_SERVICE_PORT}{path}"
        try:
            resp = requests.get(url, timeout=timeout_sec)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            last_exc = exc
            continue
    if last_exc:
        raise last_exc
    raise RuntimeError("Bridge fetch failed without exception")

def tail_ml_alerts(cache_size=ALERT_CACHE_SIZE):
    """
    Fetch alerts and stats from the internal Bridge (WSL) or local DB.
    """
    try:
        # Check platform - if Windows, we hit the WSL Data Service
        if sys.platform == "win32":
            try:
                # 1. Fetch alerts from Bridge
                db_alerts = _fetch_bridge_payload("/api/alerts")

                # 2. Fetch stats from Bridge
                stats = _fetch_bridge_payload("/api/stats")
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
        skipped = 0
        for a in db_alerts:
            # We allow a bit more flow data to fill the graph, only skipping pure noise
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
    except Exception as e:
        logger.error(f"Error seeding data: {e}")
        import traceback
        traceback.print_exc()
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
