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

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

from common.config import HEARTBEAT_LOG, ALERT_CACHE_SIZE, DATA_SERVICE_PORT
from common.wsl_utils import get_wsl_ip
import requests
from common.database import query_alerts, get_stats


# Cache the last successful bridge snapshot to avoid regressing to stale local data.
_last_bridge_alerts = None
_last_bridge_stats = None


def _get_data_service_hosts():
    """Return bridge host candidates in priority order."""
    hosts = ["127.0.0.1"]
    wsl_ip = get_wsl_ip()
    if wsl_ip and wsl_ip not in hosts:
        hosts.append(wsl_ip)
    return hosts


def _fetch_bridge_payload(path, params=None, attempts=3, timeout_sec=5.0):
    """Fetch JSON payload from WSL bridge with short retries and host fallback."""
    last_exc = None
    for attempt_idx in range(attempts):
        for host in _get_data_service_hosts():
            url = f"http://{host}:{DATA_SERVICE_PORT}{path}"
            try:
                resp = requests.get(url, params=params, timeout=timeout_sec)
                resp.raise_for_status()
                return resp.json()
            except requests.RequestException as exc:
                last_exc = exc
                continue

        # Tiny backoff to allow bridge startup without noticeably delaying UI.
        if attempt_idx < attempts - 1:
            time.sleep(0.2 * (attempt_idx + 1))

    if last_exc:
        raise last_exc
    raise RuntimeError("Bridge fetch failed without exception")

def tail_ml_alerts(cache_size=ALERT_CACHE_SIZE):
    """
    Fetch alerts and stats from the internal Bridge (WSL) or local DB.
    """
    global _last_bridge_alerts, _last_bridge_stats

    try:
        # Check platform - if Windows, we hit the WSL Data Service
        if sys.platform == "win32":
            try:
                # 1. Fetch alerts from Bridge
                db_alerts = _fetch_bridge_payload("/api/alerts", params={"limit": cache_size, "offset": 0})

                # 2. Fetch stats from Bridge
                stats = _fetch_bridge_payload("/api/stats")
                _last_bridge_alerts = db_alerts
                _last_bridge_stats = stats
            except (requests.RequestException, ValueError, TypeError, json.JSONDecodeError) as exc:
                if _last_bridge_alerts is not None and _last_bridge_stats is not None:
                    logger.warning(
                        f"WSL Data Service unreachable ({exc}); using cached bridge snapshot to avoid stale fallback."
                    )
                    db_alerts = _last_bridge_alerts
                    stats = _last_bridge_stats
                elif os.environ.get("ALLOW_STALE_WINDOWS_DB_FALLBACK", "0") == "1":
                    logger.warning(
                        f"WSL Data Service unreachable ({exc}); using direct Windows DB fallback "
                        f"(ALLOW_STALE_WINDOWS_DB_FALLBACK=1)."
                    )
                    db_alerts = query_alerts(limit=cache_size)
                    stats = get_stats()
                else:
                    logger.warning(
                        f"WSL Data Service unreachable ({exc}); returning empty seed instead of stale local data."
                    )
                    db_alerts = []
                    stats = {"total_processed": 0, "attack_total": 0, "normal_total": 0}
        else:
            # Native Linux execution
            db_alerts = query_alerts(limit=cache_size)
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
    except (requests.RequestException, ValueError, TypeError, KeyError, json.JSONDecodeError, OSError) as exc:
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
