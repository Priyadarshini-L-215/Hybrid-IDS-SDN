"""
Anti-Gravity IDS – Flask Backend
"""

import ipaddress
import logging
import sys
import os
import threading
import time
import json
import asyncio
from pathlib import Path
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sock import Sock
import websockets as ws_client

# Ensure sibling and parent modules are importable
CURRENT_DIR = Path(__file__).resolve().parent
SRC_DIR = CURRENT_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from integration import tail_ml_alerts, reset_ml_alert_state, get_consumer_heartbeat
    from common.config import (
        EVE_LOG, ML_ALERTS_LOG, WS_URI, 
        ALERT_CACHE_SIZE, ensure_dirs
    )
    from nmap_runner import run_nmap, analyse_with_gemini, SCAN_PROFILES, get_nmap_status
    ensure_dirs()
except ImportError as e:
    print(f"CRITICAL: Failed to import internal modules: {e}")
    sys.exit(1)

# ===== CONFIGURATION =====
DEFAULT_BIND_HOST = os.environ.get("IDS_BIND_HOST", "0.0.0.0")
DEFAULT_BIND_PORT = int(os.environ.get("IDS_PORT", "5000"))
REMOTE_CONTROL_ENABLED = os.environ.get("IDS_ALLOW_REMOTE_CONTROL") == "1"
REMOTE_CONTROL_TOKEN = os.environ.get("IDS_API_TOKEN", "").strip()

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
sock = Sock(app)

# --- Internal relay: connects to consumer WS, broadcasts to browsers ---
_browser_clients = set()
_browser_lock = threading.Lock()

def _relay_worker():
    """Relays messages from WSL consumer to browser clients."""
    async def _relay():
        global _browser_clients
        while True:
            try:
                logger.info(f"[Relay] Connecting to consumer: {WS_URI}")
                # Use a specific timeout for the initial connection
                async with ws_client.connect(WS_URI, open_timeout=10, ping_interval=20) as ws:
                    logger.info("[Relay] Success: Pipeline established with WSL sensor")
                    async for message in ws:
                        with _browser_lock:
                            if not _browser_clients:
                                continue
                            
                            dead = set()
                            # Efficient broadcast to all connected dashboard instances
                            for client in list(_browser_clients):
                                try:
                                    client.send(message)
                                except Exception:
                                    dead.add(client)
                            
                            if dead:
                                _browser_clients -= dead
                                logger.debug(f"[Relay] Pruned {len(dead)} dead browser connections")
            except Exception as e:
                logger.warning(f"[Relay] Pipeline interruption: {e}. Reconnecting in 5s...")
                await asyncio.sleep(5)

    try:
        asyncio.run(_relay())
    except Exception as fatal:
        logger.critical(f"[Relay] Fatal worker crash: {fatal}")

threading.Thread(target=_relay_worker, daemon=True, name="WS-Relay-Thread").start()

@sock.route("/ws/alerts")
def ws_alerts(ws):
    """Browser connects here for real-time stream."""
    with _browser_lock:
        _browser_clients.add(ws)
    try:
        while True:
            # Keep the socket open for up to 1 hour of silence before cycling.
            # The relay worker will push data whenever it arrives.
            ws.receive(timeout=3600)
    except: pass
    finally:
        with _browser_lock:
            _browser_clients.discard(ws)

# Cache for API fallbacks
_cache = {
    "alerts": [],
    "total_processed": 0,
    "displayed_total": 0,
    "attack_total": 0,
    "normal_total": 0,
    "last_updated": "never",
}
_cache_lock = threading.Lock()

# DEPRECATED: background_refresh removed in favor of Initial Seed + WebSocket Stream
# This reduces DB load and prevents state clobbering in the UI

# ===== API ROUTES =====

@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    """Returns the latest alerts for initial dashboard seeding."""
    try:
        # Fetch fresh data directly from integration layer
        alerts, total, displayed, attacks, normal = tail_ml_alerts(ALERT_CACHE_SIZE)
        return jsonify({
            "alerts": alerts,
            "total_processed": total,
            "displayed_total": displayed,
            "attack_total": attacks,
            "normal_total": normal,
            "last_updated": time.strftime("%H:%M:%S")
        }), 200
    except Exception as e:
        logger.error(f"API Error (alerts): {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/stats", methods=["GET"])
def api_stats():
    """Returns real-time aggregator statistics."""
    try:
        # Fetch directly from DB integration
        _, total, displayed, attacks, normal = tail_ml_alerts(ALERT_CACHE_SIZE)
        return jsonify({
            "processed_total": total,
            "displayed_total": displayed,
            "suppressed_total": max(total - displayed, 0),
            "attacks": attacks,
            "normal": normal,
            "last_updated": time.strftime("%H:%M:%S")
        }), 200
    except Exception as e:
        logger.error(f"API Error (stats): {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({
        "flask": "ok",
        "consumer": get_consumer_heartbeat()
    }), 200

@app.route("/api/alerts/clear", methods=["POST"])
def api_alerts_clear():
    # In a real environment, you'd add _guard_sensitive_api() here
    with _cache_lock:
        _cache["alerts"] = []
    reset_ml_alert_state()
    return jsonify({"success": True}), 200

@app.route("/api/nmap/check", methods=["GET"])
def api_nmap_check():
    return jsonify(get_nmap_status()), 200

@app.route("/api/nmap/profiles", methods=["GET"])
def api_nmap_profiles():
    return jsonify({"profiles": [{"id": k, **v} for k, v in SCAN_PROFILES.items()]}), 200

@app.route("/api/nmap/scan", methods=["POST"])
def api_nmap_scan():
    data = request.get_json() or {}
    res = run_nmap(data.get("target", ""), data.get("profile", "quick"), data.get("extra_flags"))
    return jsonify(res), 200 if res.get("success") else 400

@app.route("/api/nmap/analyse", methods=["POST"])
def api_nmap_analyse():
    data = request.get_json() or {}
    analysis = analyse_with_gemini(data.get("nmap_output", ""), data.get("target", "unknown"))
    return jsonify({"success": True, "analysis": analysis}), 200

if __name__ == "__main__":
    app.run(host=DEFAULT_BIND_HOST, port=DEFAULT_BIND_PORT, debug=False, use_reloader=False)
