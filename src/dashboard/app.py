"""
Sentinel Core IPS – Flask WebSocket Relay & API Backend
"""

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
import socket
import websockets as ws_client

# Ensure sibling and parent modules are importable
CURRENT_DIR = Path(__file__).resolve().parent
SRC_DIR = CURRENT_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

try:
    from integration import tail_ml_alerts, get_consumer_heartbeat
    from common.config import (
        EVE_LOG, ML_ALERTS_LOG, WS_URI, WS_PORT,
        ALERT_CACHE_SIZE, ensure_dirs, LOG_LEVEL
    )
    from nmap_runner import run_nmap, analyse_with_gemini, SCAN_PROFILES, get_nmap_status
    ensure_dirs()
except ImportError as e:
    print(f"CRITICAL: Failed to import internal modules: {e}")
    print(f"Python Executable: {sys.executable}")
    print(f"Python Path: {sys.path}")
    sys.exit(1)

# ===== CONFIGURATION =====
DEFAULT_BIND_HOST = os.environ.get("IDS_BIND_HOST", "0.0.0.0")
DEFAULT_BIND_PORT = int(os.environ.get("IDS_PORT", "5000"))
REMOTE_CONTROL_ENABLED = os.environ.get("IDS_ALLOW_REMOTE_CONTROL") == "1"
REMOTE_CONTROL_TOKEN = os.environ.get("IDS_API_TOKEN", "").strip()

# Logger is initialized in common.config via setup_error_logging
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
sock = Sock(app)

# --- Internal relay: connects to consumer WS, broadcasts to browsers ---
_browser_clients = set()
_browser_lock = threading.Lock()

# Relay status for diagnostics
_relay_status_lock = threading.Lock()
_relay_status = {
    "state": "starting",          # starting | connected | retrying | failed
    "current_uri": WS_URI,
    "consecutive_failures": 0,
    "last_error": None,
    "last_connected_at": None,
    "messages_relayed": 0,
}

# Signal the relay worker to skip its sleep and retry immediately
_relay_reconnect_event = threading.Event()


def _relay_worker():
    """Relays messages from consumer WebSocket to browser clients."""
    async def _relay():
        global _browser_clients
        
        target_uri = f"ws://127.0.0.1:{WS_PORT}"
        logger.info(f"[Relay] Targeting {target_uri}")
        
        with _relay_status_lock:
            _relay_status["current_uri"] = target_uri
            _relay_status["state"] = "starting"
        
        RETRY_INTERVAL = 3.0
        consecutive_failures = 0
        
        while True:
            try:
                logger.info(f"[Relay] Connecting → {target_uri} (attempt {consecutive_failures + 1})")
                
                # Fix: Some environments add 'Connection: keep-alive' which breaks strict WS handshakes
                # We force 'Connection: Upgrade' to ensure compatibility.
                async with ws_client.connect(
                    target_uri,
                    open_timeout=15,
                    ping_interval=20,
                    ping_timeout=20,
                    close_timeout=10,
                    extra_headers={"Connection": "Upgrade"}
                ) as ws:
                    logger.info(f"[Relay] ✓ Pipeline active: {target_uri}")
                    consecutive_failures = 0
                    with _relay_status_lock:
                        _relay_status.update({
                            "state": "connected",
                            "consecutive_failures": 0,
                            "last_error": None,
                            "last_connected_at": time.strftime("%H:%M:%S"),
                            "current_uri": target_uri,
                        })
                    
                    async for message in ws:
                        relay_recv_ts = time.time()
                        
                        # Stamp tracer events with relay timestamps
                        try:
                            parsed = json.loads(message)
                            if parsed.get("_tracer"):
                                parsed["_relay_recv_ts"] = relay_recv_ts
                                parsed["_relay_fwd_ts"] = time.time()
                                message = json.dumps(parsed)
                                logger.info(f"[TRACER] T5 Relay recv at {relay_recv_ts:.6f}")
                        except (json.JSONDecodeError, TypeError, ValueError):
                            pass
                        
                        with _relay_status_lock:
                            _relay_status["messages_relayed"] += 1
                        # --- Fan-out broadcast to all browser clients ---
                        with _browser_lock:
                            if _browser_clients:
                                dead = set()
                                for client in list(_browser_clients):
                                    try:
                                        client.send(message)
                                    except (OSError, RuntimeError, TimeoutError) as send_err:
                                        logger.debug(f"[Relay] Send failed (dead client): {send_err}")
                                        dead.add(client)
                                    except Exception as exc:
                                        logger.warning(f"[Relay] Unexpected error broadcasting to client: {exc}")
                                        dead.add(client)
                                
                                if dead:
                                    _browser_clients -= dead
                                    logger.info(f"[Relay] Pruned {len(dead)} stalled connections. Active: {len(_browser_clients)}")

            except (ConnectionRefusedError, socket.error,
                    ws_client.exceptions.InvalidMessage,
                    asyncio.TimeoutError,
                    ws_client.exceptions.WebSocketException) as e:
                consecutive_failures += 1
                err_msg = f"{type(e).__name__}: {e}"
                with _relay_status_lock:
                    _relay_status.update({
                        "state": "retrying",
                        "consecutive_failures": consecutive_failures,
                        "last_error": err_msg,
                        "current_uri": target_uri,
                    })
                
                hint = ""
                if isinstance(e, ConnectionRefusedError):
                    hint = " [consumer not running]"
                elif isinstance(e, asyncio.TimeoutError):
                    hint = " [consumer may still be initializing]"
                
                logger.warning(
                    f"[Relay] ✗ {target_uri} unreachable — {type(e).__name__}{hint} "
                    f"(attempt {consecutive_failures}). Retry in {RETRY_INTERVAL}s..."
                )
                
                # Interruptible sleep with exponential backoff
                sleep_time = min(RETRY_INTERVAL * (2 ** (consecutive_failures // 3)), 30.0)
                _relay_reconnect_event.clear()
                deadline = time.time() + sleep_time
                while time.time() < deadline:
                    if _relay_reconnect_event.is_set():
                        logger.info("[Relay] Reconnect signal received — retrying immediately")
                        break
                    await asyncio.sleep(1.0)

            except (OSError, RuntimeError, ValueError, TypeError, ws_client.exceptions.WebSocketException) as e:
                consecutive_failures += 1
                err_msg = f"{type(e).__name__}: {e}"
                with _relay_status_lock:
                    _relay_status.update({
                        "state": "retrying",
                        "consecutive_failures": consecutive_failures,
                        "last_error": err_msg,
                    })
                logger.error(f"[Relay] ✗ Unexpected error: {err_msg}. Reconnecting in {RETRY_INTERVAL}s...")
                sleep_time = min(RETRY_INTERVAL * (2 ** (consecutive_failures // 3)), 30.0)
                _relay_reconnect_event.clear()
                deadline = time.time() + sleep_time
                while time.time() < deadline:
                    if _relay_reconnect_event.is_set():
                        break
                    await asyncio.sleep(1.0)

    try:
        asyncio.run(_relay())
    except Exception as fatal:
        _relay_status["state"] = "failed"
        logger.critical(f"[Relay] Fatal worker crash: {fatal}")

# Start relay thread only when not testing
if not app.testing:
    threading.Thread(target=_relay_worker, daemon=True, name="WS-Relay-Thread").start()

@sock.route("/ws/alerts")
def ws_alerts(ws):
    """Browser connects here for real-time stream."""
    with _browser_lock:
        _browser_clients.add(ws)
    try:
        while True:
            try:
                message = ws.receive(timeout=30)
            except TypeError:
                message = ws.receive()
            except TimeoutError:
                continue

            if message is None:
                break
    except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
        logger.debug(f"[WS] Browser socket closed: {exc}")
    except Exception as exc:
        logger.debug(f"[WS] Browser socket terminated: {exc}")
        pass
    finally:
        with _browser_lock:
            _browser_clients.discard(ws)

# ===== API ROUTES =====

@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    """Returns the latest alerts for initial dashboard seeding."""
    try:
        alerts, total, displayed, attacks, normal = tail_ml_alerts(ALERT_CACHE_SIZE)
        return jsonify({
            "alerts": alerts,
            "total_processed": total,
            "displayed_total": displayed,
            "attack_total": attacks,
            "normal_total": normal,
            "last_updated": time.strftime("%H:%M:%S")
        }), 200
    except (OSError, RuntimeError, ValueError, TypeError, json.JSONDecodeError) as e:
        logger.error(f"API Error (alerts): {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/stats", methods=["GET"])
def api_stats():
    """Returns real-time aggregator statistics."""
    try:
        _, total, displayed, attacks, normal = tail_ml_alerts(ALERT_CACHE_SIZE)
        return jsonify({
            "processed_total": total,
            "displayed_total": displayed,
            "suppressed_total": max(total - displayed, 0),
            "attacks": attacks,
            "normal": normal,
            "last_updated": time.strftime("%H:%M:%S")
        }), 200
    except (OSError, RuntimeError, ValueError, TypeError, json.JSONDecodeError) as e:
        logger.error(f"API Error (stats): {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({
        "flask": "ok",
        "consumer": get_consumer_heartbeat()
    }), 200

@app.route("/api/pipeline/status", methods=["GET"])
def api_pipeline_status():
    """Live diagnostic endpoint — shows relay state and pipeline health."""
    import subprocess
    
    # Check consumer process
    consumer_running = False
    try:
        r = subprocess.run(
            ["pgrep", "-f", "consumer.py"],
            capture_output=True, text=True, timeout=4
        )
        consumer_running = r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        pass
    
    # Check Redis
    redis_ok = False
    try:
        r = subprocess.run(
            ["redis-cli", "ping"],
            capture_output=True, text=True, timeout=4
        )
        redis_ok = r.stdout.strip() == "PONG"
    except (OSError, subprocess.SubprocessError):
        pass
    
    # Try to reach the WS port (TCP connect test)
    ws_port_open = False
    try:
        import socket as _socket
        s = _socket.socket()
        s.settimeout(2)
        s.connect(("127.0.0.1", WS_PORT))
        s.close()
        ws_port_open = True
    except (OSError, socket.error):
        pass
    
    # Get tail of consumer log
    consumer_log_tail = []
    try:
        r = subprocess.run(
            ["tail", "-n", "30", "data/logs/consumer.log"],
            capture_output=True, text=True, timeout=5,
        )
        consumer_log_tail = r.stdout.strip().splitlines() if r.returncode == 0 else [r.stderr.strip()]
    except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError) as e:
        consumer_log_tail = [f"(could not read log: {e})"]
    
    # Build diagnosis
    issues = []
    if not consumer_running:
        issues.append("ML consumer (consumer.py) is NOT running. Run ./start.sh")
    if not redis_ok:
        issues.append("Redis is not responding. Run: sudo service redis-server start")
    if consumer_running and not ws_port_open:
        issues.append(f"WebSocket port {WS_PORT} is not reachable. The consumer may still be initializing — wait 5-10s.")
    if not issues:
        issues.append("All checks passed — pipeline appears healthy.")
    
    with _relay_status_lock:
        relay_snapshot = dict(_relay_status)
    with _browser_lock:
        browser_client_count = len(_browser_clients)
    
    return jsonify({
        "relay": relay_snapshot,
        "checks": {
            "consumer_running": consumer_running,
            "redis_ok": redis_ok,
            "ws_port_open": ws_port_open,
            "ws_port": WS_PORT,
            "browser_clients_connected": browser_client_count,
        },
        "diagnosis": issues,
        "consumer_log_tail": consumer_log_tail,
        "ts": time.strftime("%H:%M:%S"),
    }), 200

@app.route("/api/alerts/clear", methods=["POST"])
def api_alerts_clear():
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

@app.route("/api/relay/reconnect", methods=["POST"])
def api_relay_reconnect():
    """Immediately interrupt relay backoff sleep and trigger a reconnect attempt."""
    logger.info("[Relay] Manual reconnection requested via API.")
    with _relay_status_lock:
        _relay_status["consecutive_failures"] = 0
        _relay_status["state"] = "retrying"
    _relay_reconnect_event.set()
    return jsonify({"success": True, "message": "Reconnect signal sent — relay will retry immediately"}), 200

@app.route("/api/nmap/analyse", methods=["POST"])
def api_nmap_analyse():
    data = request.get_json() or {}
    analysis = analyse_with_gemini(data.get("nmap_output", ""), data.get("target", "unknown"))
    return jsonify({"success": True, "analysis": analysis}), 200

if __name__ == "__main__":
    app.run(host=DEFAULT_BIND_HOST, port=DEFAULT_BIND_PORT, debug=False, use_reloader=False)
