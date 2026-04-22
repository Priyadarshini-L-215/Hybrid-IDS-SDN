"""
Sentinel Core IPS – Flask WebSocket Relay & API Backend
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
import socket
import websockets as ws_client

# Ensure sibling and parent modules are importable
CURRENT_DIR = Path(__file__).resolve().parent
SRC_DIR = CURRENT_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from integration import tail_ml_alerts, get_consumer_heartbeat
    from common.config import (
        EVE_LOG, ML_ALERTS_LOG, WS_URI, WS_PORT,
        ALERT_CACHE_SIZE, ensure_dirs
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

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
sock = Sock(app)

# --- Internal relay: connects to consumer WS, broadcasts to browsers ---
_browser_clients = set()
_browser_lock = threading.Lock()

# Relay status for diagnostics
_relay_status = {
    "state": "starting",          # starting | connected | retrying | failed
    "current_uri": WS_URI,
    "consecutive_failures": 0,
    "last_error": None,
    "last_connected_at": None,
    "wsl_ip": None,
    "messages_relayed": 0,
}

# Signal the relay worker to skip its sleep and retry immediately
_relay_reconnect_event = threading.Event()


def _build_relay_candidates(seed_uri: str):
    """Build ordered relay candidates from configured URI and current WSL IP."""
    candidates = []

    def _add(uri):
        if uri and uri not in candidates:
            candidates.append(uri)

    _add(seed_uri)
    _add(f"ws://127.0.0.1:{WS_PORT}")

    # Fallback to WSL IP if 127.0.0.1 fails
    wsl_ip = _get_wsl_ip()
    if wsl_ip:
        _add(f"ws://{wsl_ip}:{WS_PORT}")

    return candidates

def _get_wsl_ip():
    """Resolve WSL2 IP address by querying `wsl hostname -I`."""
    try:
        import subprocess
        output = subprocess.check_output(["wsl", "hostname", "-I"], text=True, timeout=3)
        ip = output.strip().split()[0]
        _relay_status["wsl_ip"] = ip
        return ip
    except Exception as exc:
        logger.warning(f"[Relay] Could not resolve WSL IP: {exc}")
        _relay_status["wsl_ip"] = None
        return None

def _relay_worker():
    """Relays messages from WSL consumer to browser clients."""
    async def _relay():
        global _browser_clients
        
        relay_candidates = _build_relay_candidates(WS_URI)
        candidate_idx = 0
        current_uri = relay_candidates[candidate_idx]
        logger.info(f"[Relay] Targeting {current_uri} (candidates: {relay_candidates})")
        
        _relay_status["current_uri"] = current_uri
        _relay_status["state"] = "starting"
        
        RETRY_INTERVAL = 3.0   # seconds between attempts
        WSL_RECHECK_EVERY = 5  # re-resolve WSL IP every N failures
        consecutive_failures = 0
        
        while True:
            try:
                logger.info(f"[Relay] Connecting → {current_uri} (attempt {consecutive_failures + 1})")
                _relay_status["state"] = "retrying"
                
                async with ws_client.connect(
                    current_uri,
                    open_timeout=15,  # Increased from 5 to 15 to handle WSL startup lag
                    ping_interval=20,
                    ping_timeout=20,
                    close_timeout=10
                ) as ws:
                    logger.info(f"[Relay] ✓ Pipeline active: {current_uri}")
                    consecutive_failures = 0
                    _relay_status.update({
                        "state": "connected",
                        "consecutive_failures": 0,
                        "last_error": None,
                        "last_connected_at": time.strftime("%H:%M:%S"),
                        "current_uri": current_uri,
                    })
                    
                    async for message in ws:
                        relay_recv_ts = time.time()  # T5a: relay received from WSL
                        
                        # Stamp tracer events with T5 (relay timestamps)
                        try:
                            parsed = json.loads(message)
                            if parsed.get("_tracer"):
                                parsed["_relay_recv_ts"] = relay_recv_ts
                                parsed["_relay_fwd_ts"] = time.time()  # T5b: about to forward
                                message = json.dumps(parsed)
                                logger.info(f"[TRACER] T5 Relay recv at {relay_recv_ts:.6f}")
                        except (json.JSONDecodeError, TypeError, ValueError):
                            pass
                        
                        _relay_status["messages_relayed"] += 1
                        with _browser_lock:
                            if not _browser_clients:
                                continue
                            dead = set()
                            for client in list(_browser_clients):
                                try:
                                    client.send(message)
                                except Exception:
                                    dead.add(client)
                            if dead:
                                _browser_clients -= dead
                                logger.debug(f"[Relay] Pruned {len(dead)} dead browser connections")

            except (ConnectionRefusedError, socket.error,
                    ws_client.exceptions.InvalidMessage,
                    asyncio.TimeoutError,
                    ws_client.exceptions.WebSocketException) as e:
                consecutive_failures += 1
                err_msg = f"{type(e).__name__}: {e}"
                _relay_status.update({
                    "state": "retrying",
                    "consecutive_failures": consecutive_failures,
                    "last_error": err_msg,
                    "current_uri": current_uri,
                })
                
                hint = ""
                if isinstance(e, ConnectionRefusedError):
                    hint = " [consumer not running or WSL restarted]"
                elif isinstance(e, asyncio.TimeoutError):
                    hint = " [WSL firewall/port not exposed — check consumer started]"
                
                logger.warning(
                    f"[Relay] ✗ {current_uri} unreachable — {type(e).__name__}{hint} "
                    f"(attempt {consecutive_failures}). Retry in {RETRY_INTERVAL}s..."
                )

                # Try the next candidate first for fast recovery on mixed WSL networking setups.
                if len(relay_candidates) > 1:
                    candidate_idx = (candidate_idx + 1) % len(relay_candidates)
                    next_uri = relay_candidates[candidate_idx]
                    if next_uri != current_uri:
                        current_uri = next_uri
                        _relay_status["current_uri"] = current_uri
                        logger.info(f"[Relay] Switching target → {current_uri}")
                
                # Re-resolve WSL IP periodically — WSL IP can change after restart
                if consecutive_failures % WSL_RECHECK_EVERY == 0:
                    new_ip = _get_wsl_ip()
                    if new_ip:
                        candidate = f"ws://{new_ip}:{WS_PORT}"
                        if candidate not in relay_candidates:
                            relay_candidates.append(candidate)
                            logger.info(f"[Relay] Added new WSL relay candidate → {candidate}")
                    else:
                        logger.error(
                            "[Relay] ✗ WSL IP could not be resolved. "
                            "Is WSL running? Run: wsl hostname -I"
                        )
                
                # Interruptible sleep: check _relay_reconnect_event in 1s ticks
                sleep_time = min(RETRY_INTERVAL * (2 ** (consecutive_failures // 3)), 30.0)
                _relay_reconnect_event.clear()
                deadline = time.time() + sleep_time
                while time.time() < deadline:
                    if _relay_reconnect_event.is_set():
                        logger.info("[Relay] Reconnect signal received — retrying immediately")
                        break
                    await asyncio.sleep(1.0)

            except Exception as e:
                consecutive_failures += 1
                err_msg = f"{type(e).__name__}: {e}"
                _relay_status.update({
                    "state": "retrying",
                    "consecutive_failures": consecutive_failures,
                    "last_error": err_msg,
                })
                logger.error(f"[Relay] ✗ Unexpected error: {err_msg}. Reconnecting in {RETRY_INTERVAL}s...")
                # Interruptible sleep
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
    except Exception:
        pass
    finally:
        with _browser_lock:
            _browser_clients.discard(ws)

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

@app.route("/api/pipeline/status", methods=["GET"])
def api_pipeline_status():
    """Live diagnostic endpoint — shows exactly what the relay is doing and why it may be failing."""
    import subprocess
    
    # Check WSL is up
    wsl_running = False
    wsl_ip = None
    try:
        out = subprocess.check_output(["wsl", "hostname", "-I"], text=True, timeout=3).strip()
        wsl_ip = out.split()[0] if out.strip() else None
        wsl_running = bool(wsl_ip)
    except Exception as e:
        wsl_ip = None
        wsl_running = False
    
    # Check consumer process in WSL
    consumer_running = False
    try:
        r = subprocess.run(
            ["wsl", "pgrep", "-f", "consumer.py"],
            capture_output=True, text=True, timeout=4
        )
        consumer_running = r.returncode == 0
    except Exception:
        pass
    
    # Check Redis in WSL
    redis_ok = False
    try:
        r = subprocess.run(
            ["wsl", "redis-cli", "ping"],
            capture_output=True, text=True, timeout=4
        )
        redis_ok = r.stdout.strip() == "PONG"
    except Exception:
        pass
    
    # Try to reach the WS port from Windows (TCP connect test)
    ws_port_open = False
    test_host = wsl_ip or "127.0.0.1"
    try:
        import socket as _socket
        s = _socket.socket()
        s.settimeout(2)
        s.connect((test_host, WS_PORT))
        s.close()
        ws_port_open = True
    except Exception:
        pass
    
    # Get tail of consumer log from WSL
    consumer_log_tail = []
    try:
        r = subprocess.run(
            ["wsl", "tail", "-n", "30", "data/logs/consumer.log"],
            capture_output=True, text=True, timeout=5,
            cwd=None  # wsl resolves paths relative to Windows CWD
        )
        consumer_log_tail = r.stdout.strip().splitlines() if r.returncode == 0 else [r.stderr.strip()]
    except Exception as e:
        consumer_log_tail = [f"(could not read log: {e})"]
    
    # Build diagnosis
    issues = []
    if not wsl_running:
        issues.append("WSL is not running. Run: wsl in a terminal to start it.")
    if wsl_running and not consumer_running:
        issues.append("ML consumer (consumer.py) is NOT running inside WSL. Run start.bat or: wsl -u root bash start_ids.sh")
    if wsl_running and not redis_ok:
        issues.append("Redis is not responding inside WSL. Run: wsl -u root redis-server --daemonize yes")
    if wsl_running and consumer_running and not ws_port_open:
        issues.append(f"WebSocket port {WS_PORT} is not reachable on {test_host}. The consumer may still be initializing — wait 5-10s.")
    if not issues:
        issues.append("All checks passed — pipeline appears healthy.")
    
    with _browser_lock:
        browser_client_count = len(_browser_clients)
    
    return jsonify({
        "relay": _relay_status,
        "checks": {
            "wsl_running": wsl_running,
            "wsl_ip": wsl_ip,
            "consumer_running": consumer_running,
            "redis_ok": redis_ok,
            "ws_port_open": ws_port_open,
            "ws_port": WS_PORT,
            "ws_test_host": test_host,
            "browser_clients_connected": browser_client_count,
        },
        "diagnosis": issues,
        "consumer_log_tail": consumer_log_tail,
        "ts": time.strftime("%H:%M:%S"),
    }), 200

@app.route("/api/alerts/clear", methods=["POST"])
def api_alerts_clear():
    # In a real environment, you'd add _guard_sensitive_api() here
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
    _relay_status["consecutive_failures"] = 0
    _relay_status["state"] = "retrying"
    _relay_reconnect_event.set()  # Interrupt asyncio.sleep in the relay loop
    return jsonify({"success": True, "message": "Reconnect signal sent — relay will retry immediately"}), 200

@app.route("/api/nmap/analyse", methods=["POST"])
def api_nmap_analyse():
    data = request.get_json() or {}
    analysis = analyse_with_gemini(data.get("nmap_output", ""), data.get("target", "unknown"))
    return jsonify({"success": True, "analysis": analysis}), 200

if __name__ == "__main__":
    app.run(host=DEFAULT_BIND_HOST, port=DEFAULT_BIND_PORT, debug=False, use_reloader=False)
