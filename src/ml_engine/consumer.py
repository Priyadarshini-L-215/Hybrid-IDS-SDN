import json
import os
import time
import pickle
import logging
import signal
import pandas as pd
from pathlib import Path
import sys
from datetime import datetime, timezone
import asyncio
import threading
import websockets
from redis.exceptions import RedisError
from websockets.exceptions import ConnectionClosed, WebSocketException

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.feature_extractor import extract_features_from_eve, load_feature_names, validate_feature_vector
from common.database import init_db, add_alert
from common.config import (
    EVE_LOG, HEARTBEAT_LOG, 
    MODEL_PATH, FEATURES_PATH, 
    POLL_INTERVAL_SEC, HEARTBEAT_INTERVAL_SEC,
    WS_HOST, WS_PORT,
    ensure_dirs, LOG_LEVEL,
    USE_REDIS_QUEUE, WORKER_COUNT, BATCH_SIZE, WATCHER_FLUSH_TIMEOUT,
    REDIS_QUEUE_NAME, REDIS_HOST, REDIS_PORT
)
from ml_engine.data_service import start_data_service
from ml_engine.firewall import ActiveFirewall
from ml_engine.redis_client import test_redis, redis_client
from ml_engine.file_watcher import AsyncFileWatcher
from ml_engine.worker_pool import WorkerPool
import collections

# Initialize
ensure_dirs()
init_db()

# WebSocket broadcast state
_ws_clients = set()
_ws_clients_lock = threading.Lock()
_ws_queue = None             # Initialized in main() to ensure correct event loop
_RUNNING = True
_TRACER_ENABLED = os.environ.get("SENTINEL_TRACER", "0") == "1"

# Setup logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.WARNING),
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


def _sanitize_tracer_fields(payload: dict) -> dict:
    if _TRACER_ENABLED:
        return payload

    for tracer_key in ("_tracer", "_watcher_read_ts", "_redis_push_ts", "_ws_send_ts"):
        payload.pop(tracer_key, None)
    return payload

async def _ws_handler(websocket):
    """Handle new WebSocket connections."""
    logger.info(f"[WS] Connection attempt from {websocket.remote_address}")
    with _ws_clients_lock:
        _ws_clients.add(websocket)
        total_clients = len(_ws_clients)
    logger.info(f"[WS] Client connected. Total: {total_clients}")
    try:
        # websockets 14+ requires consuming the stream to process ping/pong/close frames
        async for _ in websocket:
            pass
    except (ConnectionClosed, WebSocketException, OSError) as exc:
        logger.debug(f"[WS] Connection closed or reset: {exc}")
    finally:
        with _ws_clients_lock:
            if websocket in _ws_clients:
                _ws_clients.discard(websocket)
            total_clients = len(_ws_clients)
        logger.info(f"[WS] Client disconnected. Total: {total_clients}")

async def _broadcast(message: str):
    """Adds message to the broadcast queue."""
    if _ws_queue:
        await _ws_queue.put(message)

async def _broadcast_worker():
    """Background task to pull from queue and send to all clients in batches."""
    logger.info("[WS] Broadcast worker started")
    while _RUNNING:
        try:
            # Wait for at least one message
            message = await _ws_queue.get()
            
            # Stamp tracer events with T4 (WS send time) only when enabled.
            try:
                parsed = json.loads(message)
                if parsed.get("_tracer") and _TRACER_ENABLED:
                    parsed["_ws_send_ts"] = time.time()
                    logger.info(f"[TRACER] T4 WS broadcast at {parsed['_ws_send_ts']:.6f}")
                elif not _TRACER_ENABLED:
                    parsed = _sanitize_tracer_fields(parsed)
                    message = json.dumps(parsed)
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
            
            with _ws_clients_lock:
                clients = list(_ws_clients)
            if not clients:
                _ws_queue.task_done()
                continue
            
            # Send to all clients
            if clients:
                tasks = [client.send(message) for client in clients]
                await asyncio.gather(*tasks, return_exceptions=True)
            
            _ws_queue.task_done()
        except (OSError, RuntimeError, WebSocketException, asyncio.CancelledError) as exc:
            if not _RUNNING: break
            logger.error(f"[WS] Broadcast worker error: {exc}")
            await asyncio.sleep(0.1)

class MLEngine:
    def __init__(self):
        logger.info("Initializing Machine Learning Model...")
        self.use_sklearn = False
        self.model = None
        
        try:
            with open(MODEL_PATH, "rb") as f:
                content = f.read(10)
                f.seek(0)
                # Simple check for pickle format
                if content.startswith(b'\x80') or content.startswith(b'('):
                    self.model = pickle.load(f)
                    self.use_sklearn = True
                    logger.info("[OK] Sklearn Random Forest model loaded")
                else:
                    logger.info("Model file is placeholder - using heuristic classifier")
        except FileNotFoundError as exc:
            logger.error(f"Model file not found at {MODEL_PATH}: {exc}")
            raise SystemExit(1)
        except (OSError, EOFError, pickle.UnpicklingError, AttributeError, ValueError) as exc:
            logger.error(f"Could not load sklearn model from {MODEL_PATH}: {exc}")
            raise SystemExit(1)
        
        try:
            self.features = load_feature_names(FEATURES_PATH)
            logger.info(f"[OK] Loaded {len(self.features)} feature definitions")
        except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError) as exc:
            logger.error(f"Failed to load features: {exc}")
            raise

    def extract_features(self, event):
        try:
            # Shared logic from feature_extractor.py
            feature_vector = extract_features_from_eve(event, self.features)
            if feature_vector and validate_feature_vector(feature_vector):
                return feature_vector
            return None
        except (ValueError, KeyError, TypeError, AttributeError, json.JSONDecodeError) as exc:
            logger.error(f"Feature extraction error: {exc}")
            return None

    def predict(self, feature_vector):
        try:
            if self.use_sklearn and self.model is not None:
                # Prepare data for model
                df = pd.DataFrame([feature_vector], columns=self.features)
                prediction = self.model.predict(df)[0]
                try:
                    proba = self.model.predict_proba(df)[0]
                    confidence = float(max(proba)) * 100
                except (AttributeError, IndexError, TypeError, ValueError):
                    confidence = 100.0
                classification = "attack" if int(prediction) == 1 else "normal"
            else:
                classification, confidence = self._heuristic_predict(feature_vector)
            
            return {
                "classification": classification,
                "raw_prediction": 1 if classification == "attack" else 0,
                "confidence": round(confidence, 2)
            }
        except (ValueError, TypeError, AttributeError, KeyError, IndexError) as exc:
            logger.error(f"Prediction error: {exc}")
            return {"classification": "error", "error": str(exc)}

    def _heuristic_predict(self, feature_vector):
        """Fallback heuristics if ML model is unavailable."""
        feature_dict = {name: val for name, val in zip(self.features, feature_vector)}
        score = 0
        # High volume/frequency signals
        if feature_dict.get("Flow Bytes/s", 0) > 10_000_000: score += 40
        if feature_dict.get("Flow Packets/s", 0) > 100_000: score += 40
        if feature_dict.get("Packet Length Std", 0) > 500: score += 20
        
        # More aggressive heuristic for high-frequency low-payload flows (common in scans)
        if feature_dict.get("Flow Bytes/s", 0) < 1000 and feature_dict.get("Flow Packets/s", 0) > 100: score += 30
        
        classification = "attack" if score >= 20 else "normal"
        confidence = min(60 + score, 99)
        return classification, confidence


# ========== REDIS-BACKED PIPELINE (NEW - Option B) ==========

async def eve_batch_to_redis(batch):
    """
    Callback: batch of EVE JSON lines → parse → push to Redis queue.
    Used by AsyncFileWatcher.
    """
    if not batch or redis_client is None:
        return
    
    for line in batch:
        try:
            event = json.loads(line.strip())
            # Stamp tracer events with T2 only when enabled.
            if event.get("_tracer") and _TRACER_ENABLED:
                event["_redis_push_ts"] = time.time()
                logger.info(f"[TRACER] T2 Redis push at {event['_redis_push_ts']:.6f}")
            elif not _TRACER_ENABLED:
                event = _sanitize_tracer_fields(event)
            # Push to Redis queue
            redis_client.rpush(REDIS_QUEUE_NAME, json.dumps(event))
        except (json.JSONDecodeError, TypeError, RedisError, OSError) as exc:
            logger.debug(f"[Redis] Queue push skipped: {exc}")


async def redis_reader_task():
    """
    Reader task: watch EVE file and feed Redis queue with batches.
    Replaces polling-based reading with async file watching.
    """
    logger.info(f"[Redis] Waiting for EVE log: {EVE_LOG}")
    while not EVE_LOG.exists():
        await asyncio.sleep(1)
    
    logger.info(f"[Redis] Monitoring {EVE_LOG} for events (batching {BATCH_SIZE} per push)")
    
    watcher = AsyncFileWatcher(EVE_LOG, batch_size=BATCH_SIZE, flush_timeout=WATCHER_FLUSH_TIMEOUT)
    await watcher.watch(eve_batch_to_redis)

async def redis_pipeline_main():
    """
    Main entry point for Redis-backed pipeline.
    
    Startup sequence is strictly sequential to avoid race conditions:
    1. Bind WebSocket server (prevents hang)
    2. Start Worker Pool
    3. Start File Watcher/Reader
    """
    global _RUNNING
    
    # Check Redis connectivity
    if not test_redis():
        logger.error(f"[Redis] Cannot connect to Redis at {REDIS_HOST}:{REDIS_PORT}")
        logger.error("[Redis] Falling back to legacy polling mode")
        return await log_tailer()
    
    # Initialize ML engine for workers
    engine = MLEngine()
    
    # Initialize worker pool with current event loop for thread-safe broadcasting
    loop = asyncio.get_running_loop()
    worker_pool = WorkerPool(worker_count=WORKER_COUNT, ml_engine=engine, broadcast_func=_broadcast, loop=loop)
    
    # 1. Start WebSocket server and maintain pipeline within its context
    bind_host = "0.0.0.0" # Bind to all interfaces for bridge accessibility
    logger.info(f"[WS] Starting WebSocket server on {bind_host}:{WS_PORT}...")
    try:
        async with websockets.serve(_ws_handler, bind_host, WS_PORT, ping_interval=30, ping_timeout=15):
            logger.info(f"[WS] WebSocket server online on {bind_host}:{WS_PORT}")
            
            # 2. Start workers and broadcast worker after WS is confirmed listening
            logger.info("[Redis] Starting worker pool and broadcast worker...")
            worker_pool.start()
            asyncio.create_task(_broadcast_worker())
            
            # 3. Start reader coroutine
            async def reader():
                logger.info(f"[Redis] Waiting for EVE log: {EVE_LOG}")
                while not EVE_LOG.exists() and _RUNNING:
                    await asyncio.sleep(1)
                
                if not _RUNNING: return
                
                logger.info(f"[Redis] Monitoring {EVE_LOG} for events")
                watcher = AsyncFileWatcher(EVE_LOG, batch_size=BATCH_SIZE, flush_timeout=WATCHER_FLUSH_TIMEOUT)
                await watcher.watch(eve_batch_to_redis)

            # Run reader and keep-alive loop
            # Create reader as a background task
            asyncio.create_task(reader())
            
            logger.info("[Main] Pipeline fully initialized and running")
            while _RUNNING:
                await asyncio.sleep(1)
                
    except (OSError, RuntimeError, WebSocketException, RedisError) as exc:
        logger.error(f"[Main] Pipeline runtime error: {exc}")
    finally:
        logger.info("[Redis] Shutting down pipeline...")
        _RUNNING = False
        worker_pool.stop()
        logger.info("[Redis] Pipeline stopped")


# ========== LEGACY PIPELINE (Old - backward compatible) ==========

async def log_tailer():
    """Main loop for tailing EVE log and processing alerts."""
    global _RUNNING
    engine = MLEngine()
    
    # Stateful Tracking for Flow Correlation
    # Stores timestamps of flows per IP: {ip: [ts1, ts2, ...]}
    flow_history = collections.defaultdict(list)
    port_history = collections.defaultdict(set)
    WINDOW_SIZE = 10.0 # seconds
    
    logger.info(f"Waiting for Suricata log file: {EVE_LOG}")
    while not EVE_LOG.exists() and _RUNNING:
        await asyncio.sleep(1)
    
    if not _RUNNING: return

    logger.info(f"Tailing {EVE_LOG} for events...")
    
    # Persistent file handle
    f = open(EVE_LOG, "r", encoding="utf-8")
    f.seek(0, os.SEEK_END)
    current_inode = os.fstat(f.fileno()).st_ino
    
    last_hb = 0.0
    events_in_session = 0
    last_activity = time.time()

    while _RUNNING:
        line = f.readline()
        now = time.time()

        # Heartbeat logic
        if now - last_hb >= HEARTBEAT_INTERVAL_SEC:
            try:
                with open(HEARTBEAT_LOG, "w") as hb:
                    hb.write(datetime.now(timezone.utc).isoformat())
                
                status_msg = f"[STATUS] Session events: {events_in_session} | "
                if events_in_session == 0:
                    status_msg += "Watching /var/log/suricata/eve.json..."
                else:
                    status_msg += f"Stable (Last: {int(now - last_activity)}s ago)"
                logger.info(status_msg)
                
                last_hb = now
            except OSError as exc:
                logger.debug(f"Heartbeat write skipped: {exc}")

        if line:
            events_in_session += 1
            last_activity = now
            try:
                event = json.loads(line)
                
                # 1. Feature Extraction
                features = engine.extract_features(event)
                if features is None: continue

                # 2. ML Prediction
                prediction = engine.predict(features)
                if prediction["classification"] == "error": continue

                # 3. DB Logging
                alert_info = event.get("alert", {})
                # Override ML if Suricata already knows it's an alert
                final_classification = prediction.get("classification")
                final_confidence = prediction.get("confidence")
                
                if event.get("event_type") == "alert":
                    final_classification = "attack"
                    final_confidence = max(final_confidence, 90.0)

                # Dynamic Signature Enrichment
                sig = alert_info.get("signature")
                if not sig:
                    etype = event.get("event_type", "flow")
                    if etype == "dns":
                        dns = event.get("dns", {})
                        sig = f"DNS Query: {dns.get('rrname', 'unknown')}"
                    elif etype == "http":
                        http = event.get("http", {})
                        sig = f"HTTP {http.get('http_method')} -> {http.get('hostname', 'unknown')}"
                    elif etype == "ssh":
                        sig = "SSH Connection Attempt"
                    else:
                        proto = event.get("proto", "TCP")
                        port = event.get("dest_port", "")
                        sig = f"{proto} Potential Probe (Port {port})" if final_classification == "attack" else f"{proto} Flow"

                # Build db_payload OUTSIDE the if-not-sig block so it always exists
                db_payload = {
                    "timestamp": event.get("timestamp"),
                    "event_type": event.get("event_type"),
                    "src_ip": event.get("src_ip"),
                    "src_port": event.get("src_port"),
                    "dest_ip": event.get("dest_ip"),
                    "dest_port": event.get("dest_port"),
                    "protocol": event.get("proto"),
                    "alert_sig": sig,
                    "prediction": final_classification,
                    "confidence": final_confidence,
                    "severity": alert_info.get("severity", 4),
                    "category": alert_info.get("category", "ML Detection"),
                    "raw_event": event
                }

                # --- 3a. Stateful Flow Correlation ---
                src_ip = db_payload['src_ip']
                if src_ip and src_ip not in ["127.0.0.1", "172.25.16.1"]:
                    flow_history[src_ip].append(now)
                    if db_payload['dest_port']:
                        port_history[src_ip].add(db_payload['dest_port'])
                    
                    # Cleanup old entries
                    flow_history[src_ip] = [ts for ts in flow_history[src_ip] if now - ts < WINDOW_SIZE]
                    
                    # Detection Rules
                    detected_scan = False
                    if len(port_history[src_ip]) > 25:
                        final_classification = "attack"
                        final_confidence = 99.0
                        db_payload['alert_sig'] = f"Stateful Port Scan (Targeting {len(port_history[src_ip])} ports)"
                        db_payload['category'] = "Reconnaissance"
                        detected_scan = True
                        port_history[src_ip].clear() # Reset after detection
                    
                    if len(flow_history[src_ip]) > 100:
                        final_classification = "attack"
                        final_confidence = 98.0
                        db_payload['alert_sig'] = "Volumetric Flow Anomaly (DoS Pattern)"
                        db_payload['category'] = "Resource Exhaustion"
                        detected_scan = True
                    
                    if detected_scan:
                        db_payload['prediction'] = final_classification
                        db_payload['confidence'] = final_confidence

                # --- 3b. Active IPS (Firewall) ---
                if final_classification == "attack" and final_confidence >= 95.0:
                    ActiveFirewall.block(db_payload['src_ip'])
                    db_payload['category'] = f"IPS Blocked - {db_payload.get('category', 'Threat')}"

                add_alert(db_payload)

                # 4. WebSocket Broadcast
                await _broadcast(json.dumps(db_payload))
                
                logger.info(f"[{final_classification.upper()}] {db_payload['src_ip']} -> {db_payload['dest_ip']} ({final_confidence}%)")  # use final_ not original prediction

            except (json.JSONDecodeError, KeyError, TypeError, ValueError, OSError) as exc:
                logger.error(f"Processing error: {exc}")
        else:
            # Check for rotation
            try:
                s = EVE_LOG.stat()
                if s.st_ino != current_inode or s.st_size < f.tell():
                    logger.info("Log rotation detected, reopening...")
                    f.close()
                    f = open(EVE_LOG, "r", encoding="utf-8")
                    current_inode = os.fstat(f.fileno()).st_ino
                    continue
            except OSError as exc:
                logger.debug(f"Log rotation check failed: {exc}")
            
            await asyncio.sleep(POLL_INTERVAL_SEC)
            continue

    f.close()

async def main():
    """Application entry point."""
    global _RUNNING
    
    # Initialize the broadcast queue within the running loop
    global _ws_queue
    _ws_queue = asyncio.Queue()
    
    # Handle shutdown signals
    loop = asyncio.get_running_loop()
    def handle_exit():
        global _RUNNING
        _RUNNING = False
        logger.info("[Main] Shutdown signal received")

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, handle_exit)
        except NotImplementedError:
            # Fallback for systems where add_signal_handler is not implemented
            pass

    logger.info(f"Starting Sentinel Core IDS Consumer (WS: {WS_HOST}:{WS_PORT})")
    
    # (No lock needed — broadcast uses a queue)
    
    # Log pipeline mode
    if USE_REDIS_QUEUE:
        logger.info("[Main] Using Redis-backed pipeline (Option B - experimental)")
        logger.info(f"[Main] Redis: {REDIS_HOST}:{REDIS_PORT}, Workers: {WORKER_COUNT}, Batch: {BATCH_SIZE}")
    else:
        logger.info("[Main] Using legacy polling pipeline")
    
    # Start the native bridge data service for Windows bypass
    start_data_service()
    
    try:
        # Choose pipeline based on config
        if USE_REDIS_QUEUE:
            await redis_pipeline_main()
        else:
            # Legacy path: WebSocket server + polling log tailer
            async with websockets.serve(_ws_handler, WS_HOST, WS_PORT):
                logger.info(f"[WS] WebSocket server online at ws://{WS_HOST}:{WS_PORT}")
                await log_tailer()
    except (OSError, RuntimeError, WebSocketException, RedisError) as exc:
        logger.critical(f"FATAL ERROR in main loop: {exc}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        # Top-level crash guard: intentionally broad so the process exits cleanly on any uncaught failure.
        logger.critical(f"Unhandled exception: {exc}")
        sys.exit(1)
