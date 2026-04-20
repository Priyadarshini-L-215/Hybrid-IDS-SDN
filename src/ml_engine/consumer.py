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
import websockets

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.feature_extractor import extract_features_from_eve, load_feature_names, validate_feature_vector
from common.database import init_db, add_alert
from common.config import (
    EVE_LOG, ML_ALERTS_LOG, HEARTBEAT_LOG, 
    MODEL_PATH, FEATURES_PATH, 
    POLL_INTERVAL_SEC, HEARTBEAT_INTERVAL_SEC,
    WS_HOST, WS_PORT, DATA_SERVICE_PORT,
    ensure_dirs
)
from ml_engine.data_service import start_data_service
from ml_engine.firewall import ActiveFirewall
import collections

# Initialize
ensure_dirs()
init_db()

# WebSocket broadcast state
_ws_clients = set()
_ws_lock = asyncio.Lock()
_RUNNING = True

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

async def _ws_handler(websocket):
    """
    Handle new WebSocket connections.
    Updated signature for websockets 14.0+ compatibility.
    """
    async with _ws_lock:
        _ws_clients.add(websocket)
        logger.info(f"[WS] New client connected. Total: {len(_ws_clients)}")
    try:
        await websocket.wait_closed()
    finally:
        async with _ws_lock:
            if websocket in _ws_clients:
                _ws_clients.discard(websocket)
                logger.info(f"[WS] Client disconnected. Total: {len(_ws_clients)}")

async def _broadcast(message: str):
    """Broadcast message to all connected clients."""
    async with _ws_lock:
        if not _ws_clients:
            return
        # Copy set to avoid mutation issues during iteration
        clients = list(_ws_clients)
    
    # Use gather to send to all clients in parallel
    if clients:
        tasks = []
        for client in clients:
            tasks.append(client.send(message))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

class MLEngine:
    def __init__(self):
        logger.info("Initializing Machine Learning Model...")
        self.use_sklearn = False
        self.model = None
        
        try:
            if MODEL_PATH.exists():
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
            else:
                logger.warning(f"Model file not found at {MODEL_PATH} - using heuristic classifier")
        except Exception as e:
            logger.warning(f"Could not load sklearn model: {e}. Using heuristics.")
        
        try:
            self.features = load_feature_names(FEATURES_PATH)
            logger.info(f"[OK] Loaded {len(self.features)} feature definitions")
        except Exception as e:
            logger.error(f"Failed to load features: {e}")
            raise

    def extract_features(self, event):
        try:
            # Shared logic from feature_extractor.py
            feature_vector = extract_features_from_eve(event, self.features)
            if feature_vector and validate_feature_vector(feature_vector):
                return feature_vector
            return None
        except Exception as e:
            logger.error(f"Feature extraction error: {e}")
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
                except:
                    confidence = 100.0
                classification = "attack" if int(prediction) == 1 else "normal"
            else:
                classification, confidence = self._heuristic_predict(feature_vector)
            
            return {
                "classification": classification,
                "raw_prediction": 1 if classification == "attack" else 0,
                "confidence": round(confidence, 2)
            }
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {"classification": "error", "error": str(e)}

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

    while _RUNNING:
        line = f.readline()
        now = time.time()

        # Heartbeat logic
        if now - last_hb >= HEARTBEAT_INTERVAL_SEC:
            try:
                with open(HEARTBEAT_LOG, "w") as hb:
                    hb.write(datetime.now(timezone.utc).isoformat())
                
                # Periodic summary log for visibility
                if 'events_in_session' not in locals(): events_in_session = 0
                if 'last_activity' not in locals(): last_activity = now
                
                status_msg = f"[STATUS] Session events: {events_in_session} | "
                if events_in_session == 0:
                    status_msg += "Watching /var/log/suricata/eve.json..."
                else:
                    status_msg += f"Stable (Last: {int(now - last_activity)}s ago)"
                logger.info(status_msg)
                
                last_hb = now
            except: pass

        if line:
            if 'events_in_session' not in locals(): events_in_session = 0
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
                
                logger.info(f"[{prediction['classification'].upper()}] {db_payload['src_ip']} -> {db_payload['dest_ip']} ({prediction['confidence']}%)")

            except Exception as e:
                logger.error(f"Processing error: {e}")
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
            except: pass
            
            await asyncio.sleep(POLL_INTERVAL_SEC)
            continue

    f.close()

async def main():
    """Application entry point."""
    global _RUNNING
    
    # Handle shutdown signals
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: setattr(sys.modules[__name__], '_RUNNING', False))

    logger.info(f"Starting Anti-Gravity IDS Consumer (WS: {WS_HOST}:{WS_PORT})")
    
    # Start the native bridge data service for Windows bypass
    start_data_service()
    
    try:
        # Start WebSocket server and log tailer concurrently
        async with websockets.serve(_ws_handler, WS_HOST, WS_PORT):
            logger.info(f"[WS] WebSocket server online at ws://{WS_HOST}:{WS_PORT}")
            await log_tailer()
    except Exception as e:
        logger.critical(f"FATAL ERROR in main loop: {e}")
        # Ensure we exit so start_ids.sh notices
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.critical(f"Unhandled exception: {e}")
        sys.exit(1)
