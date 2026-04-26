import json
import os
import time
import logging
import signal
import warnings
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
import sys
from datetime import datetime, timezone
import asyncio
import threading
import websockets
try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    torch = None
    nn = None
    TORCH_AVAILABLE = False
from redis.exceptions import RedisError
from websockets.exceptions import ConnectionClosed, WebSocketException

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.feature_extractor import extract_features_from_eve, load_feature_names, validate_feature_vector
from common.database import init_db, add_alert
from common.config import (
    EVE_LOG, HEARTBEAT_LOG, 
    RF_MODEL_PATH, SCALER_PATH, AUTOENCODER_PATH, FEATURES_PATH,
    AUTOENCODER_THRESHOLD, AUTOENCODER_THRESHOLD_PERCENTILE,
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

# Suppress repetitive sklearn metadata warning spam in production logs.
warnings.filterwarnings(
    "ignore",
    message="X does not have valid feature names, but StandardScaler was fitted with feature names",
    category=UserWarning,
)

# Model artifacts may be trained with a different sklearn minor version.
# Keep runtime logs actionable by suppressing this known persistence warning.
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except Exception:
    pass


if TORCH_AVAILABLE:
    class DenseAutoencoder(nn.Module):
        """Configurable dense autoencoder with default 57 -> 32 -> 16 -> 8 bottleneck."""

        def __init__(self, input_dim=57, hidden_dims=(32, 16), bottleneck_dim=8):
            super().__init__()
            self.input_dim = int(input_dim)
            self.hidden_dims = tuple(int(v) for v in hidden_dims)
            self.bottleneck_dim = int(bottleneck_dim)

            encoder_layers = []
            encoder_dims = [self.input_dim, *self.hidden_dims, self.bottleneck_dim]
            for idx in range(len(encoder_dims) - 1):
                encoder_layers.append(nn.Linear(encoder_dims[idx], encoder_dims[idx + 1]))
                if idx < len(encoder_dims) - 2:
                    encoder_layers.append(nn.ReLU())

            decoder_layers = []
            decoder_dims = [self.bottleneck_dim, *reversed(self.hidden_dims), self.input_dim]
            for idx in range(len(decoder_dims) - 1):
                decoder_layers.append(nn.Linear(decoder_dims[idx], decoder_dims[idx + 1]))
                if idx < len(decoder_dims) - 2:
                    decoder_layers.append(nn.ReLU())

            self.encoder = nn.Sequential(*encoder_layers)
            self.decoder = nn.Sequential(*decoder_layers)

        @staticmethod
        def from_state_dict(state_dict):
            """Infer layer dimensions from checkpoint keys when architecture differs."""
            encoder_weight_keys = [
                key for key in state_dict.keys()
                if key.startswith("encoder.") and key.endswith(".weight")
            ]
            if not encoder_weight_keys:
                return DenseAutoencoder()

            encoder_weight_keys = sorted(
                encoder_weight_keys,
                key=lambda key: int(key.split(".")[1])
            )

            first_weight = state_dict[encoder_weight_keys[0]]
            dims = [int(first_weight.shape[1])]
            for key in encoder_weight_keys:
                dims.append(int(state_dict[key].shape[0]))

            if len(dims) < 2:
                return DenseAutoencoder()

            input_dim = dims[0]
            bottleneck_dim = dims[-1]
            hidden_dims = tuple(dims[1:-1])
            return DenseAutoencoder(input_dim=input_dim, hidden_dims=hidden_dims, bottleneck_dim=bottleneck_dim)

        def forward(self, x):
            latent = self.encoder(x)
            return self.decoder(latent)


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
        logger.info("Initializing Tri-Layer ML pipeline...")
        self.rf_model = None
        self.scaler = None
        self.autoencoder = None
        self.autoencoder_enabled = os.environ.get("USE_AUTOENCODER", "1") == "1"
        if self.autoencoder_enabled and not TORCH_AVAILABLE:
            logger.warning("PyTorch is not installed in WSL. Autoencoder layer disabled; running RF-only mode.")
            self.autoencoder_enabled = False
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu") if TORCH_AVAILABLE else None
        self._mse_history = []
        self._calibration_window = 500
        self._ae_dimension_warning_emitted = False
        self._feature_align_warning_emitted = False

        rf_candidates = [
            RF_MODEL_PATH,
            RF_MODEL_PATH.parent / "sentinel_rf.pkl",
            RF_MODEL_PATH.parents[1] / "new" / "rf_model.pkl",
            RF_MODEL_PATH.parents[1] / "new" / "sentinel_rf.pkl",
        ]
        scaler_candidates = [
            SCALER_PATH,
            SCALER_PATH.parent / "sentinel_scaler.pkl",
            SCALER_PATH.parents[1] / "new" / "scaler.pkl",
            SCALER_PATH.parents[1] / "new" / "sentinel_scaler.pkl",
        ]
        ae_candidates = [
            AUTOENCODER_PATH,
            AUTOENCODER_PATH.parent / "sentinel_autoencoder.pth",
            AUTOENCODER_PATH.parents[1] / "new" / "autoencoder.pth",
            AUTOENCODER_PATH.parents[1] / "new" / "sentinel_autoencoder.pth",
        ]

        self.rf_model_path = self._resolve_first_existing_path(rf_candidates)
        self.scaler_path = self._resolve_first_existing_path(scaler_candidates)
        self.autoencoder_path = self._resolve_first_existing_path(ae_candidates)

        try:
            self.rf_model = joblib.load(self.rf_model_path)
            logger.info(f"[OK] Random Forest loaded from {self.rf_model_path}")
        except FileNotFoundError as exc:
            logger.error(f"RF model file not found: {exc}")
            raise SystemExit(1)
        except (OSError, ValueError, TypeError) as exc:
            logger.error(f"Could not load RF model from {self.rf_model_path}: {exc}")
            raise SystemExit(1)

        try:
            self.scaler = joblib.load(self.scaler_path)
            logger.info(f"[OK] Scaler loaded from {self.scaler_path}")
        except FileNotFoundError as exc:
            logger.error(f"Scaler file not found: {exc}")
            raise SystemExit(1)
        except (OSError, ValueError, TypeError) as exc:
            logger.error(f"Could not load scaler from {self.scaler_path}: {exc}")
            raise SystemExit(1)

        if self.autoencoder_enabled:
            try:
                state_dict = torch.load(self.autoencoder_path, map_location=self.device)
                inferred_autoencoder = DenseAutoencoder.from_state_dict(state_dict).to(self.device)
                inferred_autoencoder.load_state_dict(state_dict, strict=True)
                self.autoencoder = inferred_autoencoder
                self.autoencoder.eval()
                logger.info(
                    f"[OK] Autoencoder loaded from {self.autoencoder_path} on {self.device} "
                    f"(input_dim={self.autoencoder.input_dim}, bottleneck={self.autoencoder.bottleneck_dim})"
                )
            except FileNotFoundError as exc:
                logger.warning(f"Autoencoder file not found: {exc}. Autoencoder layer disabled.")
                self.autoencoder_enabled = False
            except (OSError, RuntimeError, ValueError, TypeError) as exc:
                logger.warning(
                    f"Could not load autoencoder from {self.autoencoder_path}: {exc}. "
                    "Using untrained 57-feature fallback architecture."
                )
                self.autoencoder = DenseAutoencoder(input_dim=57, hidden_dims=(32, 16), bottleneck_dim=8).to(self.device)
                self.autoencoder.eval()

        self.autoencoder_threshold = AUTOENCODER_THRESHOLD
        self.autoencoder_threshold_percentile = AUTOENCODER_THRESHOLD_PERCENTILE
        
        try:
            self.features = load_feature_names(FEATURES_PATH)
            logger.info(f"[OK] Loaded {len(self.features)} feature definitions")
        except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError) as exc:
            logger.error(f"Failed to load features: {exc}")
            raise

    @staticmethod
    def _resolve_first_existing_path(path_candidates):
        for candidate in path_candidates:
            if Path(candidate).exists():
                return Path(candidate)
        return Path(path_candidates[0])

    @staticmethod
    def _is_attack_prediction(prediction_value):
        if isinstance(prediction_value, str):
            normalized = prediction_value.strip().lower()
            return normalized in {"attack", "anomaly", "malicious", "dos", "ddos", "intrusion", "1"}

        try:
            return int(prediction_value) == 1
        except (TypeError, ValueError):
            return bool(prediction_value)

    @staticmethod
    def _estimate_rf_confidence(rf_model, scaled_input):
        try:
            proba = rf_model.predict_proba(scaled_input)[0]
            return float(np.max(proba)) * 100.0
        except (AttributeError, IndexError, TypeError, ValueError):
            return 100.0

    def _effective_autoencoder_threshold(self):
        if self.autoencoder_threshold > 0:
            return self.autoencoder_threshold

        if not self._mse_history:
            return float("inf")

        return float(np.percentile(self._mse_history, self.autoencoder_threshold_percentile))

    def _align_to_expected_dim(self, vector_2d, expected_dim, label):
        current_dim = vector_2d.shape[1]
        if current_dim == expected_dim:
            return vector_2d

        if not self._feature_align_warning_emitted:
            logger.warning(
                "Feature dimension mismatch for %s: got %s, expected %s. Applying zero-pad/truncate alignment.",
                label,
                current_dim,
                expected_dim,
            )
            self._feature_align_warning_emitted = True

        if current_dim < expected_dim:
            pad = np.zeros((vector_2d.shape[0], expected_dim - current_dim), dtype=vector_2d.dtype)
            return np.concatenate([vector_2d, pad], axis=1)

        return vector_2d[:, :expected_dim]

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
            features_np = np.asarray(feature_vector, dtype=np.float32).reshape(1, -1)
            expected_dim = len(self.features)
            if features_np.shape[1] != expected_dim:
                raise ValueError(f"Expected {expected_dim} features, got {features_np.shape[1]}")

            scaler_expected = int(getattr(self.scaler, "n_features_in_", features_np.shape[1]))
            aligned_for_scaler = self._align_to_expected_dim(features_np, scaler_expected, "scaler")

            # Layer 1: input normalization for downstream models.
            if hasattr(self.scaler, "feature_names_in_") and len(self.scaler.feature_names_in_) == aligned_for_scaler.shape[1]:
                scaler_input = pd.DataFrame(aligned_for_scaler, columns=list(self.scaler.feature_names_in_))
            else:
                scaler_input = aligned_for_scaler
            scaled_vector = self.scaler.transform(scaler_input)

            rf_expected = int(getattr(self.rf_model, "n_features_in_", scaled_vector.shape[1]))
            scaled_vector = self._align_to_expected_dim(scaled_vector, rf_expected, "random_forest")

            # Layer 2: known attack detection (Random Forest).
            rf_pred = self.rf_model.predict(scaled_vector)[0]
            rf_confidence = self._estimate_rf_confidence(self.rf_model, scaled_vector)
            if self._is_attack_prediction(rf_pred):
                return {
                    "classification": "attack",
                    "raw_prediction": 1,
                    "confidence": round(rf_confidence, 2),
                    "layer": "random_forest",
                    "reconstruction_mse": None,
                }

            if not self.autoencoder_enabled or self.autoencoder is None:
                return {
                    "classification": "normal",
                    "raw_prediction": 0,
                    "confidence": round(max(100.0 - rf_confidence, 50.0), 2),
                    "layer": "random_forest_only",
                    "reconstruction_mse": None,
                    "threshold": None,
                }

            # Layer 3: zero-day anomaly detection (Autoencoder reconstruction error).
            if scaled_vector.shape[1] != self.autoencoder.input_dim:
                if not self._ae_dimension_warning_emitted:
                    logger.warning(
                        "Autoencoder input dimension mismatch: expected %s, got %s. "
                        "Skipping zero-day layer until compatible model is deployed.",
                        self.autoencoder.input_dim,
                        scaled_vector.shape[1],
                    )
                    self._ae_dimension_warning_emitted = True
                return {
                    "classification": "normal",
                    "raw_prediction": 0,
                    "confidence": round(max(100.0 - rf_confidence, 50.0), 2),
                    "layer": "autoencoder_skipped",
                    "reconstruction_mse": None,
                    "threshold": None,
                }

            input_tensor = torch.tensor(scaled_vector, dtype=torch.float32, device=self.device)
            with torch.no_grad():
                reconstructed = self.autoencoder(input_tensor)

            mse = float(torch.mean((reconstructed - input_tensor) ** 2).item())
            active_threshold = self._effective_autoencoder_threshold()
            if mse > active_threshold:
                return {
                    "classification": "zero-day anomaly",
                    "raw_prediction": 2,
                    "confidence": 99.0,
                    "layer": "autoencoder",
                    "reconstruction_mse": round(mse, 8),
                    "threshold": round(active_threshold, 8) if np.isfinite(active_threshold) else "warming_up",
                }

            self._mse_history.append(mse)
            if len(self._mse_history) > self._calibration_window:
                self._mse_history = self._mse_history[-self._calibration_window:]

            return {
                "classification": "normal",
                "raw_prediction": 0,
                "confidence": round(max(100.0 - rf_confidence, 50.0), 2),
                "layer": "autoencoder",
                "reconstruction_mse": round(mse, 8),
                "threshold": round(active_threshold, 8) if np.isfinite(active_threshold) else "warming_up",
            }
        except (ValueError, TypeError, AttributeError, KeyError, IndexError, RuntimeError) as exc:
            logger.error(f"Prediction error: {exc}")
            return {"classification": "error", "error": str(exc)}

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
                        is_malicious = final_classification in {"attack", "zero-day anomaly"}
                        sig = f"{proto} Potential Probe (Port {port})" if is_malicious else f"{proto} Flow"

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
                if final_classification in {"attack", "zero-day anomaly"} and final_confidence >= 95.0:
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
