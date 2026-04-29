import os
from pathlib import Path
import sys
import logging
import json
import yaml
from logging.handlers import RotatingFileHandler

# --- BASE DIRECTORY RESOLUTION ---
# This file is at src/common/config.py, so level 2 is project root
BASE_DIR = Path(__file__).resolve().parents[2]

# --- YAML CONFIG LOADING ---
CONFIG_PATH = BASE_DIR / "config" / "sentinel_config.yaml"

def _load_yaml_config():
    if not CONFIG_PATH.exists():
        return {}
    try:
        with open(CONFIG_PATH, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"Warning: Failed to load config from {CONFIG_PATH}: {e}")
        return {}

YAML_CONFIG = {}

def get_cfg(path, default=None):
    """Deep lookup in YAML config (e.g. 'detection.weights.ml')"""
    parts = path.split(".")
    val = YAML_CONFIG
    for p in parts:
        if isinstance(val, dict) and p in val:
            val = val[p]
        else:
            return default
    return val

def refresh_config():
    """Reloads the YAML config from disk and updates global state."""
    global YAML_CONFIG, API_PORT, UI_PORT, REDIS_HOST, REDIS_PORT, ML_THRESHOLD_ATTACK, ML_THRESHOLD_SUSPICIOUS, ML_WEIGHT_SIG, ML_WEIGHT_RF, ML_WEIGHT_AE, ANOMALY_PERCENTILE, ANOMALY_MIN_SAMPLES, REPUTATION_LIMIT, REPUTATION_TEMP_BLOCK, REPUTATION_PERM_BLOCK, BLOCK_TTL, RATE_LIMIT_PER_SEC
    
    YAML_CONFIG = _load_yaml_config()
    
    # Update network settings
    API_PORT = int(get_cfg("network.api_port", 5000))
    UI_PORT = int(get_cfg("network.ui_port", 3000))
    REDIS_HOST = os.environ.get("REDIS_HOST", get_cfg("network.redis_host", "127.0.0.1"))
    REDIS_PORT = int(os.environ.get("REDIS_PORT", get_cfg("network.redis_port", 6379)))
    
    # Update detection thresholds
    ML_THRESHOLD_ATTACK = get_cfg("detection.decision_engine.thresholds.attack", 0.85)
    ML_THRESHOLD_SUSPICIOUS = get_cfg("detection.decision_engine.thresholds.suspicious", 0.6)
    
    # Update weights
    ML_WEIGHT_SIG = get_cfg("detection.decision_engine.weights.signature", 1.0)
    ML_WEIGHT_RF = get_cfg("detection.decision_engine.weights.ml", 0.5)
    ML_WEIGHT_AE = get_cfg("detection.decision_engine.weights.anomaly", 0.3)
    
    # Update anomaly settings
    ANOMALY_PERCENTILE = float(get_cfg("detection.anomaly_percentile", 99.5))
    ANOMALY_MIN_SAMPLES = int(get_cfg("detection.anomaly_min_samples", 50))
    
    # Update mitigation settings
    REPUTATION_LIMIT = get_cfg("mitigation.reputation_limit", 10.0)
    REPUTATION_TEMP_BLOCK = get_cfg("mitigation.reputation_temp_block", 25.0)
    REPUTATION_PERM_BLOCK = get_cfg("mitigation.reputation_perm_block", 50.0)
    BLOCK_TTL = get_cfg("mitigation.block_ttl", 300)
    RATE_LIMIT_PER_SEC = get_cfg("mitigation.rate_limit_per_sec", 5)
    
    # print(f"Config refreshed from {CONFIG_PATH}")

# Initialize with defaults before first refresh
API_PORT = 5000
UI_PORT = 3000
REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
ML_THRESHOLD_ATTACK = 0.85
ML_THRESHOLD_SUSPICIOUS = 0.6
ML_WEIGHT_SIG = 1.0
ML_WEIGHT_RF = 0.5
ML_WEIGHT_AE = 0.3
ANOMALY_PERCENTILE = 99.5
ANOMALY_MIN_SAMPLES = 50
REPUTATION_LIMIT = 10.0
REPUTATION_TEMP_BLOCK = 25.0
REPUTATION_PERM_BLOCK = 50.0
BLOCK_TTL = 300
RATE_LIMIT_PER_SEC = 5

refresh_config()

# --- LOG PATHS ---
LOG_DIR = BASE_DIR / "data" / "logs"
EVE_LOG = Path(os.environ.get("EVE_LOG", str(LOG_DIR / "eve.json")))
SURICATA_SOCKET = Path(os.environ.get("SURICATA_SOCKET", "/tmp/sentinel_suricata.sock"))
ML_ALERTS_LOG = LOG_DIR / "ml_alerts.json"
HEARTBEAT_LOG = LOG_DIR / "consumer_heartbeat.txt"

# --- DATABASE PATH ---
DB_PATH = BASE_DIR / "data" / "alerts_fresh.db"

# --- MODEL PATHS ---
MODELS_DIR = BASE_DIR / "models"
RF_MODEL_PATH = MODELS_DIR / "rf_model.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"
AUTOENCODER_PATH = MODELS_DIR / "autoencoder.pth"
FEATURES_PATH = MODELS_DIR / "features.json"

# Autoencoder anomaly threshold. If AUTOENCODER_THRESHOLD is not set,
# a percentile value (default 95th) can be used by calibration logic.
AUTOENCODER_THRESHOLD = float(os.environ.get("AUTOENCODER_THRESHOLD", "0.0"))
AUTOENCODER_THRESHOLD_PERCENTILE = float(os.environ.get("AUTOENCODER_THRESHOLD_PERCENTILE", "95.0"))

# --- SYSTEM SETTINGS ---
POLL_INTERVAL_SEC = 0.1
HEARTBEAT_INTERVAL_SEC = 10
ALERT_CACHE_SIZE = 100

# --- NETWORK ---
API_HOST = os.environ.get("API_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("API_PORT", get_cfg("network.api_port", 5000)))
UI_PORT = int(os.environ.get("UI_PORT", get_cfg("network.ui_port", 3000)))
WS_URI = os.environ.get("WS_URI", f"ws://127.0.0.1:{API_PORT}/ws")

# --- LOGGING ---
LOG_LEVEL = os.environ.get("LOG_LEVEL", get_cfg("system.log_level", "INFO")).upper()

class JsonFormatter(logging.Formatter):
    """Structured JSON log formatter."""
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "file": record.filename,
            "line": record.lineno
        }
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record)

# Add src to path for internal imports
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.logging_setup import setup_logging
# We'll call this in each entrypoint (main.py, ingestion.py etc) 
# instead of globally on import to allow component-specific naming.

# --- REDIS QUEUE & CACHING ---
REDIS_HOST = os.environ.get("REDIS_HOST", get_cfg("network.redis_host", "127.0.0.1"))
REDIS_PORT = int(os.environ.get("REDIS_PORT", get_cfg("network.redis_port", 6379)))
REDIS_DB = int(os.environ.get("REDIS_DB", "0"))
REDIS_QUEUE_NAME = "sentinel_alerts_queue"
REDIS_ALERT_STREAM = "sentinel_alerts_stream"
USE_REDIS_QUEUE = os.environ.get("USE_REDIS_QUEUE", "1") == "1"

# --- WORKER POOL & BATCHING ---
BATCH_SIZE = int(get_cfg("system.batch_size", 10))
BATCH_FLUSH_INTERVAL = float(get_cfg("system.batch_flush_interval", 0.25))
WATCHER_FLUSH_TIMEOUT = 0.2
WORKER_COUNT = int(os.environ.get("WORKER_COUNT", get_cfg("system.worker_count", 4)))

# --- MITIGATION PROTECTED IPS ---
def get_protected_ips():
    """Get list of IPs that should never be blocked."""
    protected = {"127.0.0.1", "::1", "0.0.0.0"}
    try:
        from common.net_utils import get_local_ip, get_gateway_ip
        lip = get_local_ip()
        gip = get_gateway_ip()
        if lip: protected.add(lip)
        if gip: protected.add(gip)
    except Exception:
        pass
    protected.update(["172.17.0.1", "172.18.0.1", "172.19.0.1", "172.20.0.1", "192.168.0.1"])
    return protected

# --- DETECTION THRESHOLDS ---
DETECTION_PORT_SCAN_THRESHOLD = get_cfg("detection.port_scan_threshold", 25)
DETECTION_DOS_THRESHOLD = get_cfg("detection.dos_threshold", 100)
DETECTION_WINDOW = get_cfg("detection.correlation_window", 10.0)

# --- ML DECISION ENGINE ---
ML_THRESHOLD_ATTACK = get_cfg("detection.decision_engine.thresholds.attack", 0.85)
ML_THRESHOLD_SUSPICIOUS = get_cfg("detection.decision_engine.thresholds.suspicious", 0.6)
ML_WEIGHT_SIG = get_cfg("detection.decision_engine.weights.signature", 1.0)
ML_WEIGHT_RF = get_cfg("detection.decision_engine.weights.ml", 0.5)
ML_WEIGHT_AE = get_cfg("detection.decision_engine.weights.anomaly", 0.3)
ANOMALY_PERCENTILE = float(get_cfg("detection.anomaly_percentile", 99.5))
ANOMALY_MIN_SAMPLES = int(get_cfg("detection.anomaly_min_samples", 50))

# --- MITIGATION SETTINGS ---
REPUTATION_LIMIT = get_cfg("mitigation.reputation_limit", 10.0)
REPUTATION_TEMP_BLOCK = get_cfg("mitigation.reputation_temp_block", 25.0)
REPUTATION_PERM_BLOCK = get_cfg("mitigation.reputation_perm_block", 50.0)
BLOCK_TTL = get_cfg("mitigation.block_ttl", 300)
RATE_LIMIT_PER_SEC = get_cfg("mitigation.rate_limit_per_sec", 5)

def ensure_dirs():
    """Ensure all required directories exist."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    # Ensure DB directory exists
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
