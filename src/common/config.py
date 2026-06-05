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
    global YAML_CONFIG, API_PORT, REDIS_HOST, REDIS_PORT, \
           ML_THRESHOLD_ATTACK, ML_THRESHOLD_SUSPICIOUS, ML_THRESHOLD_ANOMALY, ML_WEIGHT_SIG, ML_WEIGHT_RF, ML_WEIGHT_AE, \
           ANOMALY_PERCENTILE, ANOMALY_MIN_SAMPLES, REPUTATION_LIMIT, REPUTATION_TEMP_BLOCK, REPUTATION_PERM_BLOCK, \
           BLOCK_TTL, RATE_LIMIT_PER_SEC, ACTIVE_MODEL_FILE, ACTIVE_SCALER_FILE, DEV_MODE, \
           ALIENTVAULT_KEY, PCAP_ENABLED, SDN_ENABLED, SDN_CONTROLLER_HOST, SDN_CONTROLLER_PORT, \
           SDN_BRIDGE_NAME, SDN_HONEYPOT_IP, SDN_FALLBACK_TO_IPSET, \
           BATCH_SIZE, BATCH_FLUSH_INTERVAL, REDIS_DB, AUTOENCODER_THRESHOLD, DB_RETENTION_DAYS, \
           EBPF_ENABLED, EBPF_INTERFACE, QUARANTINE_VLAN_ID
    
    YAML_CONFIG = _load_yaml_config()
    
    # Update network settings
    API_PORT = int(get_cfg("network.api_port", 3000))
    REDIS_HOST = os.environ.get("REDIS_HOST", get_cfg("network.redis_host", "127.0.0.1"))
    REDIS_PORT = int(os.environ.get("REDIS_PORT", get_cfg("network.redis_port", 6379)))
    REDIS_DB = int(os.environ.get("REDIS_DB", get_cfg("network.redis_db", 0)))
    
    # Update detection thresholds
    ML_THRESHOLD_ATTACK = get_cfg("detection.decision_engine.thresholds.attack", 0.85)
    ML_THRESHOLD_SUSPICIOUS = get_cfg("detection.decision_engine.thresholds.suspicious", 0.6)
    ML_THRESHOLD_ANOMALY = get_cfg("detection.decision_engine.thresholds.anomaly", 0.5)
    
    # Update weights
    ML_WEIGHT_SIG = get_cfg("detection.decision_engine.weights.signature", 1.0)
    ML_WEIGHT_RF = get_cfg("detection.decision_engine.weights.ml", 0.5)
    ML_WEIGHT_AE = get_cfg("detection.decision_engine.weights.anomaly", 0.3)
    
    # Update anomaly settings
    ANOMALY_PERCENTILE = float(get_cfg("detection.anomaly_percentile", 99.5))
    ANOMALY_MIN_SAMPLES = int(get_cfg("detection.anomaly_min_samples", 50))
    AUTOENCODER_THRESHOLD = float(get_cfg("detection.autoencoder_threshold", 0.0283))
    
    # Update mitigation settings
    REPUTATION_LIMIT = get_cfg("mitigation.reputation_limit", 10.0)
    REPUTATION_TEMP_BLOCK = get_cfg("mitigation.reputation_temp_block", 25.0)
    REPUTATION_PERM_BLOCK = get_cfg("mitigation.reputation_perm_block", 50.0)
    BLOCK_TTL = get_cfg("mitigation.block_ttl", 300)
    RATE_LIMIT_PER_SEC = get_cfg("mitigation.rate_limit_per_sec", 5)
    EBPF_ENABLED = get_cfg("mitigation.ebpf_enabled", False)
    EBPF_INTERFACE = get_cfg("mitigation.ebpf_interface", "eth0")
    QUARANTINE_VLAN_ID = get_cfg("mitigation.quarantine_vlan_id", 99)
    
    ACTIVE_MODEL_FILE = get_cfg("detection.ml.active_model", "rf_pipeline.onnx")
    ACTIVE_SCALER_FILE = get_cfg("detection.ml.active_scaler", "scaler.pkl")
    
    # Dev Mode
    DEV_MODE = get_cfg("system.dev_mode", False)
    
    # Batch processing
    BATCH_SIZE = int(get_cfg("system.batch_size", 20))
    BATCH_FLUSH_INTERVAL = float(get_cfg("system.batch_flush_interval", 0.25))
    
    # CTI Settings
    ALIENTVAULT_KEY = get_cfg("cti.alienvault_key", "")
    
    # Forensics Settings
    PCAP_ENABLED = get_cfg("forensics.pcap_enabled", False)
    
    # SDN Settings
    SDN_ENABLED = get_cfg("sdn.enabled", False)
    SDN_CONTROLLER_HOST = get_cfg("sdn.controller_host", "127.0.0.1")
    SDN_CONTROLLER_PORT = int(get_cfg("sdn.controller_port", 8080))
    SDN_BRIDGE_NAME = get_cfg("sdn.bridge_name", "br-sentinel")
    SDN_HONEYPOT_IP = get_cfg("sdn.honeypot_ip", "10.99.0.2")
    SDN_FALLBACK_TO_IPSET = get_cfg("sdn.fallback_to_ipset", True)
    
    # DB Retention
    DB_RETENTION_DAYS = int(get_cfg("system.db_retention_days", 7))
    
    # Precedence: Env > YAML > Default
    AUTOENCODER_THRESHOLD = float(os.environ.get("AUTOENCODER_THRESHOLD", get_cfg("detection.autoencoder_threshold", 0.0283)))

# Initialize with defaults
API_PORT = 3000
REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
REDIS_DB = 0
ML_THRESHOLD_ATTACK = 0.85
ML_THRESHOLD_SUSPICIOUS = 0.6
ML_THRESHOLD_ANOMALY = 0.5
ML_WEIGHT_SIG = 1.0
ML_WEIGHT_RF = 0.8
ML_WEIGHT_AE = 0.2
ANOMALY_PERCENTILE = 99.5
ANOMALY_MIN_SAMPLES = 50
REPUTATION_LIMIT = 10.0
REPUTATION_TEMP_BLOCK = 25.0
REPUTATION_PERM_BLOCK = 50.0
BLOCK_TTL = 300
RATE_LIMIT_PER_SEC = 5
EBPF_ENABLED = False
EBPF_INTERFACE = "eth0"
QUARANTINE_VLAN_ID = 99
ACTIVE_MODEL_FILE = "rf_model.pkl"
ACTIVE_SCALER_FILE = "scaler.pkl"
DEV_MODE = False
BATCH_SIZE = 20
BATCH_FLUSH_INTERVAL = 0.25
DB_RETENTION_DAYS = 7
SDN_ENABLED = False
SDN_CONTROLLER_HOST = "127.0.0.1"
SDN_CONTROLLER_PORT = 8080
SDN_BRIDGE_NAME = "br-sentinel"
SDN_HONEYPOT_IP = "10.99.0.2"
SDN_FALLBACK_TO_IPSET = True
ALIENTVAULT_KEY = ""
PCAP_ENABLED = False
AUTOENCODER_THRESHOLD = 0.0283

# Load dynamic config
refresh_config()

# --- LOG PATHS ---
LOG_DIR = BASE_DIR / "data" / "logs"
EVE_LOG = Path(os.environ.get("EVE_LOG", str(LOG_DIR / "eve.json")))
SURICATA_SOCKET = Path(os.environ.get("SURICATA_SOCKET", "/tmp/sentinel_suricata.sock"))
ML_ALERTS_LOG = LOG_DIR / "ml_alerts.json"
HEARTBEAT_LOG = LOG_DIR / "consumer_heartbeat.txt"

# --- DATABASE PATH ---
DB_PATH = BASE_DIR / "data" / "alerts_fresh.db"

# --- MODEL PATHS (DYNAMIC) ---
MODELS_DIR = BASE_DIR / "models"
def get_model_path():
    return MODELS_DIR / ACTIVE_MODEL_FILE

def get_scaler_path():
    return MODELS_DIR / ACTIVE_SCALER_FILE

AUTOENCODER_PATH = MODELS_DIR / "vae_encoder.keras"
FEATURES_PATH = MODELS_DIR / "features.json"

# Threshold moved into refresh_config() for better precedence handling

# --- SYSTEM SETTINGS ---
WORKER_COUNT = int(os.environ.get("WORKER_COUNT", get_cfg("system.worker_count", 4)))
POLL_INTERVAL_SEC = 0.1
HEARTBEAT_INTERVAL_SEC = 10
ALERT_CACHE_SIZE = 100
REDIS_QUEUE_NAME = os.environ.get("REDIS_QUEUE_NAME", "sentinel_events_queue")

# --- NETWORK ---
API_HOST = os.environ.get("API_HOST", "0.0.0.0")
REDIS_ALERT_STREAM = os.environ.get("REDIS_ALERT_STREAM", "sentinel_alerts_stream")
WS_PORT = int(os.environ.get("WS_PORT", "8777"))
WS_URI = os.environ.get("WS_URI", f"ws://{API_HOST}:{API_PORT}/ws")

# --- LOGGING ---
_default_log_level = get_cfg("system.log_level", "INFO").upper()
LOG_LEVEL = "DEBUG" if DEV_MODE else os.environ.get("LOG_LEVEL", _default_log_level).upper()

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

def get_protected_ips() -> set:
    """Returns a set of internal/protected IPs to exclude from mitigation."""
    protected = {"127.0.0.1", "0.0.0.0", "::1"}
    # Add common internal ranges
    protected.update(["192.168.1.1", "10.0.0.1"]) 
    # Load from config if available
    extra = get_cfg("mitigation.protected_ips", [])
    if isinstance(extra, list):
        protected.update(extra)
    return protected

# --- LATE BINDING REDUNDANCY REMOVAL ---
# These were already set by refresh_config() called above.
# We only keep unique logic here if any.

def ensure_dirs():
    """Ensure all required directories exist."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    # Ensure DB and PCAP directories exist
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "data" / "pcaps").mkdir(parents=True, exist_ok=True)

# Create directories immediately on import
ensure_dirs()
