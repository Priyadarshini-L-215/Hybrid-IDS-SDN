import os
from pathlib import Path
import sys
import logging
from logging.handlers import RotatingFileHandler

# --- BASE DIRECTORY RESOLUTION ---
# This file is at src/common/config.py, so level 2 is project root
BASE_DIR = Path(__file__).resolve().parents[2]

# --- LOG PATHS ---
LOG_DIR = BASE_DIR / "data" / "logs"
EVE_LOG = Path("/var/log/suricata/eve.json")
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

# --- WEBSOCKET ---
WS_HOST = os.environ.get("WS_HOST", "0.0.0.0")
WS_PORT = int(os.environ.get("WS_PORT", "8777"))
WS_URI = os.environ.get("WS_URI", f"ws://127.0.0.1:{WS_PORT}")

# --- LOGGING ---
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

def setup_logging():
    """Configure centralized logging for file and console."""
    root_logger = logging.getLogger()
    # Clear existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        
    root_logger.setLevel(getattr(logging, LOG_LEVEL))

    # 1. Error File Handler (Rotating)
    error_log_path = LOG_DIR / "errors.log"
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        error_log_path, 
        maxBytes=10*1024*1024, # 10MB
        backupCount=3
    )
    file_handler.setLevel(logging.ERROR)
    file_formatter = logging.Formatter(
        '[%(asctime)s] %(name)s [%(levelname)s] (%(filename)s:%(lineno)d): %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

    # 2. Console Handler (for redirection to consumer.log/relay.log)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, LOG_LEVEL))
    console_formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] %(name)s: %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

# Initialize logging immediately on import
setup_logging()

# --- REDIS QUEUE & CACHING ---
REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_DB = int(os.environ.get("REDIS_DB", "0"))
REDIS_QUEUE_NAME = "sentinel_alerts_queue"
REDIS_ALERT_STREAM = "sentinel_alerts_stream"
USE_REDIS_QUEUE = os.environ.get("USE_REDIS_QUEUE", "1") == "1"

# --- WORKER POOL & BATCHING ---
BATCH_SIZE = 5  # events to batch before processing
BATCH_FLUSH_INTERVAL = 0.25  # seconds
WATCHER_FLUSH_TIMEOUT = 0.2  # seconds
WORKER_COUNT = int(os.environ.get("WORKER_COUNT", "4"))  # parallel workers

def ensure_dirs():
    """Ensure all required directories exist."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    # Ensure DB directory exists
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
