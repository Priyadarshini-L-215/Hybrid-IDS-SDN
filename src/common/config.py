import os
from pathlib import Path

# --- BASE DIRECTORY RESOLUTION ---
# This file is at src/common/config.py, so level 2 is project root
BASE_DIR = Path(__file__).resolve().parents[2]

# --- LOG PATHS ---
LOG_DIR = BASE_DIR / "data" / "logs"
import sys
if sys.platform == "linux":
    EVE_LOG = Path("/var/log/suricata/eve.json")
else:
    EVE_LOG = LOG_DIR / "eve.json"
ML_ALERTS_LOG = LOG_DIR / "ml_alerts.json"
HEARTBEAT_LOG = LOG_DIR / "consumer_heartbeat.txt"

# --- DATABASE PATH ---
if sys.platform == "linux":
    # Use native Linux partition to avoid 9p mount latency (D: drive)
    DB_PATH = Path(os.path.expanduser("~/.fyp_ids/alerts.db"))
else:
    # Windows fallback
    DB_PATH = BASE_DIR / "data" / "alerts.db"

# --- MODEL PATHS ---
MODELS_DIR = BASE_DIR / "models"
MODEL_PATH = MODELS_DIR / "model.pkl"
FEATURES_PATH = MODELS_DIR / "features.json"

# --- SYSTEM SETTINGS ---
POLL_INTERVAL_SEC = 0.1
HEARTBEAT_INTERVAL_SEC = 10
ALERT_CACHE_SIZE = 100

# --- WEBSOCKET & DATA SERVICE ---
WS_HOST = "0.0.0.0"
WS_PORT = 8765
DATA_SERVICE_PORT = 5001
WS_URI = f"ws://127.0.0.1:{WS_PORT}"

def ensure_dirs():
    """Ensure all required directories exist."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    # Ensure native Linux DB directory exists
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
