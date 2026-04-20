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

# --- MODEL PATHS ---
MODELS_DIR = BASE_DIR / "models"
MODEL_PATH = MODELS_DIR / "model.pkl"
FEATURES_PATH = MODELS_DIR / "features.json"

# --- SYSTEM SETTINGS ---
POLL_INTERVAL_SEC = 0.5
HEARTBEAT_INTERVAL_SEC = 10
ALERT_CACHE_SIZE = 100

# --- WEBSOCKET SETTINGS ---
WS_HOST = "0.0.0.0"
WS_PORT = 8765
WS_URI = f"ws://localhost:{WS_PORT}"  # 'localhost' is often safer for WSL2 bridging

def ensure_dirs():
    """Ensure all required directories exist."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
