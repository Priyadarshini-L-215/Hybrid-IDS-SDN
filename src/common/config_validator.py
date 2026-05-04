import os
import sys
import json
from pathlib import Path
from typing import Tuple, List

# Add project root to path
BASE_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE_DIR / "src"))

try:
    from common.config import (
        MODELS_DIR, ACTIVE_MODEL_FILE, ACTIVE_SCALER_FILE, 
        REDIS_HOST, REDIS_PORT, SURICATA_SOCKET
    )
except ImportError:
    # Fallback if config can't be imported
    MODELS_DIR = BASE_DIR / "models"
    ACTIVE_MODEL_FILE = "rf_model.pkl"
    ACTIVE_SCALER_FILE = "scaler.pkl"
    REDIS_HOST = "127.0.0.1"
    REDIS_PORT = 6379
    SURICATA_SOCKET = Path("/tmp/sentinel_suricata.sock")

class ConfigValidator:
    """
    Validates the Sentinel Core environment and configuration.
    """
    def __init__(self):
        self.errors = []
        self.warnings = []

    def validate_all(self) -> Tuple[bool, List[str], List[str]]:
        """Run all validation checks."""
        self.check_model_files()
        self.check_log_permissions()
        self.check_redis_connectivity()
        self.check_ui_build()
        return len(self.errors) == 0, self.errors, self.warnings

    def check_model_files(self):
        """Verify essential model files exist."""
        required_models = [
            ACTIVE_MODEL_FILE,
            ACTIVE_SCALER_FILE,
            "vae_encoder.keras",
            "vae_decoder.keras",
            "vae_scaler.pkl",
            "features.json"
        ]
        
        for model in required_models:
            path = MODELS_DIR / model
            if not path.exists():
                if "vae" in model:
                    self.warnings.append(f"Optional model file missing: {model} (Anomaly detection will be disabled)")
                else:
                    self.errors.append(f"Critical model file missing: {model}")

    def check_log_permissions(self):
        """Verify logs directory is writable."""
        logs_dir = BASE_DIR / "data" / "logs"
        if not logs_dir.exists():
            try:
                logs_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                self.errors.append(f"Cannot create logs directory: {logs_dir} ({e})")
                return

        if not os.access(logs_dir, os.W_OK):
            self.errors.append(f"Logs directory not writable: {logs_dir}")

    def check_redis_connectivity(self):
        """Verify Redis is reachable."""
        try:
            import redis
            r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, socket_connect_timeout=2)
            r.ping()
        except ImportError:
            self.warnings.append("Python 'redis' package not installed. Cannot verify Redis connectivity.")
        except Exception as e:
            self.errors.append(f"Redis connectivity failed: {REDIS_HOST}:{REDIS_PORT} ({e})")

    def check_ui_build(self):
        """Verify UI is built (dist folder exists)."""
        ui_dist = BASE_DIR / "ui" / "dist"
        if not ui_dist.exists():
            self.warnings.append("UI dist directory missing. Dashboard may not serve correctly until built.")

if __name__ == "__main__":
    validator = ConfigValidator()
    success, errors, warnings = validator.validate_all()
    
    if warnings:
        for w in warnings:
            print(f"WARN: {w}")
            
    if not success:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    
    print("SUCCESS: Configuration validation passed.")
    sys.exit(0)
