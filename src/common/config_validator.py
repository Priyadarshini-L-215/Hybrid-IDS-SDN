import os
import sys
import json
from pathlib import Path
from typing import Tuple, List

# Keep validation CPU-only and quiet on hosts without CUDA.
os.environ.setdefault("KERAS_BACKEND", "torch")
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
os.environ.setdefault("TF_ENABLE_ONEDNN_OPTS", "0")

# Add project root to path
BASE_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE_DIR / "src"))

try:
    from common.config import (
        MODELS_DIR, ACTIVE_MODEL_FILE, ACTIVE_SCALER_FILE, 
        REDIS_HOST, REDIS_PORT, SURICATA_SOCKET
    )
    from common.model_manifest import load_model_manifest
except ImportError:
    # Fallback if config can't be imported
    MODELS_DIR = BASE_DIR / "models"
    ACTIVE_MODEL_FILE = "rf_model.pkl"
    ACTIVE_SCALER_FILE = "scaler.pkl"
    REDIS_HOST = "127.0.0.1"
    REDIS_PORT = 6379
    SURICATA_SOCKET = Path("/tmp/sentinel_suricata.sock")

    def load_model_manifest():
        return {}

class ConfigValidator:
    """
    Validates the Sentinel Core environment and configuration.
    """
    def __init__(self):
        self.errors = []
        self.warnings = []

    def validate_all(self) -> Tuple[bool, List[str], List[str]]:
        """Run all validation checks."""
        self.check_model_manifest()
        self.check_model_files()
        self.check_vae_loadability()
        self.check_log_permissions()
        self.check_redis_connectivity()
        self.check_ui_build()
        return len(self.errors) == 0, self.errors, self.warnings

    def check_model_manifest(self):
        """Verify the canonical model manifest exists and matches the active runtime files."""
        manifest = load_model_manifest()
        if not manifest:
            self.warnings.append("models/manifest.json missing or unreadable; model versioning is not centralized")
            return

        active = manifest.get("active", {}) if isinstance(manifest, dict) else {}
        if not isinstance(active, dict):
            self.errors.append("models/manifest.json has an invalid 'active' section")
            return

        rf_model = active.get("rf", {}).get("model")
        rf_scaler = active.get("rf", {}).get("scaler")
        if rf_model and rf_model != ACTIVE_MODEL_FILE:
            self.warnings.append(
                f"Manifest RF model ({rf_model}) does not match active config ({ACTIVE_MODEL_FILE})"
            )
        if rf_scaler and rf_scaler != ACTIVE_SCALER_FILE:
            self.warnings.append(
                f"Manifest scaler ({rf_scaler}) does not match active config ({ACTIVE_SCALER_FILE})"
            )

        feature_count = active.get("feature_schema", {}).get("feature_count")
        if feature_count and feature_count != 49:
            self.warnings.append(f"Manifest feature count is {feature_count}, expected 49 for the current VAE schema")

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

    def check_vae_loadability(self):
        """Verify the VAE detector can deserialize the saved artifacts."""
        encoder_path = MODELS_DIR / "vae_encoder.keras"
        decoder_path = MODELS_DIR / "vae_decoder.keras"
        scaler_path = MODELS_DIR / "vae_scaler.pkl"

        if not (encoder_path.exists() and decoder_path.exists() and scaler_path.exists()):
            return

        try:
            from ml_engine.vae_detector import VaeAnomalyDetector

            detector = VaeAnomalyDetector(
                encoder_path=encoder_path,
                decoder_path=decoder_path,
                scaler_path=scaler_path,
            )

            if not detector.is_ready:
                self.errors.append("VAE detector failed to load saved artifacts")
        except Exception as e:
            self.errors.append(f"VAE detector loadability check failed: {e}")

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
