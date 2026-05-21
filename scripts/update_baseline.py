"""
update_baseline.py
==================
Recalibrates the VAE anomaly threshold using confirmed-normal traffic
features exported by capture_local_normal.py.

Workflow:
  1. Load data/local_normal.csv (49-feature vectors with label=0).
  2. Instantiate VaeAnomalyDetector from the current model artifacts.
  3. Compute raw MSE reconstruction errors on the normal samples.
  4. Set the new threshold = 99th-percentile MSE × 1.10  (10% safety buffer).
  5. Persist the result to models/vae_config.json so the ML Engine picks it up
     on the next restart / hot-reload.
"""

import sys
import json
import numpy as np
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR / "src"))

MODELS_DIR = BASE_DIR / "models"
DATA_DIR = BASE_DIR / "data"
CSV_PATH = DATA_DIR / "local_normal.csv"
VAE_CONFIG_PATH = MODELS_DIR / "vae_config.json"


def main():
    print("=" * 70)
    print("  Sentinel Core — VAE Baseline Threshold Calibration")
    print("=" * 70)

    # ---- 1. Load normal features ----
    if not CSV_PATH.exists():
        print(f"[ERROR] Normal feature CSV not found: {CSV_PATH}")
        print("        Run 'python3 scripts/capture_local_normal.py' first.")
        sys.exit(1)

    df = pd.read_csv(CSV_PATH)
    print(f"[INFO] Loaded {len(df)} samples from {CSV_PATH.name}")

    # Drop the label column if present
    if "label" in df.columns:
        df = df.drop(columns=["label"])

    if len(df) < 10:
        print("[ERROR] Too few samples for reliable threshold calibration (need >= 10).")
        sys.exit(1)

    # Load the feature order used by the ML pipeline
    features_path = MODELS_DIR / "features.json"
    with open(features_path) as f:
        feature_order = json.load(f)

    # Align columns to the expected feature order, filling missing with 0
    for col in feature_order:
        if col not in df.columns:
            df[col] = 0.0
    X_raw = df[feature_order].values.astype(np.float32)
    print(f"[INFO] Feature matrix shape: {X_raw.shape}")

    # Pre-scale using the pipeline StandardScaler (models/scaler.pkl).
    # The VAE's MinMaxScaler was fitted on data that had already been
    # normalized by the pipeline scaler during VAE training, so we must
    # replicate that same normalization chain here for correct MSE values.
    import joblib
    pipeline_scaler_path = MODELS_DIR / "scaler.pkl"
    if not pipeline_scaler_path.exists():
        print(f"[ERROR] Pipeline scaler not found: {pipeline_scaler_path}")
        sys.exit(1)
    pipeline_scaler = joblib.load(pipeline_scaler_path)
    X = pipeline_scaler.transform(X_raw).astype(np.float32)
    print(f"[INFO] Applied pipeline scaler — scaled range: [{X.min():.4f}, {X.max():.4f}]")

    # ---- 2. Load VAE detector ----
    from ml_engine.vae_detector import VaeAnomalyDetector

    encoder_path = MODELS_DIR / "vae_encoder.keras"
    decoder_path = MODELS_DIR / "vae_decoder.keras"
    scaler_path = MODELS_DIR / "vae_scaler.pkl"

    for p in (encoder_path, decoder_path, scaler_path):
        if not p.exists():
            print(f"[ERROR] Missing model artifact: {p}")
            sys.exit(1)

    detector = VaeAnomalyDetector(
        encoder_path=encoder_path,
        decoder_path=decoder_path,
        scaler_path=scaler_path,
        threshold=0.3,          # placeholder — we are about to recalculate
        feature_order=feature_order,
    )

    if not detector.is_ready:
        print("[ERROR] VAE detector failed to initialise. Check Keras/ONNX installation.")
        sys.exit(1)

    print("[INFO] VAE detector loaded successfully.")

    # ---- 3. Compute reconstruction errors ----
    mse = detector.raw_mse(X)
    print(f"[INFO] MSE stats — min: {mse.min():.6f}  mean: {mse.mean():.6f}  "
          f"max: {mse.max():.6f}  std: {np.std(mse):.6f}")

    # ---- 4. Calibrate threshold ----
    p99 = float(np.percentile(mse, 99))
    new_threshold = round(p99 * 1.1, 12)   # 10 % safety buffer

    # Read old threshold for comparison
    old_threshold = None
    if VAE_CONFIG_PATH.exists():
        try:
            with open(VAE_CONFIG_PATH) as f:
                old_cfg = json.load(f)
            old_threshold = old_cfg.get("threshold")
        except Exception:
            pass

    print()
    print("-" * 50)
    print(f"  Old threshold : {old_threshold}")
    print(f"  99th %-ile MSE: {p99:.12f}")
    print(f"  New threshold : {new_threshold:.12f}  (99th × 1.10)")
    print("-" * 50)

    # ---- 5. Persist to vae_config.json ----
    config = {"threshold": new_threshold, "input_dim": 22}
    with open(VAE_CONFIG_PATH, "w") as f:
        json.dump(config, f)

    print(f"\n[OK] Saved new threshold to {VAE_CONFIG_PATH}")
    print("[OK] The ML Engine will use this threshold on next startup / hot-reload.")
    print("=" * 70)


if __name__ == "__main__":
    main()
