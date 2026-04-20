"""
Create a simple dummy Random Forest model for testing.
This allows the IDS to run without the full CICIDS dataset.
"""

import pickle
import json
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
import numpy as np

# Paths
BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "model.pkl"
FEATURES_PATH = BASE_DIR / "models" / "features.json"

# Load feature names
with open(FEATURES_PATH, "r", encoding="utf-8") as f:
    features = json.load(f)

print(f"Creating dummy Random Forest model with {len(features)} features...")

# Create a simple Random Forest trained on random data
# This is just for testing - it won't be accurate but will allow the system to run
if __name__ == "__main__":
    X_dummy = np.random.randn(100, len(features))  # 100 samples using the current feature layout
    y_dummy = np.random.randint(0, 2, 100)  # Binary classification

    model = RandomForestClassifier(
        n_estimators=10,  # Small for quick training
        max_depth=5,
        random_state=42,
        n_jobs=1
    )

    print("Training dummy model...")
    model.fit(X_dummy, y_dummy)

    print(f"Saving to {MODEL_PATH}...")
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)

    print("[OK] Dummy model created successfully")
    print(f"  Model type: {type(model).__name__}")
    print(f"  Features: {len(features)}")
    print(f"  Model file: {MODEL_PATH}")
