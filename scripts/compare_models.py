import joblib
import pandas as pd
import numpy as np
import json
import time
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import warnings

# Suppress version warnings
warnings.filterwarnings('ignore', category=UserWarning)

# Configuration
DATASET_PATH = Path("data/dataset.csv")
OLD_MODEL_PATH = Path("models/rf_model.pkl")
OLD_SCALER_PATH = Path("models/scaler.pkl")
OLD_FEATURES_PATH = Path("models/features.json")

NEW_MODEL_PATH = Path("new model/model.pkl")
NEW_SCALER_PATH = Path("new model/scaler.pkl")
NEW_FEATURES_PATH = Path("new model/feature_names.json")

# Mapping from new model short names to dataset column names
FEATURE_MAP = {
    'flow_dur': 'Flow Duration',
    'fwd_pkts': 'Total Fwd Packets',
    'bwd_pkts': 'Total Backward Packets',
    'fwd_bytes': 'Fwd Packets Length Total',
    'bwd_bytes': 'Bwd Packets Length Total',
    'fwd_len_max': 'Fwd Packet Length Max',
    'bwd_len_max': 'Bwd Packet Length Max',
    'fwd_len_mean': 'Fwd Packet Length Mean',
    'bwd_len_mean': 'Bwd Packet Length Mean',
    'fwd_len_std': 'Fwd Packet Length Std',
    'bwd_len_std': 'Bwd Packet Length Std',
    'pkts_per_sec': 'Flow Packets/s',
    'ack_flag': 'ACK Flag Count',
    'psh_flag': 'PSH Flag Count',
    'header_fwd': 'Fwd Header Length',
    'header_bwd': 'Bwd Header Length',
}

def evaluate(y_true, y_pred, y_prob, name, latency):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)
    fpr = cm[0, 1] / (cm[0, 0] + cm[0, 1]) if (cm[0, 0] + cm[0, 1]) > 0 else 0
    
    return {
        "Model": name,
        "Accuracy": f"{acc:.4f}",
        "Precision": f"{prec:.4f}",
        "Recall": f"{rec:.4f}",
        "F1-Score": f"{f1:.4f}",
        "FPR": f"{fpr:.4f}",
        "Latency (ms/sample)": f"{latency:.4f}"
    }

def main():
    print("=" * 80)
    print("SENTINEL IDS MODEL COMPARISON BENCHMARK (v3.1 vs v4.0.0)")
    print("=" * 80)

    if not DATASET_PATH.exists():
        print(f"Error: Dataset not found at {DATASET_PATH}")
        return

    # 1. Load Data
    print(f"Loading dataset: {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH)
    # Clean column names
    df.columns = [c.strip() for c in df.columns]
    
    # Pre-process labels: 0 for normal, 1 for attack
    normal_labels = {"BENIGN", "NORMAL", "0", 0}
    y_true = df['Label'].apply(lambda x: 0 if x in normal_labels else 1).values
    
    print(f"Dataset loaded: {len(df):,} samples.")
    print("-" * 40)

    # 2. Run Old Model (v3.1)
    print("Running v3.1 Model (77 features)...")
    try:
        old_model = joblib.load(OLD_MODEL_PATH)
        old_scaler = joblib.load(OLD_SCALER_PATH)
        with open(OLD_FEATURES_PATH, 'r') as f:
            old_features = json.load(f)
            
        X_old = df[old_features].values.astype(np.float32)
        
        start = time.time()
        X_old_scaled = old_scaler.transform(X_old)
        old_probs = old_model.predict_proba(X_old_scaled)[:, 1]
        old_latency = (time.time() - start) * 1000 / len(df)
        
        # v3.1 uses threshold 0.85
        old_preds = (old_probs > 0.85).astype(int)
        old_res = evaluate(y_true, old_preds, old_probs, "v3.1 (RF+AE)", old_latency)
    except Exception as e:
        print(f"v3.1 Failure: {e}")
        old_res = {"Model": "v3.1", "Status": "FAILED"}

    # 3. Run New Model (v4.0.0)
    print("Running v4.0.0 Model (16 manifold features)...")
    try:
        new_model = joblib.load(NEW_MODEL_PATH)
        new_scaler = joblib.load(NEW_SCALER_PATH)
        with open(NEW_FEATURES_PATH, 'r') as f:
            new_feature_shorts = json.load(f)
            
        new_feature_cols = [FEATURE_MAP[f] for f in new_feature_shorts]
        X_new = df[new_feature_cols].values.astype(np.float32)
        
        start = time.time()
        X_new_scaled = new_scaler.transform(X_new)
        new_probs = new_model.predict_proba(X_new_scaled)[:, 1]
        new_latency = (time.time() - start) * 1000 / len(df)
        
        # v4.0.0 uses default threshold 0.153
        new_preds = (new_probs > 0.153).astype(int)
        new_res = evaluate(y_true, new_preds, new_probs, "v4.0.0 (Calibrated RF)", new_latency)
    except Exception as e:
        print(f"v4.0.0 Failure: {e}")
        new_res = {"Model": "v4.0.0", "Status": "FAILED"}

    # 4. Show Comparison
    print("\n" + "=" * 80)
    print(f"{'Metric':<25} | {'v3.1 (Old)':<25} | {'v4.0.0 (New)':<25}")
    print("-" * 80)
    for metric in ["Accuracy", "Precision", "Recall", "F1-Score", "FPR", "Latency (ms/sample)"]:
        print(f"{metric:<25} | {old_res.get(metric, 'N/A'):<25} | {new_res.get(metric, 'N/A'):<25}")
    print("=" * 80)
    
    # Save results
    results = {"v3.1": old_res, "v4.0.0": new_res}
    with open("data/model_comparison.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to data/model_comparison.json")

if __name__ == "__main__":
    main()
