import os
import sys
import json
import zipfile
from pathlib import Path
import numpy as np

# Force Keras backend before imports
os.environ["KERAS_BACKEND"] = "torch"

# Suppress Keras/torch startup verbosity
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

# Add project src directory to system path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

def main():
    print("==================================================")
    print("      SENTINEL CORE: PIPELINE ACCURACY TESTER")
    print("==================================================")
    
    # 1. Dataset Extraction
    zip_path = PROJECT_ROOT / "data" / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.zip"
    csv_path = PROJECT_ROOT / "data" / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    
    if not csv_path.exists():
        if zip_path.exists():
            print(f"[*] Extracting dataset zip: {zip_path.name}...")
            try:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(zip_path.parent)
                print("[+] Extraction successful.")
            except Exception as e:
                print(f"[!] Extraction failed: {e}")
                sys.exit(1)
        else:
            print(f"[!] Error: Dataset zip not found at {zip_path}")
            sys.exit(1)

    # 2. Initialize ML Engine (suppress per-row logging)
    print("[*] Initializing ML Engine...")
    from ml_engine.engine import MLEngine
    engine = MLEngine()
    if not engine.is_ready:
        print("[!] Error: ML Engine failed to initialize.")
        sys.exit(1)
    print("[+] ML Engine ready.")

    # 3. Load and Preprocess Dataset
    print(f"[*] Loading dataset: {csv_path.name}...")
    import pandas as pd
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"[!] Failed to load CSV: {e}")
        sys.exit(1)
    
    print(f"[*] Loaded {len(df):,} samples. Preprocessing...")
    df.columns = [c.strip() for c in df.columns]
    
    # Column mappings from CIC-IDS2017 to UNSW-NB15 feature names
    col_mapping = {
        'Flow Duration':                    'flow_duration',
        'Total Fwd Packets':                'total_fwd_packets',
        'Total Backward Packets':           'total_bwd_packets',
        'Total Length of Fwd Packets':      'total_fwd_bytes',
        'Total Length of Bwd Packets':      'total_bwd_bytes',
        'Flow IAT Mean':                    'flow_iat_mean',
        'Flow IAT Std':                     'flow_iat_std',
        'Fwd IAT Mean':                     'fwd_iat_mean',
        'Bwd IAT Mean':                     'bwd_iat_mean',
        'Packet Length Mean':               'pkt_len_mean',
        'Packet Length Std':                'pkt_len_std',
        # Dual-use
        'Total Fwd Packets':                'spkts',
        'Total Backward Packets':           'dpkts',
        'Total Length of Fwd Packets':      'sbytes',
        'Total Length of Bwd Packets':      'dbytes',
        'Flow Bytes/s':                     'sload',
        'Flow Packets/s':                   'dload',
        'Fwd IAT Mean':                     'sinpkt',
        'Bwd IAT Mean':                     'dinpkt',
        'Init_Win_bytes_forward':           'swin',
        'Init_Win_bytes_backward':          'dwin',
        'Destination Port':                 'app_proto',
    }
    
    df_mapped = pd.DataFrame(index=df.index)
    
    # Explicit field-by-field mapping
    field_map = [
        ('Flow Duration',               'flow_duration'),
        ('Total Fwd Packets',           'total_fwd_packets'),
        ('Total Backward Packets',      'total_bwd_packets'),
        ('Total Length of Fwd Packets', 'total_fwd_bytes'),
        ('Total Length of Bwd Packets', 'total_bwd_bytes'),
        ('Flow IAT Mean',               'flow_iat_mean'),
        ('Flow IAT Std',                'flow_iat_std'),
        ('Fwd IAT Mean',                'fwd_iat_mean'),
        ('Bwd IAT Mean',                'bwd_iat_mean'),
        ('Packet Length Mean',          'pkt_len_mean'),
        ('Packet Length Std',           'pkt_len_std'),
        ('Total Fwd Packets',           'spkts'),
        ('Total Backward Packets',      'dpkts'),
        ('Total Length of Fwd Packets', 'sbytes'),
        ('Total Length of Bwd Packets', 'dbytes'),
        ('Flow Bytes/s',                'sload'),
        ('Flow Packets/s',              'dload'),
        ('Fwd IAT Mean',                'sinpkt'),
        ('Bwd IAT Mean',                'dinpkt'),
        ('Init_Win_bytes_forward',      'swin'),
        ('Init_Win_bytes_backward',     'dwin'),
        ('Destination Port',            'app_proto'),
    ]
    
    for src, dst in field_map:
        if src in df.columns:
            df_mapped[dst] = df[src]
        else:
            df_mapped[dst] = 0.0
    
    # Fill remaining expected features with 0
    for feat in engine.feature_order:
        if feat not in df_mapped.columns:
            df_mapped[feat] = 0.0
    
    # Reorder to match feature_order
    df_mapped = df_mapped[list(engine.feature_order)]
    
    # Map true labels
    y_true = df['Label'].apply(lambda x: 'normal' if str(x).strip().upper() == 'BENIGN' else 'attack').values
    
    # Clean infinities / NaNs
    X = df_mapped.values.astype(np.float64)
    X = np.where(np.isinf(X), np.nan, X)
    X = np.where(np.isnan(X), 0.0, X)
    X = X.astype(np.float32)
    
    # 4. Batch Inference (vectorized, no per-row logging)
    print("[*] Running Random Forest batch inference...")
    X_scaled = engine.scaler.transform(X)
    rf_proba = engine.rf_model.predict_proba(X_scaled)[:, 1]  # P(attack)
    
    # 5. Vectorized VAE Anomaly Scoring
    anomaly_scores = np.zeros(len(X))
    if engine.vae_detector and engine.vae_detector.is_ready:
        print("[*] Running VAE anomaly scoring (batch)...")
        anomaly_scores = engine.vae_detector.score(X)
        print(f"[+] VAE scoring complete.")
    
    # 6. Vectorized Decision (mirror decision_engine weights/thresholds)
    # Weights: ml=0.7, anomaly=0.3
    combined = 0.7 * rf_proba + 0.3 * anomaly_scores
    # Threshold: "attack" >= 0.9, else "suspicious" >= 0.7, else "anomaly" >= 0.6, else "normal"
    attack_mask    = combined >= 0.9
    suspicious_mask = (combined >= 0.7) & ~attack_mask
    anomaly_mask   = (combined >= 0.6) & ~attack_mask & ~suspicious_mask
    normal_mask    = ~attack_mask & ~suspicious_mask & ~anomaly_mask
    
    y_pred = np.where(attack_mask, 'attack',
             np.where(suspicious_mask, 'attack',   # suspicious → attack for binary eval
             np.where(anomaly_mask, 'attack',       # anomaly → attack for binary eval
             'normal')))
    
    # 7. Classification Metrics
    from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
    
    acc = accuracy_score(y_true, y_pred)
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0,
                                   labels=["normal", "attack"])
    
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=["normal", "attack"]).ravel()
    
    report["normal"]["tn"] = int(tn)
    report["normal"]["fp"] = int(fp)
    report["attack"]["fn"] = int(fn)
    report["attack"]["tp"] = int(tp)
    
    # 8. Print Results
    print("\n" + "="*52)
    print("                  EVALUATION SUMMARY")
    print("="*52)
    print(f"  Total Samples : {len(X):>10,}")
    print(f"  Accuracy      : {acc * 100:>9.4f}%")
    print(f"  Model Version : {engine.meta.get('model_version', 'v4.0')}")
    print("-"*52)
    
    for lbl in ["normal", "attack"]:
        s = report.get(lbl, {})
        print(f"  Class {lbl.upper():<7} Precision={s.get('precision',0):.4f}"
              f"  Recall={s.get('recall',0):.4f}  F1={s.get('f1-score',0):.4f}"
              f"  Support={int(s.get('support',0)):,}")
    
    print("\n" + "="*52)
    print("                   CONFUSION MATRIX")
    print("="*52)
    print(f"  {'':30} {'Pred Normal':>12}  {'Pred Attack':>12}")
    print(f"  {'Actual Normal':<30} {tn:>12,}  {fp:>12,}")
    print(f"  {'Actual Attack':<30} {fn:>12,}  {tp:>12,}")
    print("="*52)
    
    # 9. Save to eval_results.json for UI
    results = {
        "success": True,
        "metrics": report,
        "summary": {
            "total_samples": len(X),
            "accuracy": float(acc),
            "model_version": engine.meta.get("model_version", "v4.0"),
            "dataset": csv_path.name,
        }
    }
    
    eval_json_path = PROJECT_ROOT / "data" / "eval_results.json"
    with open(eval_json_path, "w") as f:
        json.dump(results, f, indent=4)
    
    print(f"\n[+] Full metrics saved to data/eval_results.json")
    print("[+] Dashboard UI will now display these updated metrics.")
    print("="*52)

if __name__ == "__main__":
    main()
