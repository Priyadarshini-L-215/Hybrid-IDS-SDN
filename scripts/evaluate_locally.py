import os
import json
import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from sklearn.metrics import classification_report, confusion_matrix

def evaluate():
    print("=== Sentinel Core: Local Model Evaluation ===")
    
    # Paths
    MODEL_PATH = 'models/rf_model.pkl'
    SCALER_PATH = 'models/scaler.pkl'
    FEATURES_PATH = 'models/features.json'
    DATA_FILE = 'data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'

    if not os.path.exists(DATA_FILE):
        print(f"Error: Data file not found at {DATA_FILE}")
        return

    # Load Artifacts
    print("Loading model and features...")
    with open(FEATURES_PATH, 'r') as f:
        expected_features = json.load(f)
    
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    
    # Load Data
    print(f"Loading dataset: {DATA_FILE}")
    df = pd.read_csv(DATA_FILE)
    
    # Clean column names
    df.columns = [c.strip() for c in df.columns]
    
    # Mapping for common CIC-IDS2017 naming mismatches
    mapping = {
        'Total Length of Fwd Packets': 'Fwd Packets Length Total',
        'Total Length of Bwd Packets': 'Bwd Packets Length Total',
        'Min Packet Length': 'Packet Length Min',
        'Max Packet Length': 'Packet Length Max',
        'Average Packet Size': 'Avg Packet Size',
        'Init_Win_bytes_forward': 'Init Fwd Win Bytes',
        'Init_Win_bytes_backward': 'Init Bwd Win Bytes',
        'act_data_pkt_fwd': 'Fwd Act Data Packets',
        'min_seg_size_forward': 'Fwd Seg Size Min'
    }
    df.rename(columns=mapping, inplace=True)
    
    # Preprocess
    print("Preprocessing data...")
    df['Label'] = df['Label'].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)
    
    # Check for missing features after rename
    missing = [f for f in expected_features if f not in df.columns]
    if missing:
        print(f"Warning: Missing features after mapping: {missing}")
        for f in missing:
            if f == 'Protocol':
                df[f] = 6.0 # TCP
            else:
                df[f] = 0.0
            
    X_eval = df[expected_features].copy()
    y_true = df['Label']
    
    X_eval.replace([np.inf, -np.inf], np.nan, inplace=True)
    X_eval.fillna(0, inplace=True)
    X_eval_scaled = scaler.transform(X_eval)
    
    # Predict
    print("Running inference...")
    y_pred = model.predict(X_eval_scaled)
    
    # Report
    print("\n" + "="*40)
    print("CLASSIFICATION REPORT")
    print("="*40)
    print(classification_report(y_true, y_pred))
    
    print("\nCONFUSION MATRIX")
    cm = confusion_matrix(y_true, y_pred)
    print(f"  Normal -> Normal: {cm[0,0]:>8}")
    print(f"  Normal -> Attack: {cm[0,1]:>8}")
    print(f"  Attack -> Normal: {cm[1,0]:>8}")
    print(f"  Attack -> Attack: {cm[1,1]:>8}")
    print("="*40)

if __name__ == "__main__":
    evaluate()
