import pandas as pd
import numpy as np
import json
import os
from pathlib import Path

def prepare_data():
    print("=== Sentinel Core: Data Preparation Pipeline (v4) ===")
    
    # Paths
    BASE_DIR = Path(__file__).resolve().parents[1]
    DATA_DIR = BASE_DIR / "data"
    MODELS_DIR = BASE_DIR / "models"
    RAW_FILE = DATA_DIR / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    OUTPUT_FILE = DATA_DIR / "dataset.csv"
    FEATURES_PATH = MODELS_DIR / "features.json"

    if not RAW_FILE.exists():
        print(f"Error: Raw file not found at {RAW_FILE}")
        return

    # Load expected features
    print("Loading expected features...")
    with open(FEATURES_PATH, 'r') as f:
        expected_features = json.load(f)

    # Load Data
    print(f"Loading raw data: {RAW_FILE.name}")
    # Raw file has leading spaces in column names
    df = pd.read_csv(RAW_FILE)
    df.columns = [c.strip() for c in df.columns]

    # Mapping CIC-IDS2017 to UNSW-NB15 (Sentinel)
    # Note: This is an approximation as the features are not 1:1
    mapping = {
        'Flow Duration': 'flow_duration',
        'Total Fwd Packets': 'total_fwd_packets',
        'Total Backward Packets': 'total_bwd_packets',
        'Total Length of Fwd Packets': 'total_fwd_bytes',
        'Total Length of Bwd Packets': 'total_bwd_bytes',
        'Flow IAT Mean': 'flow_iat_mean',
        'Flow IAT Std': 'flow_iat_std',
        'Fwd IAT Mean': 'fwd_iat_mean',
        'Bwd IAT Mean': 'bwd_iat_mean',
        'Packet Length Mean': 'pkt_len_mean',
        'Packet Length Std': 'pkt_len_std',
        'Init_Win_bytes_forward': 'swin',
        'Init_Win_bytes_backward': 'dwin',
        'Avg Fwd Segment Size': 'smeansz',
        'Avg Bwd Segment Size': 'dmeansz',
        'act_data_pkt_fwd': 'spkts',
        'min_seg_size_forward': 'ct_state_ttl' # Proxying
    }
    
    # Rename mapped columns
    print("Mapping columns...")
    df.rename(columns=mapping, inplace=True)
    
    # Aliases for duplicated logic in extractor
    df['sbytes'] = df['total_fwd_bytes']
    df['dbytes'] = df['total_bwd_bytes']
    df['spkts'] = df['total_fwd_packets']
    df['dpkts'] = df['total_bwd_packets']
    
    # Fill defaults for missing features
    print("Filling missing features with defaults...")
    for f in expected_features:
        if f not in df.columns:
            if 'ttl' in f:
                df[f] = 64.0
            else:
                df[f] = 0.0

    # Ensure Label is numeric (0=Benign, 1=Attack)
    print("Normalizing labels...")
    df['Label'] = df['Label'].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)

    # Keep only expected features + Label
    print(f"Selecting {len(expected_features)} features...")
    final_df = df[expected_features + ['Label']]
    
    # Clean data (NaNs and Infs)
    final_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    final_df.fillna(0, inplace=True)

    # Convert everything to float32 except Label
    for col in expected_features:
        final_df[col] = final_df[col].astype(np.float32)

    # Save
    print(f"Saving normalized dataset to {OUTPUT_FILE}")
    final_df.to_csv(OUTPUT_FILE, index=False)
    print(f"[OK] Prepared {len(final_df)} samples.")

if __name__ == "__main__":
    prepare_data()
