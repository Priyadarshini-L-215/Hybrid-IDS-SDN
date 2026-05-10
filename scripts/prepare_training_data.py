import pandas as pd
import numpy as np
import json
import os
from pathlib import Path

def prepare_data():
    print("=== Sentinel Core: Data Preparation Pipeline ===")
    
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
    df = pd.read_csv(RAW_FILE)
    df.columns = [c.strip() for c in df.columns]

    # Mapping
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

    # Add missing Protocol (TCP=6)
    if 'Protocol' not in df.columns:
        print("Adding default Protocol (6.0)")
        df['Protocol'] = 6.0

    # Ensure Label is numeric (0=Benign, 1=Attack)
    print("Normalizing labels...")
    df['Label'] = df['Label'].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)

    # Keep only expected features + Label
    print(f"Selecting {len(expected_features)} features...")
    
    # Fill any remaining missing features with 0
    for f in expected_features:
        if f not in df.columns:
            df[f] = 0.0
            
    final_df = df[expected_features + ['Label']]
    
    # Clean data (NaNs and Infs)
    final_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    final_df.fillna(0, inplace=True)

    # Save
    print(f"Saving normalized dataset to {OUTPUT_FILE}")
    final_df.to_csv(OUTPUT_FILE, index=False)
    print(f"[OK] Prepared {len(final_df)} samples.")

if __name__ == "__main__":
    prepare_data()
