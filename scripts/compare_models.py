import joblib
import pandas as pd
from pathlib import Path
from sklearn.metrics import accuracy_score
import json
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Paths
BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data" / "UNSW-NB15_c"
MODELS_DIR = BASE_DIR / "models"
NEW_MODEL_DIR = BASE_DIR / "new model"

def preprocess_for_model(df, feature_order, scaler, le_proto=None):
    df_proc = df.copy()
    
    # Strip spaces from object columns
    for col in df_proc.select_dtypes(include=['object']).columns:
        df_proc[col] = df_proc[col].astype(str).str.strip()

    # Handle hex ports
    for col in ['sport', 'dsport']:
        if col in df_proc.columns:
            df_proc[col] = df_proc[col].apply(lambda x: int(str(x), 16) if str(x).startswith('0x') else x)
            df_proc[col] = pd.to_numeric(df_proc[col], errors='coerce').fillna(0).astype(int)

    # Standard mapping
    mapping = {
        'dur': 'flow_duration',
        'spkts': 'spkts', 'Spkts': 'spkts',
        'dpkts': 'dpkts', 'Dpkts': 'dpkts',
        'sbytes': 'sbytes', 'Sbytes': 'sbytes',
        'dbytes': 'dbytes', 'Dbytes': 'dbytes',
        'sttl': 'sttl', 'dttl': 'dttl',
        'Sload': 'sload', 'Dload': 'dload',
        'sloss': 'sloss', 'dloss': 'dloss',
        'swin': 'swin', 'dwin': 'dwin',
        'stcpb': 'stcpb', 'dtcpb': 'dtcpb',
        'smeansz': 'smeansz', 'dmeansz': 'dmeansz'
    }
    df_proc = df_proc.rename(columns=mapping)
    
    # Fill NAs
    df_proc = df_proc.replace(' ', 0).replace('', 0)
    df_proc = df_proc.fillna(0)
    
    # Add dummy columns for features not in raw UNSW but expected by model
    for feat in feature_order:
        if feat not in df_proc.columns:
            df_proc[feat] = 0
            
    # Apply proto encoding if provided
    if le_proto and 'proto' in df_proc.columns:
        try:
            df_proc['proto'] = le_proto.transform(df_proc['proto'].astype(str))
        except:
            df_proc['proto'] = 0

    # Ensure all features are numeric
    X = df_proc[feature_order].apply(pd.to_numeric, errors='coerce').fillna(0)
    X_scaled = scaler.transform(X)
    return X_scaled

def compare():
    print("=== Model Comparison Evaluation ===")
    
    # Load Test Data
    column_names = [
        'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 
        'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb', 
        'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 
        'Dintpkt', 'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 
        'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 
        'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'label'
    ]
    print(f"Loading test dataset (UNSW-NB15_4.csv)...")
    df_test = pd.read_csv(DATA_DIR / "UNSW-NB15_4.csv", names=column_names, header=None, low_memory=False)
    y_test = df_test['label']

    # 1. Evaluate Current Multi-Dataset Model
    print("\n[1/2] Evaluating Current Multi-Dataset Model (17 features)...")
    rf_multi = joblib.load(MODELS_DIR / "rf_multi_model.pkl")
    scaler_multi = joblib.load(MODELS_DIR / "scaler_multi.pkl")
    with open(MODELS_DIR / "feature_order_multi.json", "r") as f:
        features_multi = json.load(f)["feature_order"]
    
    X_multi = preprocess_for_model(df_test, features_multi, scaler_multi)
    y_pred_multi = rf_multi.predict(X_multi)
    acc_multi = accuracy_score(y_test, y_pred_multi)
    print(f"Accuracy: {acc_multi*100:.2f}%")

    # 2. Evaluate 'new model'
    print("\n[2/2] Evaluating 'new model' (49 features)...")
    rf_new = joblib.load(NEW_MODEL_DIR / "rf_model.pkl")
    scaler_new = joblib.load(NEW_MODEL_DIR / "scaler.pkl")
    features_new = joblib.load(NEW_MODEL_DIR / "feature_order.pkl")
    le_proto_new = joblib.load(NEW_MODEL_DIR / "le_proto.pkl")
    
    X_new = preprocess_for_model(df_test, features_new, scaler_new, le_proto_new)
    y_pred_new = rf_new.predict(X_new)
    acc_new = accuracy_score(y_test, y_pred_new)
    print(f"Accuracy: {acc_new*100:.2f}%")

    print("\n" + "="*40)
    print("FINAL COMPARISON RESULTS")
    print(f"Current Multi-Dataset Model: {acc_multi*100:.2f}%")
    print(f"New Model (49 Features):    {acc_new*100:.2f}%")
    print("="*40)
    
    if acc_multi > acc_new:
        print("WINNER: Current Multi-Dataset Model")
    else:
        print("WINNER: New Model (49 Features)")

if __name__ == "__main__":
    compare()
