import joblib
import pandas as pd
from pathlib import Path
from sklearn.metrics import classification_report, accuracy_score
import json

# Paths
BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data" / "UNSW-NB15_c"
MODELS_DIR = BASE_DIR / "models"

def evaluate():
    print("Loading model, scaler, and encoders...")
    model = joblib.load(MODELS_DIR / "rf_model.pkl")
    scaler = joblib.load(MODELS_DIR / "scaler.pkl")
    le_proto = joblib.load(MODELS_DIR / "le_proto.pkl")
    le_service = joblib.load(MODELS_DIR / "le_service.pkl")
    
    with open(MODELS_DIR / "feature_order.json", "r") as f:
        feature_order = json.load(f)["feature_order"]
    
    print(f"Loading unseen dataset (UNSW-NB15_4.csv)...")
    column_names = [
        'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 
        'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb', 
        'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 
        'Dintpkt', 'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 
        'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 
        'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'label'
    ]
    
    df = pd.read_csv(DATA_DIR / "UNSW-NB15_4.csv", names=column_names, header=None, low_memory=False)
    y_test = df['label']
    
    print("Preprocessing test data...")
    # Handle hex strings in sport/dsport
    for col in ['sport', 'dsport']:
        if col in df.columns:
            df[col] = df[col].astype(str).apply(lambda x: int(x, 16) if x.startswith('0x') else x)
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)

    # Standard preprocessing
    df = df.drop(columns=['srcip', 'dstip', 'Stime', 'Ltime', 'attack_cat', 'label'], errors='ignore')
    
    # Apply saved encoding
    df['proto'] = le_proto.transform(df['proto'].astype(str))
    df['service'] = le_service.transform(df['service'].astype(str))
    
    # Handle other categorical if any (state, ct_ftp_cmd)
    # For now, just drop or factorize (state is often categorical)
    if 'state' in df.columns:
        df['state'] = pd.factorize(df['state'])[0]
    if 'ct_ftp_cmd' in df.columns:
        df['ct_ftp_cmd'] = pd.to_numeric(df['ct_ftp_cmd'], errors='coerce').fillna(0)

    # Align features
    X_test = df[feature_order]
    
    # Scale
    X_test_scaled = scaler.transform(X_test)
    
    print("Evaluating...")
    y_pred = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    
    print(f"\nFinal Accuracy on UNSEEN Dataset (UNSW-NB15_4.csv): {acc*100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

if __name__ == "__main__":
    evaluate()

if __name__ == "__main__":
    evaluate()
