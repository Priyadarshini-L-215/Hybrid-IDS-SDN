import sys
from pathlib import Path
import json

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ml_engine.engine import MLEngine
import pandas as pd
import numpy as np
import logging
import structlog

# Suppress noisy logs during batch evaluation
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING))
logging.getLogger("ml_engine").setLevel(logging.WARNING)
logging.getLogger("src.ml_engine.decision_engine").setLevel(logging.WARNING)

def main():
    print("Initializing ML Engine...")
    engine = MLEngine()
    
    if not engine.is_ready:
        print("ML Engine failed to initialize models.")
        return

    dataset_path = "data/UNSW-NB15_c/UNSW_NB15_testing-set.csv"
    if not Path(dataset_path).exists():
        print(f"Dataset not found at {dataset_path}")
        return

    print(f"Loading dataset: {dataset_path}...")
    df = pd.read_csv(dataset_path)
    
    # Mapping for UNSW-NB15 dataset to model features
    mapping = {
        'dur': 'flow_duration',
        'spkts': 'spkts',
        'dpkts': 'dpkts',
        'sbytes': 'sbytes',
        'dbytes': 'dbytes',
        'sload': 'sload',
        'dload': 'dload',
        'sloss': 'sloss',
        'dloss': 'dloss',
        'sttl': 'sttl',
        'dttl': 'dttl',
        'swin': 'swin',
        'dwin': 'dwin',
        'stcpb': 'stcpb',
        'dtcpb': 'dtcpb',
        'tcprtt': 'tcprtt',
        'synack': 'synack',
        'ackdat': 'ackdat',
        'sinpkt': 'sinpkt',
        'dinpkt': 'dinpkt',
        'sjit': 'sjit',
        'djit': 'djit',
        'ct_state_ttl': 'ct_state_ttl',
        'ct_flw_http_mthd': 'ct_flw_http_mthd',
        'ct_srv_src': 'ct_srv_src',
        'ct_srv_dst': 'ct_srv_dst',
        'ct_dst_ltm': 'ct_dst_ltm',
        'ct_src_ltm': 'ct_src_ltm',
        'ct_src_dport_ltm': 'ct_src_dport_ltm',
        'ct_dst_sport_ltm': 'ct_dst_sport_ltm',
        'ct_dst_src_ltm': 'ct_dst_src_ltm',
        'smean': 'smeansz',
        'dmean': 'dmeansz',
        'trans_depth': 'trans_depth',
        'response_body_len': 'res_bdy_len',
        'is_sm_ips_ports': 'is_sm_ips_ports',
        'is_ftp_login': 'is_ftp_login',
        'ct_ftp_cmd': 'ct_ftp_cmd'
    }
    
    # Rename columns
    df = df.rename(columns=mapping)
    
    # Derived features
    df['flow_duration'] = df['flow_duration'] * 1000 # UNSW is in seconds, model uses ms
    df['total_fwd_packets'] = df['spkts']
    df['total_bwd_packets'] = df['dpkts']
    df['total_fwd_bytes'] = df['sbytes']
    df['total_bwd_bytes'] = df['dbytes']
    df['flow_iat_mean'] = (df['flow_duration'] / (df['spkts'] + df['dpkts']).clip(lower=1))
    df['flow_iat_std'] = 0.0
    df['fwd_iat_mean'] = df['sinpkt']
    df['bwd_iat_mean'] = df['dinpkt']
    df['pkt_len_mean'] = (df['sbytes'] + df['dbytes']) / (df['spkts'] + df['dpkts']).clip(lower=1)
    df['pkt_len_std'] = 0.0
    
    # Protocol encoding
    from common.feature_extractor import get_proto_encoder
    le = get_proto_encoder()
    if le:
        df['app_proto'] = df['proto'].apply(lambda x: float(le.transform([x.lower()])[0]) if x.lower() in le.classes_ else 0.0)
    else:
        df['app_proto'] = 0.0

    # Ensure all 49 features are present
    for f in engine.feature_order:
        if f not in df.columns:
            df[f] = 0.0

    print(f"Evaluating mapped dataset...")
    # Use label_column="label" (lowercase in CSV)
    from ml_engine.evaluator import evaluate_dataset
    
    # Save processed temp file for evaluate_dataset to use
    temp_path = "data/temp_eval.csv"
    df.to_csv(temp_path, index=False)
    
    results = evaluate_dataset(temp_path, engine, label_column="label")
    
    if not results.get("success"):
        print(f"Evaluation failed: {results.get('error')}")
        return

    print("\n" + "="*50)
    print("EVALUATION RESULTS")
    print("="*50)
    print(f"Total Samples: {results['summary']['total_samples']}")
    print(f"Accuracy:      {results['summary']['accuracy']:.4f}")
    print(f"Model Version: {results['summary']['model_version']}")
    print("-" * 50)
    
    metrics = results['metrics']
    for label, scores in metrics.items():
        if isinstance(scores, dict):
            print(f"Class: {label}")
            print(f"  Precision: {scores.get('precision', 0):.4f}")
            print(f"  Recall:    {scores.get('recall', 0):.4f}")
            print(f"  F1-Score:  {scores.get('f1-score', 0):.4f}")
            print(f"  Support:   {scores.get('support', 0)}")
    
    # Save results to file
    with open("data/eval_results.json", "w") as f:
        json.dump(results, f, indent=4)
    print("\nFull metrics saved to data/eval_results.json")

if __name__ == "__main__":
    main()
