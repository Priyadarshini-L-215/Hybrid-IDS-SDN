import sys
import json
import subprocess
import numpy as np
import joblib
from pathlib import Path

# Add src to path
BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR / "src"))

from common.feature_extractor import extract_features_from_eve, load_feature_names

async def evaluate_pcap(pcap_path):
    print(f"=== Sentinel Core: PCAP Evaluation ({pcap_path}) ===")
    
    # 1. Setup paths
    pcap_path = Path(pcap_path).absolute()
    output_dir = BASE_DIR / "data" / "pcap_eval"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # We'll use a specific eve.json for this run
    eve_path = output_dir / "eve.json"
    if eve_path.exists():
        eve_path.unlink() # Clear previous results

    original_config_path = BASE_DIR / "config" / "suricata" / "suricata.yaml"
    temp_config_path = output_dir / "suricata_temp.yaml"
    
    # 2. Prepare Config (Replace __REPO_ROOT__)
    print("Step 1: Preparing Suricata configuration...")
    with open(original_config_path, 'r') as f:
        config_content = f.read()
    
    # Replace placeholders
    repo_root = str(BASE_DIR)
    processed_config = config_content.replace("__REPO_ROOT__", repo_root)
    processed_config = processed_config.replace("__SURICATA_INTERFACE__", "eth0") # Dummy for offline
    
    # Redirect eve-log to our specific path for easy parsing
    # The config has two eve-log outputs. We'll find the regular one.
    processed_config = processed_config.replace(
        f"filename: {repo_root}/data/logs/eve.json",
        f"filename: {str(eve_path)}"
    )
    
    with open(temp_config_path, 'w') as f:
        f.write(processed_config)

    # 3. Run Suricata
    print("Step 2: Running Suricata in offline mode...")
    cmd = [
        "suricata",
        "-r", str(pcap_path),
        "-c", str(temp_config_path),
        "-l", str(output_dir),
        "-k", "none"
    ]
    
    try:
        # We don't use check=True to avoid crashing on warnings
        result = subprocess.run(cmd, capture_output=True)
        if result.returncode != 0:
            print(f"Suricata finished with code {result.returncode}")
            print(result.stderr.decode()[-500:]) # Show last part of error
    except Exception as e:
        print(f"Fatal error running Suricata: {e}")
        return

    if not eve_path.exists():
        print(f"Error: {eve_path} was not generated.")
        # Check if it was generated at the default path instead
        default_eve = BASE_DIR / "data" / "logs" / "eve.json"
        if default_eve.exists():
            print(f"Found eve.json at fallback path: {default_eve}")
            eve_path = default_eve
        else:
            return

    # 4. Load Model and Features
    print("Step 3: Loading ML artifacts...")
    model = joblib.load(BASE_DIR / "models" / "rf_model.pkl")
    scaler = joblib.load(BASE_DIR / "models" / "scaler.pkl")
    feature_order = load_feature_names()

    # 5. Extract Features
    print("Step 4: Extracting features from EVE JSON...")
    all_features = []
    flow_infos = []
    
    with open(eve_path, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                if event.get('event_type') == 'flow':
                    features = await extract_features_from_eve(event, feature_order)
                    if features:
                        all_features.append(features)
                        flow_infos.append({
                            "timestamp": event.get('timestamp'),
                            "src_ip": event.get('src_ip'),
                            "src_port": event.get('src_port'),
                            "dest_ip": event.get('dest_ip'),
                            "dest_port": event.get('dest_port'),
                            "proto": event.get('proto')
                        })
            except Exception:
                continue

    if not all_features:
        print("No valid flows found in the EVE JSON.")
        return

    print(f"Found {len(all_features)} flows.")

    # 6. Inference
    print("Step 5: Running ML inference...")
    X = np.array(all_features)
    # Ensure float32 to match model training
    X = X.astype(np.float32)
    X_scaled = scaler.transform(X)
    
    preds = model.predict(X_scaled)
    probs = model.predict_proba(X_scaled)[:, 1]

    # 7. Results
    print("\n" + "="*95)
    print(f"{'TIMESTAMP':<25} {'SOURCE':<20} {'DESTINATION':<20} {'RESULT':<10} {'PROB'}")
    print("-"*95)
    
    attack_count = 0
    # Show first 50 results to avoid flooding
    display_limit = 50
    for i in range(min(len(preds), display_limit)):
        res = "ATTACK" if preds[i] == 1 else "NORMAL"
        if preds[i] == 1:
            attack_count += 1
        
        info = flow_infos[i]
        src = f"{info['src_ip']}:{info['src_port']}"
        dst = f"{info['dest_ip']}:{info['dest_port']}"
        print(f"{info['timestamp'][:23]:<25} {src:<20} {dst:<20} {res:<10} {probs[i]:.4f}")

    if len(preds) > display_limit:
        print(f"... and {len(preds) - display_limit} more flows ...")
        # Still count attacks for the whole set
        attack_count = sum(preds)

    print("="*95)
    print(f"Evaluation Summary:")
    print(f"  Total Flows: {len(preds)}")
    print(f"  Attacks Detected: {int(attack_count)}")
    print(f"  Normal Flows: {int(len(preds) - attack_count)}")
    print(f"  Detection Rate: {(attack_count/len(preds)*100):.2f}%")
    print("="*95)

if __name__ == "__main__":
    import asyncio
    pcap = sys.argv[1] if len(sys.argv) > 1 else "user/test.pcapng"
    asyncio.run(evaluate_pcap(pcap))

