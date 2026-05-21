import os
import sys
import json
import subprocess
import pandas as pd
from pathlib import Path

# Add src to path
BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR / "src"))

from common.feature_extractor import extract_features_from_eve, load_feature_names

async def pcap_to_csv(pcap_path, label, output_csv="data/dataset.csv", append=True):
    print(f"=== Converting PCAP to Training CSV ({label}) ===")
    
    pcap_path = Path(pcap_path).absolute()
    output_dir = BASE_DIR / "data" / "pcap_conv"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    eve_path = output_dir / "eve.json"
    if eve_path.exists(): eve_path.unlink()

    original_config_path = BASE_DIR / "config" / "suricata" / "suricata.yaml"
    temp_config_path = output_dir / "suricata_temp.yaml"
    
    with open(original_config_path, 'r') as f:
        config_content = f.read()
    
    repo_root = str(BASE_DIR)
    processed_config = config_content.replace("__REPO_ROOT__", repo_root)
    processed_config = processed_config.replace("__SURICATA_INTERFACE__", "eth0")
    processed_config = processed_config.replace(
        f"filename: {repo_root}/data/logs/eve.json",
        f"filename: {str(eve_path)}"
    )
    
    with open(temp_config_path, 'w') as f:
        f.write(processed_config)

    print("Running Suricata...")
    subprocess.run([
        "suricata", "-r", str(pcap_path), "-c", str(temp_config_path), "-l", str(output_dir), "-k", "none"
    ], capture_output=True)

    if not eve_path.exists():
        print("Error: eve.json not generated")
        return False

    feature_order = load_feature_names()
    all_features = []
    
    with open(eve_path, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                if event.get('event_type') == 'flow':
                    features = await extract_features_from_eve(event, feature_order)
                    if features:
                        all_features.append(features)
            except Exception:
                continue

    if not all_features:
        print("No flows found")
        return False

    df = pd.DataFrame(all_features, columns=feature_order)
    df['Label'] = 1 if str(label).lower() in ['attack', '1', 'malicious'] else 0
    
    output_path = BASE_DIR / output_csv
    if append and output_path.exists():
        print(f"Appending {len(df)} samples to {output_csv}")
        df.to_csv(output_path, mode='a', header=False, index=False)
    else:
        print(f"Saving {len(df)} samples to {output_csv}")
        df.to_csv(output_path, index=False)
        
    return True

if __name__ == "__main__":
    import asyncio
    if len(sys.argv) < 3:
        print("Usage: python3 pcap_to_csv.py <pcap> <label>")
    else:
        asyncio.run(pcap_to_csv(sys.argv[1], sys.argv[2]))

