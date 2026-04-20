import json
import os
import sys
from pathlib import Path

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common.feature_extractor import extract_features_from_eve, load_feature_names

def test_extraction():
    eve_path = "/var/log/suricata/eve.json"
    if not os.path.exists(eve_path):
        print(f"File not found: {eve_path}")
        return

    features = load_feature_names()
    print(f"Loaded {len(features)} features")

    count = 0
    with open(eve_path, "r") as f:
        # Read last 100 lines
        lines = f.readlines()[-100:]
        for line in lines:
            try:
                event = json.loads(line)
                feats = extract_features_from_eve(event, features)
                if feats:
                    print(f"Success: {event.get('event_type')} {event.get('src_ip')} -> {event.get('dest_ip')}")
                    count += 1
            except Exception as e:
                print(f"Error on line: {e}")
    
    print(f"Extracted {count} features from last 100 lines")

if __name__ == "__main__":
    test_extraction()
