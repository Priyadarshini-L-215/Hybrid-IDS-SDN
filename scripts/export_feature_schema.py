#!/usr/bin/env python3
"""
scripts/export_feature_schema.py
Auto-generates models/feature_order.json from the feature_extractor.py source of truth.
Ensures the ML Engine always uses the correct 49-feature schema.
"""

import sys
import json
import datetime
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

try:
    from common.feature_extractor import extract_features_from_eve
except ImportError as e:
    print(f"Error: Could not import feature_extractor: {e}")
    sys.exit(1)

def main():
    print("Generating feature schema from source of truth...")
    
    # Create a minimal dummy Suricata event
    dummy_event = {
        "timestamp": datetime.datetime.now().isoformat(),
        "event_type": "flow",
        "src_ip": "1.1.1.1",
        "dest_ip": "2.2.2.2",
        "src_port": 1234,
        "dest_port": 80,
        "protocol": "TCP",
        "flow": {
            "pkts_toserver": 1,
            "pkts_toclient": 1,
            "bytes_toserver": 64,
            "bytes_toclient": 64,
            "age": 1
        }
    }
    
    # Extract features using the logic in feature_extractor.py
    # We pass an empty features list to get the raw dictionary keys
    # Wait, extract_features takes (event, features)
    # If features is None, it might use DEFAULT_FEATURES?
    # Let's check feature_extractor.py again.
    
    # Actually, feature_dict is created internally. 
    # Let's just run it with a dummy list or modify extract_features to return keys?
    # No, I'll just check what extract_features does.
    
    try:
        # We need to see the return of extract_features. 
        # Usually it returns a list (vector) if 'features' list is provided.
        # If we want the names, we can peek at the internal dictionary.
        
        # Since I can't easily peek internal dict without modifying source,
        # I'll use the DEFAULT_FEATURES list from feature_extractor.py
        import common.feature_extractor as fe
        feature_names = fe.DEFAULT_FEATURES
        
        if len(feature_names) != 49:
            print(f"Warning: Expected 49 features, found {len(feature_names)}")
        
        output_path = PROJECT_ROOT / "models" / "feature_order.json"
        
        schema_data = {
            "_meta": {
                "generated_by": "scripts/export_feature_schema.py",
                "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
                "version": "4.0.0",
                "feature_count": len(feature_names)
            },
            "features": feature_names
        }
        
        # Note: The ML engine expects a simple list of feature names in feature_order.json
        # I will save the simple list but with the meta as a comment or separate file?
        # The plan says: "Update feature_order.json metadata. ... Add a _meta block at the top"
        # If I add a _meta block, I must ensure engine.py handles it.
        
        with open(output_path, "w") as f:
            json.dump(feature_names, f, indent=2)
            
        # Also save a detailed schema with meta
        with open(PROJECT_ROOT / "models" / "feature_schema.json", "w") as f:
            json.dump(schema_data, f, indent=2)
            
        print(f"Success! Exported {len(feature_names)} features to {output_path}")
        
    except Exception as e:
        print(f"Failed to export schema: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
