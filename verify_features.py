#!/usr/bin/env python3
"""
Quick verification script to test feature extraction.
Run this to verify that 57 features are being extracted correctly.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from common.feature_extractor import extract_features_from_eve, load_feature_names, validate_feature_vector

def main():
    print("=" * 80)
    print("FEATURE EXTRACTION VERIFICATION")
    print("=" * 80)
    
    # 1. Load feature names
    print("\n1. Loading feature definitions...")
    try:
        features = load_feature_names()
        print(f"   [OK] Loaded {len(features)} features")
        if len(features) != 57:
            print(f"   [WARN] Expected 57, got {len(features)}")
            return 1
    except Exception as e:
        print(f"   [ERROR] Error loading features: {e}")
        return 1
    
    # 2. Create sample EVE event
    print("\n2. Creating sample Suricata EVE JSON event...")
    sample_event = {
        "event_type": "flow",
        "flow": {
            "pkts_toserver": 10,
            "pkts_toclient": 5,
            "bytes_toserver": 1500,
            "bytes_toclient": 800,
            "age": 2.5
        },
        "src_ip": "192.168.1.100",
        "dest_ip": "10.0.0.1",
        "src_port": 12345,
        "dest_port": 80,
        "proto": "TCP",
        "timestamp": "2026-04-20T14:30:00.000Z"
    }
    print("   [OK] Created sample event")
    
    # 3. Extract features
    print("\n3. Extracting 57 features...")
    try:
        feature_vector = extract_features_from_eve(sample_event, features)
        if feature_vector is None:
            print("   [ERROR] Feature extraction returned None")
            return 1
        print(f"   [OK] Extracted {len(feature_vector)} features")
    except Exception as e:
        print(f"   [ERROR] Error extracting features: {e}")
        return 1
    
    # 4. Validate features
    print("\n4. Validating feature vector...")
    try:
        if not validate_feature_vector(feature_vector):
            print("   [ERROR] Feature vector validation failed")
            return 1
        print("   [OK] All 57 features valid")
    except Exception as e:
        print(f"   [ERROR] Error validating features: {e}")
        return 1
    
    # 5. Display feature names & values
    print("\n5. Feature Summary (first 10):")
    for i, (name, value) in enumerate(zip(features[:10], feature_vector[:10])):
        print(f"   [{i+1:2d}] {name:<40} = {value:>12.4f}")
    print(f"   ...")
    print(f"   (showing 10 of {len(features)} features)")
    
    # 6. Statistics
    print("\n6. Feature Statistics:")
    import statistics
    print(f"   Count:    {len(feature_vector)}")
    print(f"   Min:      {min(feature_vector):>12.4f}")
    print(f"   Max:      {max(feature_vector):>12.4f}")
    print(f"   Mean:     {statistics.mean(feature_vector):>12.4f}")
    print(f"   Stdev:    {statistics.stdev(feature_vector):>12.4f}")
    
    # 7. Data type check
    print("\n7. Data Type Verification:")
    all_float = all(isinstance(x, (int, float)) for x in feature_vector)
    if all_float:
        print("   [OK] All values are numeric")
    else:
        print("   [ERROR] Non-numeric values found")
        return 1
    
    # 8. Success
    print("\n" + "=" * 80)
    print("[OK] VERIFICATION COMPLETE - ALL 57 FEATURES EXTRACTED SUCCESSFULLY!")
    print("=" * 80)
    print("\nThe feature extractor is working correctly.")
    print("The ML model will now receive the complete 57-feature vector for accurate predictions.")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
