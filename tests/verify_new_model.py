import sys
from pathlib import Path
import logging

# Add src to path
BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR / "src"))

from ml_engine.engine import MLEngine

logging.basicConfig(level=logging.INFO)

def verify():
    print("Initializing MLEngine with the new model...")
    try:
        engine = MLEngine()
        if engine.is_ready:
            print("SUCCESS: ML Engine is ready and model is loaded!")
            print(f"Model version: {engine.meta.get('model_version')}")
            print(f"Feature count: {len(engine.feature_order)}")
            
            # Test a dummy prediction
            import numpy as np
            dummy_event = {"event_type": "alert", "proto": "TCP", "src_ip": "1.2.3.4"}
            # We need to provide features that match the order
            # The extract_features_batch will handle the mapping if we provide a raw event
            # But here we just want to see if the session runs
            results = engine.predict_batch([dummy_event])
            print(f"Prediction test results: {results}")
        else:
            print("FAILURE: ML Engine is NOT ready. Check logs.")
    except Exception as e:
        print(f"ERROR during verification: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    verify()
