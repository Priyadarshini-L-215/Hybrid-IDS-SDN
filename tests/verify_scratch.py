import sys
import joblib
import numpy as np
from pathlib import Path

# Files to check
files = [
    Path("new model/encrypted_c2_model.pkl"),
    Path("new model/final_encrypted_c2_model.pkl")
]

print("=== Starting Model Verification ===")

for filepath in files:
    print(f"\nVerifying: {filepath}")
    if not filepath.exists():
        print("Error: File does not exist")
        continue
    
    try:
        model = joblib.load(filepath)
        print("1. Loading: SUCCESS")
        print(f"2. Model Class: {type(model)}")
        
        # Check attributes
        n_features = getattr(model, "n_features_in_", None)
        if n_features is not None:
            print(f"3. Feature Dimension (n_features_in_): {n_features}")
        else:
            # Let's inspect some other possible attribute (like n_features_)
            n_features = getattr(model, "n_features_", None)
            print(f"3. Feature Dimension (n_features_): {n_features}")
            
        # Try a dummy inference
        if n_features is not None:
            # generate dummy input
            dummy_input = np.zeros((1, n_features))
            try:
                pred = model.predict(dummy_input)
                prob = model.predict_proba(dummy_input) if hasattr(model, "predict_proba") else None
                print(f"4. Dummy Inference: SUCCESS (prediction: {pred}, proba: {prob})")
            except Exception as inf_err:
                print(f"4. Dummy Inference: FAILED with error: {inf_err}")
        else:
            print("4. Dummy Inference: SKIPPED (unknown dimensions)")
            
    except Exception as e:
        print(f"Error checking {filepath}: {e}")
        import traceback
        traceback.print_exc()

print("\n=== Verification Finished ===")
