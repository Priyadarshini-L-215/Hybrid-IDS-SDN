import pickle
import os
import json

def generate_mocks(models_dir):
    # Dummy RF/Scaler (Pickle)
    for f in ["rf_model.pkl", "scaler.pkl", "vae_scaler.pkl", "feature_order.pkl"]:
        path = os.path.join(models_dir, f)
        if not os.path.exists(path):
            with open(path, 'wb') as fd:
                pickle.dump({"mock": True}, fd)
            print(f"Generated mock: {f}")

    # Dummy Keras (just empty files that pass exists check)
    for f in ["vae_encoder.keras", "vae_decoder.keras"]:
        path = os.path.join(models_dir, f)
        if not os.path.exists(path):
            with open(path, 'w') as fd:
                fd.write("MOCK_KERAS_MODEL")
            print(f"Generated mock: {f}")

    # Feature order JSON
    path = os.path.join(models_dir, "feature_order.json")
    if not os.path.exists(path):
        with open(path, 'w') as fd:
            json.dump(["feature1", "feature2"], fd)
        print(f"Generated mock: feature_order.json")

if __name__ == "__main__":
    import sys
    generate_mocks(sys.argv[1])
