import pickle
import os
import json

def generate_mocks(models_dir):
    import joblib, numpy as np, json
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import MinMaxScaler
    
    feature_count = 49
    X = np.random.rand(100, feature_count)
    y = np.random.randint(0, 2, 100)
    
    # 1. Functional RF Model
    rf_path = os.path.join(models_dir, "rf_model.pkl")
    if not os.path.exists(rf_path) or os.path.getsize(rf_path) < 100:
        model = RandomForestClassifier(n_estimators=5, max_depth=3).fit(X, y)
        joblib.dump(model, rf_path)
        print(f"Generated functional mock RF: {rf_path}")

    # 2. Functional Scaler
    scaler_path = os.path.join(models_dir, "scaler.pkl")
    if not os.path.exists(scaler_path) or os.path.getsize(scaler_path) < 100:
        scaler = MinMaxScaler().fit(X)
        joblib.dump(scaler, scaler_path)
        print(f"Generated functional mock Scaler: {scaler_path}")

    # 3. VAE Scaler
    vae_scaler_path = os.path.join(models_dir, "vae_scaler.pkl")
    if not os.path.exists(vae_scaler_path) or os.path.getsize(vae_scaler_path) < 100:
        scaler = MinMaxScaler().fit(X)
        joblib.dump(scaler, vae_scaler_path)
        print(f"Generated functional mock VAE Scaler: {vae_scaler_path}")

    # 4. Keras placeholders (need real files for keras.load_model to not crash)
    # Note: Keras models are harder to generate without keras installed in the setup environment
    # but we'll at least ensure the pkl files are fixed as they are the primary blocker for scores.

if __name__ == "__main__":
    import sys
    generate_mocks(sys.argv[1])
