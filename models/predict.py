import pickle
import json
import pandas as pd
import numpy as np
from pathlib import Path

# Resolve paths relative to this script so the helper works from any shell location.
BASE_DIR = Path(__file__).resolve().parent

# Load model
with open(BASE_DIR / "model.pkl", "rb") as f:
    model = pickle.load(f)

# Load feature names
with open(BASE_DIR / "features.json", "r", encoding="utf-8") as f:
    features = json.load(f)

print("Model loaded successfully")

def predict_traffic(input_features):
    df = pd.DataFrame([input_features], columns=features)
    prediction = model.predict(df)[0]
    return int(prediction)

# Example test
if __name__ == "__main__":
    sample = np.random.rand(len(features))
    result = predict_traffic(sample)

    if result == 0:
        print("Prediction: NORMAL traffic")
    else:
        print("Prediction: ATTACK")
