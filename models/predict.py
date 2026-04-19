import pickle
import json
import pandas as pd
import numpy as np

# Load model
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

# Load feature names
with open("features.json", "r") as f:
    features = json.load(f)

print("Model loaded successfully ✅")

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
        print("Prediction: ATTACK 🚨")