import json
import os
import time
import pickle
import pandas as pd
from pathlib import Path

# Paths to files
LOG_FILE = Path(r"D:\projects\FYP\data\logs\eve.json")
ALERT_OUTPUT = Path(r"D:\projects\FYP\data\logs\ml_alerts.json")
MODEL_PATH = Path(r"D:\projects\FYP\models\model.pkl")
FEATURES_PATH = Path(r"D:\projects\FYP\models\features.json")

class MLEngine:
    def __init__(self):
        print("[*] Initializing Machine Learning Model...")
        
        # Load the pre-trained model
        with open(MODEL_PATH, "rb") as f:
            self.model = pickle.load(f)
            
        # Load the feature names
        with open(FEATURES_PATH, "r") as f:
            self.features = json.load(f)
            
        print("[+] Model loaded successfully.")

    def extract_features(self, event):
        """
        Convert Suricata EVE JSON event into the feature array 
        expected by the trained model.
        """
        # We only process 'flow' events since the model expects flow metrics
        if event.get('event_type') != 'flow':
            return None
            
        flow_data = event.get('flow', {})
        
        # Suricata EVE flow metrics mapped to model features
        fwd_pkts = float(flow_data.get('pkts_toserver', 0))
        bwd_pkts = float(flow_data.get('pkts_toclient', 0))
        fwd_bytes = float(flow_data.get('bytes_toserver', 0))
        bwd_bytes = float(flow_data.get('bytes_toclient', 0))
        
        # Flow age in Suricata is in seconds. CICIDS 'Flow Duration' is often in microseconds.
        flow_duration_us = float(flow_data.get('age', 0)) * 1_000_000
        
        # Calculate derived basic features
        flow_bytes_per_sec = (fwd_bytes + bwd_bytes) / (flow_data.get('age', 1) + 0.0001)
        flow_pkts_per_sec = (fwd_pkts + bwd_pkts) / (flow_data.get('age', 1) + 0.0001)

        # Dictionary to hold mapped features. Unmapped complex statistics default to 0.0
        feature_dict = {
            "Flow Duration": flow_duration_us,
            "Total Fwd Packets": fwd_pkts,
            "Total Backward Packets": bwd_pkts,
            "Fwd Packets Length Total": fwd_bytes,
            "Bwd Packets Length Total": bwd_bytes,
            "Flow Bytes/s": flow_bytes_per_sec,
            "Flow Packets/s": flow_pkts_per_sec,
            "Subflow Fwd Packets": fwd_pkts,
            "Subflow Fwd Bytes": fwd_bytes,
            "Subflow Bwd Packets": bwd_pkts,
            "Subflow Bwd Bytes": bwd_bytes,
            "Fwd Packets/s": fwd_pkts / (flow_data.get('age', 1) + 0.0001),
            "Bwd Packets/s": bwd_pkts / (flow_data.get('age', 1) + 0.0001),
        }
        
        # Build the final array ordered exactly as the model expects
        feature_vector = []
        for feature_name in self.features:
            feature_vector.append(feature_dict.get(feature_name, 0.0))
            
        return feature_vector

    def predict(self, feature_vector):
        """
        Run the ML model inference on the extracted features.
        """
        # Create a DataFrame as expected by the predict.py logic
        df = pd.DataFrame([feature_vector], columns=self.features)
        
        prediction = self.model.predict(df)[0]
        
        # Convert prediction result to human-readable format
        classification = "attack" if int(prediction) != 0 else "normal"
        
        return {
            "classification": classification,
            "raw_prediction": int(prediction)
        }

def tail_eve_log(file_path):
    """
    Continuously tail the eve.json file for new log entries.
    """
    engine = MLEngine()
    
    print(f"[*] Waiting for Suricata log file: {file_path}")
    while not file_path.exists():
        time.sleep(1)
        
    print(f"[*] Tailing {file_path} for new events...")
    
    with open(file_path, "r", encoding="utf-8") as f:
        # Seek to the end of the file so we only process new logs
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
                
            try:
                event = json.loads(line)
                
                # 1. Extract Features
                features = engine.extract_features(event)
                
                # Only run inference on flow events
                if features is None:
                    continue
                
                # 2. Run Inference
                prediction = engine.predict(features)
                
                # 3. Save combined result for Dashboard
                dashboard_event = {
                    "original_event": event,
                    "ml_insights": prediction,
                    "timestamp": event.get("timestamp")
                }
                
                with open(ALERT_OUTPUT, "a", encoding="utf-8") as out:
                    out.write(json.dumps(dashboard_event) + "\n")
                    
                alert_symbol = "🚨" if prediction['classification'] == "attack" else "✅"
                print(f"{alert_symbol} Processed Flow Event | Prediction: {prediction['classification'].upper()}")
                
            except json.JSONDecodeError:
                pass # Ignore malformed lines
            except Exception as e:
                print(f"[-] Error processing event: {e}")

if __name__ == "__main__":
    try:
        tail_eve_log(LOG_FILE)
    except KeyboardInterrupt:
        print("\n[*] Shutting down ML Engine consumer.")