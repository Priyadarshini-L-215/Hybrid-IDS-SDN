import json
import pickle
import pandas as pd
from pathlib import Path
from collections import deque

BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_PATH = BASE_DIR / "models" / "model.pkl"
FEATURES_PATH = BASE_DIR / "models" / "features.json"
EVE_LOG = BASE_DIR / "data" / "logs" / "eve.json"

# Load model and feature list once at startup
with MODEL_PATH.open("rb") as f:
    model = pickle.load(f)

with FEATURES_PATH.open("r", encoding="utf-8") as f:
    FEATURES = json.load(f)   # list of 57/83 feature names

_EVE_LOG_POS = 0
_RECENT_ALERTS = deque(maxlen=50)

def extract_features(alert: dict) -> list:
    """Map a Suricata eve.json alert/flow to the feature vector."""
    flow = alert.get("flow", {})

    raw = {
        "Destination Port":     alert.get("dest_port", 0),
        "Flow Duration":        flow.get("age", 0) * 1_000_000,
        "Total Fwd Packets":    flow.get("pkts_toserver", 0),
        "Total Backward Packets": flow.get("pkts_toclient", 0),
        "Total Length of Fwd Packets": flow.get("bytes_toserver", 0),
        "Total Length of Bwd Packets": flow.get("bytes_toclient", 0),
        "Fwd Packet Length Max": flow.get("bytes_toserver", 0),
        "Bwd Packet Length Max": flow.get("bytes_toclient", 0),
        "Flow Bytes/s":         flow.get("bytes_toserver", 0) / max(flow.get("age", 1), 0.0001),
        "Flow Packets/s":       flow.get("pkts_toserver", 0) / max(flow.get("age", 1), 0.0001),
        # All other mapped features will default to 0 as requested
    }

    vector = [raw.get(feat, 0.0) for feat in FEATURES]
    return vector

def predict_alert(alert: dict) -> dict:
    """Return prediction dict for one Suricata log event."""
    try:
        vector = extract_features(alert)
        # Using pandas DataFrame as your specific model requires column names
        df = pd.DataFrame([vector], columns=FEATURES)
        
        label = int(model.predict(df)[0])
        
        # Some models don't expose predict_proba, fallback to 100% if missing
        try:
            proba = model.predict_proba(df)[0]
            confidence = round(float(max(proba)) * 100, 1)
        except AttributeError:
            confidence = 100.0
            
        # If the log is an alert, grab the signature. Otherwise, it's just a network flow.
        alert_info = alert.get("alert", {})
        alert_sig = alert_info.get("signature", "Flow Connection")
        severity  = alert_info.get("severity", 0)
        category  = alert_info.get("category", "")
            
        prediction_label = "Attack" if label == 1 else "Normal"
        
        # If Suricata generated a rule-based critical alert (severity 1 or 2), override the ML prediction
        # Otherwise, trust the ML Engine for events like 'ICMP Ping' or 'Nmap Generic'
        if alert.get("event_type") == "alert" and 0 < severity <= 2:
            prediction_label = "Attack"
            confidence = max(confidence, 99.0)
            
        return {
            "prediction": prediction_label,
            "confidence": confidence,
            "src_ip":    alert.get("src_ip", "Unknown"),
            "src_port":  alert.get("src_port", 0),
            "dest_ip":   alert.get("dest_ip", "Unknown"),
            "dest_port": alert.get("dest_port", 0),
            "protocol":  alert.get("proto", "Unknown"),
            "timestamp": alert.get("timestamp", "Unknown"),
            "alert_sig": alert_sig,
            "severity":  severity,
            "category":  category,
            "flow_id":   alert.get("flow_id", ""),
            "event_type": alert.get("event_type", "unknown"),
        }
    except Exception as e:
        return {"prediction": "Error", "confidence": 0, "error": str(e)}

def tail_eve_json(n_recent=50) -> list:
    """Read last n_recent alert events from eve.json."""
    global _EVE_LOG_POS

    try:
        eve_path = EVE_LOG
        if not eve_path.exists():
            return list(_RECENT_ALERTS)[-n_recent:]

        current_size = eve_path.stat().st_size
        if current_size < _EVE_LOG_POS:
            _EVE_LOG_POS = 0
            _RECENT_ALERTS.clear()

        with eve_path.open("r", encoding="utf-8", errors="ignore") as handle:
            handle.seek(_EVE_LOG_POS)
            new_chunk = handle.read()
            _EVE_LOG_POS = handle.tell()

        if not new_chunk:
            return list(_RECENT_ALERTS)[-n_recent:]

        for line in new_chunk.splitlines():
            try:
                evt = json.loads(line)
                # We analyze both 'alert' and 'flow' events so you can see live normal traffic too
                if evt.get("event_type") in ["alert", "flow"]:
                    pred_res = predict_alert(evt)
                    
                    # Prevent 'Normal' background flow connections from spamming the UI
                    if evt.get("event_type") == "flow" and pred_res["prediction"].lower() == "normal":
                        continue
                    _RECENT_ALERTS.append(pred_res)
            except json.JSONDecodeError:
                continue
    except FileNotFoundError:
        pass
    
    # Reverse so the newest is at the top/bottom depending on how Flask sends it
    return list(_RECENT_ALERTS)[-n_recent:]