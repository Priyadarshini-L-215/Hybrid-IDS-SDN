import json
import time
import os
import uuid
import sys

# Path to EVE JSON in WSL
EVE_PATH = "/var/log/suricata/eve.json"

def inject_tracer():
    tracer_id = str(uuid.uuid4())[:12]
    # T0: moment tracer is written to disk
    inject_ts = time.time()
    
    tracer_event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000"),
        "event_type": "alert",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9999999,
            "rev": 1,
            "signature": "SENTINEL_LATENCY_PROBE",
            "category": "Diagnostic",
            "severity": 3
        },
        "src_ip": "1.2.3.4",
        "dest_ip": "5.6.7.8",
        "proto": "TCP",
        "_tracer": True,
        "_tracer_id": tracer_id,
        "_tracer_inject_ts": inject_ts
    }
    
    line = json.dumps(tracer_event) + "\n"
    
    # Check permissions and write
    if not os.path.exists(os.path.dirname(EVE_PATH)):
        os.makedirs(os.path.dirname(EVE_PATH), exist_ok=True)
        
    with open(EVE_PATH, "a") as f:
        f.write(line)
        f.flush()
        
    print(f"[TRACER] Injected probe {tracer_id} at T0={inject_ts}")
    return tracer_id

if __name__ == "__main__":
    inject_tracer()
