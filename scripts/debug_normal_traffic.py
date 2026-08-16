import asyncio
import sys
from pathlib import Path
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ml_engine.engine import MLEngine
from common.feature_extractor import extract_c2_features_from_eve

async def main():
    engine = MLEngine()
    
    benign_flow = {
        "event_type": "flow",
        "proto": "UDP",
        "src_ip": "192.168.29.118",
        "dest_ip": "8.8.8.8",
        "src_port": 53535,
        "dest_port": 53,
        "app_proto": "dns",
        "flow": {
            "pkts_toserver": 2,
            "pkts_toclient": 2,
            "bytes_toserver": 150,
            "bytes_toclient": 300,
            "age": 1
        }
    }
    
    res = await engine.predict_batch([benign_flow])
    print("\nBenign Flow Prediction Result:", res[0])

if __name__ == "__main__":
    asyncio.run(main())
