import sys
import sqlite3
import redis
import requests
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from common.config import API_PORT, DB_PATH, REDIS_HOST, REDIS_PORT, MODELS_DIR

def check_redis():
    print("[*] Checking Redis...")
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        r.ping()
        print("    [+] Redis is UP")
        return True
    except Exception as e:
        print(f"    [-] Redis connection failed: {e}")
        return False

def check_db():
    print("[*] Checking SQLite Database...")
    if not DB_PATH.exists():
        print(f"    [-] DB file missing at {DB_PATH}")
        return False
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"    [+] DB connected. Tables found: {[t[0] for t in tables]}")
        cursor.execute("SELECT COUNT(*) FROM alerts")
        count = cursor.fetchone()[0]
        print(f"    [+] Alert count: {count}")
        conn.close()
        return True
    except Exception as e:
        print(f"    [-] DB check failed: {e}")
        return False

def check_models():
    print("[*] Checking ML Models...")
    required = ["rf_model.pkl", "scaler.pkl", "autoencoder.pth", "feature_order.json"]
    missing = []
    for f in required:
        p = MODELS_DIR / f
        if not p.exists():
            missing.append(f)
    if missing:
        print(f"    [-] Missing model files: {missing}")
        return False
    print("    [+] All required model files present")
    return True

def check_api():
    print(f"[*] Checking Relay API (Port {API_PORT})...")
    try:
        resp = requests.get(f"http://127.0.0.1:{API_PORT}/api/pipeline/status", timeout=5)
        if resp.status_code == 200:
            print(f"    [+] API is UP: {resp.json().get('status')}")
            return True
        else:
            print(f"    [-] API returned status {resp.status_code}")
            return False
    except Exception as e:
        print(f"    [-] API connection failed: {e}")
        return False

def run_audit():
    print("="*60)
    print("            SENTINEL SYSTEM AUDIT")
    print("="*60)
    results = {
        "redis": check_redis(),
        "database": check_db(),
        "models": check_models(),
        "api": check_api()
    }
    print("="*60)
    if all(results.values()):
        print("SUCCESS: Core system components are healthy.")
    else:
        print("WARNING: Some components failed the audit. See logs above.")
    print("="*60)

if __name__ == "__main__":
    run_audit()
