#!/bin/bash
set -e

echo "[IDS] Environment Setup..."
# Check for dependencies
python3 -c "import websockets, pandas, sklearn" 2>/dev/null || {
    echo "[IDS] ERROR: Missing Python dependencies (websockets, pandas, or sklearn)."
    echo "[IDS] Attempting automated install..."
    pip3 install websockets pandas scikit-learn
}

echo "[IDS] Ensuring Suricata is active..."
systemctl is-active --quiet suricata || systemctl start suricata
chmod 666 /var/log/suricata/eve.json 2>/dev/null || true

echo "[IDS] Cleaning up old processes..."
pkill -f "consumer.py" 2>/dev/null || true
sleep 1

echo "[IDS] Truncating old logs for fresh start..."
mkdir -p data/logs
> data/logs/consumer.log

echo "[IDS] Starting ML consumer..."
cd /mnt/d/projects/FYP
# PYTHONUNBUFFERED=1 ensures we see logs in consumer.log immediately
PYTHONUNBUFFERED=1 nohup python3 src/ml_engine/consumer.py >> data/logs/consumer.log 2>&1 &
CPID=$!

sleep 3
if ps -p $CPID > /dev/null 2>&1; then
    echo "[IDS] Consumer running (PID $CPID) on ws://0.0.0.0:8765"
    echo "[IDS] Data available in /mnt/d/projects/FYP/data/logs/consumer.log"
else
    echo "[IDS] ERROR: Consumer crashed immediately. Last 20 lines of log:"
    tail -n 20 data/logs/consumer.log
    exit 1
fi