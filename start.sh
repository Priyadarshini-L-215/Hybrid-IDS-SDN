#!/bin/bash
# start.sh - Unified Sentinel Core Launcher (Native Linux)

echo "================================================================="
echo "            SENTINEL CORE: HYBRID ML-POWERED IPS"
echo "================================================================="
echo "            Pipeline: Pure Linux (WSL Ubuntu)"
echo "================================================================="

# 1. Verification
if [ ! -d ".venv" ]; then
    echo "[ERROR] Virtual environment not found. Please run ./setup.sh first."
    exit 1
fi

# 2. Cleanup Stale Processes
echo "[+] Purging stale processes..."
./stop.sh > /dev/null 2>&1

# 3. Start Redis
echo "[+] Starting Redis Server..."
sudo service redis-server start >/dev/null 2>&1 || sudo redis-server --daemonize yes

# 4. Start Suricata
echo "[+] Starting Core IDS Sensor (Suricata)..."
if ! pgrep suricata > /dev/null; then
    sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -D
    sleep 2
fi

# 5. Start ML Consumer
echo "[+] Launching ML Engine (Consumer)..."
source .venv/bin/activate
mkdir -p data/logs
python src/ml_engine/consumer.py > data/logs/consumer.log 2>&1 &
CONSUMER_PID=$!

# Wait for ML Engine internal WebSocket to bind
echo "[*] Waiting for pipeline at 127.0.0.1:8765 (timeout 45s)..."
python scripts/wait_for_pipeline.py --host 127.0.0.1 --port 8765 --timeout 45
if [ $? -ne 0 ]; then
    echo "[ERROR] Pipeline failed to start. Check data/logs/consumer.log"
    kill $CONSUMER_PID
    exit 1
fi

# 6. Start Flask Relay
echo "[+] Launching Flask Dashboard Backend..."
export FLASK_APP=src/dashboard/app.py
export FLASK_ENV=development
python -m flask run -h 0.0.0.0 -p 5000 > data/logs/relay.log 2>&1 &

# Wait for Flask
python scripts/wait_for_pipeline.py --host 127.0.0.1 --port 5000 --timeout 30

# 7. Start React Dashboard
echo "[+] Launching Sentinel Core Dashboard (React)..."
cd ui
nohup npm run dev > ../data/logs/ui.log 2>&1 &
cd ..

echo "================================================================="
echo "[SUCCESS] Sentinel Core is now ACTIVE."
echo "================================================================="
echo "[SERVICES]"
echo "- Dashboard:      http://127.0.0.1:3000"
echo "- WebSocket API:  ws://127.0.0.1:8765"
echo "- Flask Relay:    http://127.0.0.1:5000"
echo "- Core Logs:      tail -f data/logs/consumer.log"
echo "================================================================="
echo "Press Ctrl+C to stop the system, or run ./stop.sh in another terminal."

# Keep alive to allow Ctrl+C to work gracefully if run in foreground
tail -f data/logs/consumer.log
