#!/bin/bash
# start.sh - Unified Sentinel Core Launcher (Native Linux Optimized)

echo "================================================================="
echo "            SENTINEL CORE: HYBRID ML-POWERED IPS"
echo "================================================================="
echo "            Environment: Native Linux (Ubuntu)"
echo "================================================================="

# 1. Automatic Dependency Check
if [ ! -d ".venv" ] || [ ! -d "ui/node_modules" ]; then
    echo "[!] Dependencies missing or incomplete. Running setup.sh..."
    chmod +x setup.sh
    ./setup.sh
    if [ $? -ne 0 ]; then
        echo "[ERROR] Setup failed. Please check the errors above."
        exit 1
    fi
fi

# 2. Cleanup Stale Processes
echo "[+] Purging stale processes..."
./stop.sh > /dev/null 2>&1

# 3. Start Redis
echo "[+] Checking Redis Server..."
if ! pgrep redis-server > /dev/null; then
    echo "[!] Redis is not running. Attempting to start..."
    sudo -n service redis-server start 2>/dev/null || echo "[WARN] Could not start Redis. Ensure it is installed: sudo apt install redis-server"
fi

# 4. Start Suricata
EVE_LOG="/var/log/suricata/eve.json"
echo "[+] Checking Core IDS Sensor (Suricata)..."
if ! pgrep suricata > /dev/null; then
    echo "[!] Suricata process not found."
    echo "    To start manually: sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -D"
else
    echo "[OK] Suricata is running."
fi

if [ ! -f "$EVE_LOG" ]; then
    echo "[WARN] EVE log not found at $EVE_LOG. Check Suricata configuration."
fi

# 5. Port conflict detection
source .venv/bin/activate
mkdir -p data/logs

# Load ports from config.py or use defaults
WS_PORT=$(python3 -c "from src.common.config import WS_PORT; print(WS_PORT)")
FLASK_PORT=5000

echo "[+] Checking for port conflicts on ${WS_PORT} and ${FLASK_PORT}..."
for PORT in $WS_PORT $FLASK_PORT; do
    # Try to find PID
    PID=$(fuser ${PORT}/tcp 2>/dev/null | awk '{print $1}')
    if [ -n "$PID" ]; then
        echo "[!] Port ${PORT} occupied by PID ${PID}. Attempting to free..."
        kill "$PID" 2>/dev/null
        sleep 1
        # Check again
        PID=$(fuser ${PORT}/tcp 2>/dev/null | awk '{print $1}')
        if [ -n "$PID" ]; then
            echo "[!] Port ${PORT} still occupied. Attempting SIGKILL..."
            kill -9 "$PID" 2>/dev/null
        fi
        
        # Final check - if still occupied, it might be a root process
        PID=$(fuser ${PORT}/tcp 2>/dev/null | awk '{print $1}')
        if [ -n "$PID" ]; then
            echo "[CRITICAL] Port ${PORT} is occupied by an unkillable process (PID: ${PID})."
            echo "           This usually happens if a process was started as root."
            echo "           Please run: sudo kill -9 ${PID}"
            exit 1
        fi
    fi
done

# 6. Start ML Consumer
echo "[+] Launching ML Engine (Consumer)..."
# Clear stale log
> data/logs/consumer.log
python3 src/ml_engine/consumer.py > data/logs/consumer.log 2>&1 &
CONSUMER_PID=$!

# Wait for ML Engine internal WebSocket to bind
echo "[*] Waiting for pipeline at 127.0.0.1:${WS_PORT} (timeout 45s)..."
python3 scripts/wait_for_pipeline.py --host 127.0.0.1 --port ${WS_PORT} --timeout 45
if [ $? -ne 0 ]; then
    echo "[ERROR] Pipeline failed to start."
    echo "        Check data/logs/consumer.log for details."
    # Show last few lines of consumer log for quick debugging
    echo "--- Last log entries ---"
    tail -n 10 data/logs/consumer.log
    kill $CONSUMER_PID 2>/dev/null
    exit 1
fi

# 7. Start Flask Relay
echo "[+] Launching Flask Dashboard Backend..."
export FLASK_APP=src/dashboard/app.py
export FLASK_ENV=development
python3 -m flask run -h 0.0.0.0 -p ${FLASK_PORT} > data/logs/relay.log 2>&1 &

# Wait for Flask
python3 scripts/wait_for_pipeline.py --host 127.0.0.1 --port ${FLASK_PORT} --timeout 30

# 8. Start React Dashboard
echo "[+] Launching Sentinel Core Dashboard (React)..."
cd ui
nohup npm run dev -- --host 0.0.0.0 --port 3000 > ../data/logs/ui.log 2>&1 &
cd ..

echo "================================================================="
echo "[SUCCESS] Sentinel Core is now ACTIVE."
echo "================================================================="
echo "[SERVICES]"
echo "- Dashboard:      http://127.0.0.1:3000"
echo "- WebSocket API:  ws://127.0.0.1:${WS_PORT}"
echo "- Flask Relay:    http://127.0.0.1:5000"
echo "- Core Logs:      tail -f data/logs/consumer.log"
echo "================================================================="

# Only tail logs if we are in an interactive terminal
if [ -t 1 ]; then
    echo "Press Ctrl+C to stop the system, or run ./stop.sh in another terminal."
    tail -f data/logs/consumer.log
fi
