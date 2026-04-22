#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$SCRIPT_DIR}"
USE_REDIS_QUEUE="${USE_REDIS_QUEUE:-1}"

if [ ! -d "$PROJECT_ROOT" ]; then
    echo "[IDS] ERROR: PROJECT_ROOT '$PROJECT_ROOT' does not exist."
    exit 1
fi

cd "$PROJECT_ROOT"

echo "================================================"
echo "  Sentinel Core IDS - WSL Pipeline Launcher"
echo "================================================"
if [ "$USE_REDIS_QUEUE" = "1" ]; then
    echo "  Mode: Redis Queue Pipeline (Optimized)"
else
    echo "  Mode: Legacy Polling (Compatibility)"
fi
echo "================================================"
echo

echo "[IDS] Environment Setup..."
# Check for dependencies
python3 -c "import websockets, pandas, sklearn" 2>/dev/null || {
    echo "[IDS] Missing Python dependencies. Installing..."
    pip3 install websockets pandas scikit-learn
}

if [ "$USE_REDIS_QUEUE" = "1" ]; then
    # Check for Redis Python client
    python3 -c "import redis" 2>/dev/null || {
        echo "[IDS] Installing Redis Python client..."
        pip3 install redis
    }
fi

echo "[IDS] Checking Redis..."
redis-cli ping >/dev/null 2>&1 || {
    echo "[IDS] Redis not running; starting..."
    if command -v redis-server >/dev/null 2>&1; then
        redis-server --daemonize yes --logfile /var/log/redis/redis-server.log
        sleep 1
        if redis-cli ping >/dev/null 2>&1; then
            echo "[IDS] Redis started successfully"
        else
            echo "[IDS] WARNING: Redis start failed but continuing anyway..."
        fi
    else
        echo "[IDS] WARNING: Redis not installed."
        if [ "$USE_REDIS_QUEUE" = "1" ]; then
            echo "[IDS] Falling back to legacy polling mode..."
            export USE_REDIS_QUEUE=0
        fi
    fi
}

echo "[IDS] Ensuring Suricata is active..."
systemctl is-active --quiet suricata || systemctl start suricata
chmod 666 /var/log/suricata/eve.json 2>/dev/null || true

echo "[IDS] Cleaning up old processes..."
pkill -f "consumer.py" 2>/dev/null || true
# Kill anything explicitly holding our ports
if command -v fuser >/dev/null 2>&1; then
    fuser -k 8999/tcp 5001/tcp 2>/dev/null || true
fi
sleep 1

echo "[IDS] Truncating old logs for fresh start..."
mkdir -p data/logs
rm -f data/logs/.consumer_ready 2>/dev/null || true
> data/logs/consumer.log

echo "[IDS] Starting ML consumer..."
if [ "$USE_REDIS_QUEUE" = "1" ]; then
    echo "[IDS] Pipeline: Redis Queue"
else
    echo "[IDS] Pipeline: Legacy Polling"
fi
echo

# PYTHONUNBUFFERED=1 ensures we see logs in consumer.log immediately
# Export mode for consumer to pick up
export USE_REDIS_QUEUE="$USE_REDIS_QUEUE"

PYTHONUNBUFFERED=1 nohup python3 src/ml_engine/consumer.py >> data/logs/consumer.log 2>&1 &
CPID=$!

echo "[IDS] Waiting for consumer to initialize..."
sleep 3

# Check if process is still running
if ! ps -p $CPID > /dev/null 2>&1; then
    echo "[IDS] ERROR: Consumer process died immediately (PID $CPID not found)"
    echo "[IDS] Last 50 lines of log:"
    tail -n 50 data/logs/consumer.log
    exit 1
fi

echo "[IDS] Consumer process running (PID $CPID)"

# Verify WebSocket server is actually listening
echo "[IDS] Verifying WebSocket server is listening..."
MAX_ATTEMPTS=10
ATTEMPT=0
WS_READY=0

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    # Try to connect to WebSocket port
    if ss -tlnp 2>/dev/null | grep -q ":8999"; then
        echo "[IDS] WebSocket server is listening on port 8999"
        WS_READY=1
        break
    fi
    
    ATTEMPT=$((ATTEMPT + 1))
    if [ $ATTEMPT -lt $MAX_ATTEMPTS ]; then
        echo "[IDS] WebSocket not ready yet ($ATTEMPT/$MAX_ATTEMPTS)... waiting 1s"
        sleep 1
    fi
done

if [ $WS_READY -eq 0 ]; then
    echo "[IDS] WARNING: WebSocket server not listening after $MAX_ATTEMPTS seconds"
    echo "[IDS] [DIAG] Netstat check:"
    ss -tlnp | grep -E "8999|5001" || echo "  (not listening)"
    echo "[IDS] [DIAG] Consumer log tail (last 30 lines):"
    tail -n 30 data/logs/consumer.log
    echo "[IDS] [DIAG] Checking for specific errors:"
    grep -iE "error|exception|traceback|failed|critical" data/logs/consumer.log | tail -n 10
fi

# Final status
if ps -p $CPID > /dev/null 2>&1; then
    echo "[IDS] Consumer running (PID $CPID)"
    echo "[IDS] WebSocket: ws://0.0.0.0:8999"
    echo "[IDS] Logs: $PROJECT_ROOT/data/logs/consumer.log"
    echo
    if [ $WS_READY -eq 1 ]; then
        echo "[SUCCESS] IDS Pipeline Online and Ready"
        touch data/logs/.consumer_ready
    else
        echo "[WARNING] IDS Pipeline Online but WebSocket not responding yet"
        echo "[WARNING] Flask relay may fail - check consumer logs"
        rm -f data/logs/.consumer_ready 2>/dev/null || true
    fi
    echo
else
    rm -f data/logs/.consumer_ready 2>/dev/null || true
    echo "[IDS] ERROR: Consumer process died after initialization"
    echo "[IDS] Last 50 lines of log:"
    tail -n 50 data/logs/consumer.log
    exit 1
fi