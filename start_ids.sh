#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$SCRIPT_DIR}"
USE_REDIS_QUEUE="${USE_REDIS_QUEUE:-1}"
LOG_DIR="data/logs"
CONSUMER_LOG="$LOG_DIR/consumer.log"
CONSUMER_READY="$LOG_DIR/.consumer_ready"
PIPELINE_BANNER_MODE="Legacy Polling (Compatibility)"
PIPELINE_LOG_MODE="Legacy Polling"

if [ "$USE_REDIS_QUEUE" = "1" ]; then
    PIPELINE_BANNER_MODE="Redis Queue Pipeline (Optimized)"
    PIPELINE_LOG_MODE="Redis Queue"
fi

if [ ! -d "$PROJECT_ROOT" ]; then
    echo "[IDS] ERROR: PROJECT_ROOT '$PROJECT_ROOT' does not exist."
    exit 1
fi

cd "$PROJECT_ROOT"

echo "================================================"
echo "  Sentinel Core IDS - WSL Pipeline Launcher"
echo "================================================"
echo "  Mode: $PIPELINE_BANNER_MODE"
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
(service suricata status >/dev/null 2>&1) || sudo service suricata start
sudo chmod 666 /var/log/suricata/eve.json 2>/dev/null || true

echo "[IDS] Cleaning up old processes..."
pkill -f "consumer.py" 2>/dev/null || true
# Kill anything explicitly holding our ports
if command -v fuser >/dev/null 2>&1; then
    fuser -k 8765/tcp 5001/tcp 2>/dev/null || true
fi
sleep 1

echo "[IDS] Truncating old logs for fresh start..."
mkdir -p "$LOG_DIR"
rm -f "$CONSUMER_READY" 2>/dev/null || true
> "$CONSUMER_LOG"

echo "[IDS] Starting ML consumer..."
echo "[IDS] Pipeline: $PIPELINE_LOG_MODE"
echo

# PYTHONUNBUFFERED=1 ensures we see logs in consumer.log immediately
# Export mode for consumer to pick up
export USE_REDIS_QUEUE="$USE_REDIS_QUEUE"

PYTHONUNBUFFERED=1 nohup python3 src/ml_engine/consumer.py >> "$CONSUMER_LOG" 2>&1 &
CPID=$!

echo "[IDS] Waiting for consumer to initialize..."
sleep 3

# Check if process is still running
if ! ps -p $CPID > /dev/null 2>&1; then
    echo "[IDS] ERROR: Consumer process died immediately (PID $CPID not found)"
    echo "[IDS] Last 50 lines of log:"
    tail -n 50 "$CONSUMER_LOG"
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
    if ss -tlnp 2>/dev/null | grep -q ":8765"; then
        echo "[IDS] WebSocket server is listening on port 8765"
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
    ss -tlnp | grep -E "8765|5001" || echo "  (not listening)"
    echo "[IDS] [DIAG] Consumer log tail (last 30 lines):"
    tail -n 30 "$CONSUMER_LOG"
    echo "[IDS] [DIAG] Checking for specific errors:"
    grep -iE "error|exception|traceback|failed|critical" "$CONSUMER_LOG" | tail -n 10
fi

# Final status
if ps -p $CPID > /dev/null 2>&1; then
    echo "[IDS] Consumer running (PID $CPID)"
    echo "[IDS] WebSocket: ws://0.0.0.0:8765"
    echo "[IDS] Logs: $PROJECT_ROOT/$CONSUMER_LOG"
    echo
    if [ $WS_READY -eq 1 ]; then
        echo "[SUCCESS] IDS Pipeline Online and Ready"
        touch "$CONSUMER_READY"
    else
        echo "[WARNING] IDS Pipeline Online but WebSocket not responding yet"
        echo "[WARNING] Flask relay may fail - check consumer logs"
        rm -f "$CONSUMER_READY" 2>/dev/null || true
    fi
    echo
else
    rm -f "$CONSUMER_READY" 2>/dev/null || true
    echo "[IDS] ERROR: Consumer process died after initialization"
    echo "[IDS] Last 50 lines of log:"
    tail -n 50 "$CONSUMER_LOG"
    exit 1
fi