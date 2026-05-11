#!/bin/bash
# diag.sh - Sentinel Core Diagnostics (Native Linux Optimized)

set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
APP_PYTHON="$PROJECT_ROOT/.venv/bin/python"

echo "================================================================="
echo "            SENTINEL CORE DIAGNOSTICS"
echo "================================================================="

# Color codes
GREEN='\e[32m'
RED='\e[31m'
YELLOW='\e[33m'
RESET='\e[0m'

check_process() {
    if pgrep -f "$1" > /dev/null; then
        echo -e "[${GREEN}OK${RESET}] Process running: $2"
    else
        echo -e "[${RED}FAIL${RESET}] Process stopped: $2"
    fi
}

check_port() {
    if nc -z 127.0.0.1 "$1" 2>/dev/null; then
        echo -e "[${GREEN}OK${RESET}] Port $1 open: $2"
    else
        echo -e "[${RED}FAIL${RESET}] Port $1 closed: $2"
    fi
}

echo "[+] Checking Services..."
check_process "suricata" "Suricata IDS"
check_process "src/ml_engine/ingestion.py" "Ingestion Bridge"
check_process "redis-server" "Redis Queue"
check_process "src/ml_engine/consumer.py" "ML Consumer"
check_process "relay.app:app" "Relay API (FastAPI)"
check_process "uvicorn.*relay.app" "Relay API (FastAPI)"
check_process "npm" "React UI"

echo ""
echo "[+] Checking Liveness Heartbeats..."
HEARTBEAT_FILE="$PROJECT_ROOT/data/logs/heartbeat.jsonl"
if [ -f "$HEARTBEAT_FILE" ]; then
    HB_MOD=$(stat -c %Y "$HEARTBEAT_FILE")
    HB_NOW=$(date +%s)
    HB_DIFF=$((HB_NOW - HB_MOD))
    if [ $HB_DIFF -lt 30 ]; then
        echo -e "[${GREEN}OK${RESET}] ML Consumer heartbeat is fresh (${HB_DIFF}s ago)"
    else
        echo -e "[${RED}FAIL${RESET}] ML Consumer heartbeat STALE (${HB_DIFF}s ago)"
    fi
else
    echo -e "[${RED}FAIL${RESET}] ML Consumer heartbeat file missing"
fi

echo ""
echo "[+] Checking Model Assets..."
check_model() {
    if [ -f "$PROJECT_ROOT/models/$1" ]; then
        echo -e "[${GREEN}OK${RESET}] Model asset found: $1"
    else
        echo -e "[${YELLOW}WARN${RESET}] Model asset missing: $1"
    fi
}
check_model "rf_multi_pipeline.onnx"
check_model "scaler_multi.pkl"
check_model "vae_encoder.keras"
check_model "vae_decoder.keras"
check_model "vae_scaler.pkl"
check_model "feature_order.json"

echo ""
echo "[+] Checking Ports..."
check_port 6379 "Redis"

API_PORT=$($APP_PYTHON -c "import sys; sys.path.insert(0, '$PROJECT_ROOT/src'); from common.config import API_PORT; print(API_PORT)" 2>/dev/null || echo 5000)
UI_PORT=$($APP_PYTHON -c "import sys; sys.path.insert(0, '$PROJECT_ROOT/src'); from common.config import UI_PORT; print(UI_PORT)" 2>/dev/null || echo 3000)

check_port "$API_PORT" "Relay API & WebSocket"
check_port "$UI_PORT" "React UI"

echo ""
echo "[+] Checking Redis Streams..."
STREAM_LAG=$(redis-cli xlen sentinel_alerts_stream 2>/dev/null || echo "0")
echo -e "[${GREEN}INFO${RESET}] sentinel_alerts_stream depth: $STREAM_LAG"
QUEUE_DEPTH=$(redis-cli xlen sentinel_alerts_queue 2>/dev/null || echo "0")
echo -e "[${GREEN}INFO${RESET}] sentinel_alerts_queue depth: $QUEUE_DEPTH"
LAG=$(redis-cli xinfo groups sentinel_alerts_queue 2>/dev/null | grep -A 1 "lag" | tail -n 1 | awk '{print $1}' || echo "0")
echo -e "[${GREEN}INFO${RESET}] Consumer Group Lag: $LAG"

echo ""
echo "[+] Checking Firewall & Mitigation (IPv4)..."
if sudo ipset list sentinel_blocks > /dev/null 2>&1; then
    BLOCK_COUNT=$(sudo ipset list sentinel_blocks | grep "Number of entries:" | awk '{print $4}')
    echo -e "[${GREEN}OK${RESET}] Ipset 'sentinel_blocks' active ($BLOCK_COUNT entries)"
else
    echo -e "[${RED}FAIL${RESET}] Ipset 'sentinel_blocks' NOT found"
fi

if sudo iptables -L SENTINEL_IPS -n > /dev/null 2>&1; then
    echo -e "[${GREEN}OK${RESET}] Iptables chain 'SENTINEL_IPS' is active"
else
    echo -e "[${RED}FAIL${RESET}] Iptables chain 'SENTINEL_IPS' NOT found"
fi

echo ""
echo "[+] Checking Firewall & Mitigation (IPv6)..."
if sudo ipset list sentinel_blocks_v6 > /dev/null 2>&1; then
    BLOCK_COUNT_V6=$(sudo ipset list sentinel_blocks_v6 | grep "Number of entries:" | awk '{print $4}')
    echo -e "[${GREEN}OK${RESET}] Ipset 'sentinel_blocks_v6' active ($BLOCK_COUNT_V6 entries)"
else
    echo -e "[${YELLOW}WARN${RESET}] Ipset 'sentinel_blocks_v6' NOT found"
fi

if sudo ip6tables -L SENTINEL_IPS -n > /dev/null 2>&1; then
    echo -e "[${GREEN}OK${RESET}] Ip6tables chain 'SENTINEL_IPS' is active"
else
    echo -e "[${YELLOW}WARN${RESET}] Ip6tables chain 'SENTINEL_IPS' NOT found"
fi

echo ""
echo "[+] Checking SDN Infrastructure..."
SDN_ENABLED=$($APP_PYTHON -c "import sys; sys.path.insert(0, '$PROJECT_ROOT/src'); from common.config import SDN_ENABLED; print(str(SDN_ENABLED).lower())" 2>/dev/null || echo "false")
if [ "$SDN_ENABLED" == "true" ]; then
    check_process "ryu-manager" "Ryu Controller"
    check_port 8080 "Ryu REST API"
    if ip netns list | grep -q "honeypot"; then
        echo -e "[${GREEN}OK${RESET}] SDN Namespace 'honeypot' exists"
    else
        echo -e "[${RED}FAIL${RESET}] SDN Namespace 'honeypot' MISSING"
    fi
else
    echo -e "[${YELLOW}INFO${RESET}] SDN Infrastructure disabled in config"
fi

echo ""
echo "[+] Checking Data Integrity..."
EVE_LOG=$("$PROJECT_ROOT/.venv/bin/python" -c "import sys; sys.path.insert(0,'$PROJECT_ROOT/src'); from common.config import EVE_LOG; print(EVE_LOG)" 2>/dev/null || echo "")
if [ -f "$EVE_LOG" ]; then
    LAST_MOD=$(stat -c %Y "$EVE_LOG")
    NOW=$(date +%s)
    DIFF=$((NOW - LAST_MOD))
    if [ $DIFF -lt 60 ]; then
        echo -e "[${GREEN}OK${RESET}] Suricata log is live (modified ${DIFF}s ago)"
    else
        echo -e "[${YELLOW}WARN${RESET}] Suricata log stale (${DIFF}s ago). Is traffic flowing?"
    fi
else
    echo -e "[${RED}FAIL${RESET}] Suricata log not found at $EVE_LOG"
fi

echo "================================================================="
