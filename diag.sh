#!/bin/bash
# diag.sh - Sentinel Core Diagnostics (Native Linux Optimized)

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
check_process "src.relay.app" "Relay API (FastAPI)"
check_process "npm" "React UI"

echo ""
echo "[+] Checking Ports..."
check_port 6379 "Redis"
# Dynamically get WS port from config
# WebSocket is now integrated into FastAPI on port 5000
check_port 5000 "Relay API & WebSocket"
check_port 3000 "React UI"

echo ""
echo "[+] Checking Redis Streams..."
STREAM_LAG=$(redis-cli xlen sentinel_alerts_stream 2>/dev/null || echo "0")
echo -e "[${GREEN}INFO${RESET}] sentinel_alerts_stream depth: $STREAM_LAG"
QUEUE_DEPTH=$(redis-cli xlen sentinel_alerts_queue 2>/dev/null || echo "0")
echo -e "[${GREEN}INFO${RESET}] sentinel_alerts_queue depth: $QUEUE_DEPTH"
LAG=$(redis-cli xinfo groups sentinel_alerts_queue 2>/dev/null | grep -A 1 "lag" | tail -n 1 | awk '{print $1}' || echo "0")
echo -e "[${GREEN}INFO${RESET}] Consumer Group Lag: $LAG"

echo ""
echo "[+] Checking Firewall & Mitigation..."
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
echo "[+] Checking Data Integrity..."
# Use venv python to avoid structlog import error
PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
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
