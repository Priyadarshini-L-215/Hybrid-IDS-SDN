#!/bin/bash
# diag.sh - Sentinel Core Diagnostics (Native Linux Optimized)

echo "================================================================="
echo "            SENTINEL CORE DIAGNOSTICS"
echo "================================================================="

check_process() {
    if pgrep -f "$1" > /dev/null; then
        echo -e "[\e[32mOK\e[0m] Process running: $2"
    else
        echo -e "[\e[31mFAIL\e[0m] Process stopped: $2"
    fi
}

check_port() {
    if nc -z 127.0.0.1 "$1" 2>/dev/null; then
        echo -e "[\e[32mOK\e[0m] Port $1 open: $2"
    else
        echo -e "[\e[31mFAIL\e[0m] Port $1 closed: $2"
    fi
}

echo "[+] Checking Services..."
check_process "suricata" "Suricata IDS"
check_process "redis-server" "Redis Queue"
check_process "src/ml_engine/consumer.py" "ML Consumer"
check_process "flask" "Flask Relay"
check_process "npm" "React UI"

echo ""
echo "[+] Checking Ports..."
check_port 6379 "Redis"
# Dynamically get WS port from config
source .venv/bin/activate
WS_PORT=$(python3 -c "from src.common.config import WS_PORT; print(WS_PORT)")
check_port $WS_PORT "Consumer WebSocket"
check_port 5000 "Flask Relay API"
check_port 3000 "React UI"

echo ""
echo "[+] Checking External Tools..."
if which nmap > /dev/null; then
    echo -e "[\e[32mOK\e[0m] Nmap installed at $(which nmap)"
else
    echo -e "[\e[31mFAIL\e[0m] Nmap not found"
fi

echo ""
echo "[+] Checking Data Flow..."
EVE_LOG="/var/log/suricata/eve.json"
if [ -f "$EVE_LOG" ]; then
    LAST_MOD=$(stat -c %Y "$EVE_LOG")
    NOW=$(date +%s)
    DIFF=$((NOW - LAST_MOD))
    if [ $DIFF -lt 60 ]; then
        echo -e "[\e[32mOK\e[0m] Suricata log is live (modified ${DIFF}s ago)"
    else
        echo -e "[\e[33mWARN\e[0m] Suricata log stale (${DIFF}s ago). Is traffic flowing?"
    fi
else
    echo -e "[\e[31mFAIL\e[0m] Suricata log not found at $EVE_LOG"
fi

echo ""
echo "[+] Checking Virtual Environment..."
if [ -d ".venv" ]; then
    echo -e "[\e[32mOK\e[0m] .venv exists"
    if python3 -c "import torch, sklearn, flask, redis, websockets" >/dev/null 2>&1; then
         echo -e "[\e[32mOK\e[0m] All python dependencies verified"
    else
         echo -e "[\e[31mFAIL\e[0m] Missing python dependencies (run ./setup.sh)"
    fi
else
    echo -e "[\e[31mFAIL\e[0m] .venv not found (run ./setup.sh)"
fi

echo "================================================================="
