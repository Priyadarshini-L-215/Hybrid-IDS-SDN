#!/bin/bash
# diag.sh - Sentinel Core Diagnostics (Native Linux)

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
check_process "flask run" "Flask Relay"
check_process "vite" "React UI"

echo ""
echo "[+] Checking Ports..."
check_port 6379 "Redis"
check_port 8765 "Consumer WebSocket"
check_port 5000 "Flask Relay API"
check_port 3000 "React UI"

echo ""
echo "[+] Checking Virtual Environment..."
if [ -d ".venv" ]; then
    echo -e "[\e[32mOK\e[0m] .venv exists"
    source .venv/bin/activate
    if python -c "import torch, sklearn, flask" >/dev/null 2>&1; then
         echo -e "[\e[32mOK\e[0m] Core python dependencies installed"
    else
         echo -e "[\e[31mFAIL\e[0m] Missing python dependencies (run ./setup.sh)"
    fi
else
    echo -e "[\e[31mFAIL\e[0m] .venv not found (run ./setup.sh)"
fi

echo "================================================================="
