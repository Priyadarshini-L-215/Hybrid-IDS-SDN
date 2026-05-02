#!/bin/bash
# dev.sh - Sentinel Core Development Launcher
# Starts the backend with uvicorn --reload for hot-reloading

set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
APP_PYTHON="$PROJECT_ROOT/.venv/bin/python"

# 1. Activate venv
if [ -d "$PROJECT_ROOT/.venv" ]; then
    source "$PROJECT_ROOT/.venv/bin/activate"
else
    echo "[!] No .venv found. Run ./setup.sh first."
    exit 1
fi

export PYTHONPATH="$PROJECT_ROOT/src:${PYTHONPATH:-}"

echo "================================================================="
echo "            SENTINEL CORE: DEVELOPMENT MODE"
echo "================================================================="
echo "[+] Starting Relay API with hot-reloading (uvicorn --reload)..."

# Find API_PORT from config
API_PORT=$("$APP_PYTHON" -c "import sys; sys.path.insert(0, '$PROJECT_ROOT/src'); from common.config import API_PORT; print(API_PORT)" 2>/dev/null || echo 5000)

cd "$PROJECT_ROOT"
"$APP_PYTHON" -m uvicorn relay.app:app --host 127.0.0.1 --port "$API_PORT" --reload
