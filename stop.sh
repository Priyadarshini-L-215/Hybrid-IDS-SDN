#!/bin/bash
# stop.sh - Sentinel Core Graceful Shutdown

echo "================================================================="
echo "            SENTINEL CORE: GRACEFUL SHUTDOWN"
echo "================================================================="
PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

echo "[+] Stopping ML Consumer..."
pkill -f "consumer.py" || true
sleep 1
pkill -9 -f "consumer.py" || true

echo "[+] Stopping Ingestion Service..."
pkill -f "ingestion.py" || true
sleep 0.5
pkill -9 -f "ingestion.py" || true

echo "[+] Stopping Relay API (FastAPI)..."
pkill -f "src.relay.app" || true
pkill -f "uvicorn" || true
sleep 0.5
pkill -9 -f "src.relay.app" || true
pkill -9 -f "uvicorn" || true

echo "[+] Stopping Dashboard UI (Vite)..."
pkill -f "npm.*dev" || true
pkill -f "vite" || true
sleep 0.5
pkill -9 -f "npm.*dev" || true
pkill -9 -f "vite" || true

echo "[+] Stopping Suricata Sensor..."
sudo -n pkill suricata 2>/dev/null || true

echo "[+] Stopping Redis Server..."
sudo -n service redis-server stop 2>/dev/null || true
 
echo "[+] Cleaning up sockets and locks..."
rm -f "$PROJECT_ROOT/.sentinel.lock" "$PROJECT_ROOT/.sentinel_state" || true
python3 -c "from src.common.config import SURICATA_SOCKET; import os; os.remove(str(SURICATA_SOCKET)) if os.path.exists(str(SURICATA_SOCKET)) else None" 2>/dev/null || true

echo "================================================================="
echo "[SUCCESS] Sentinel Core stopped."
echo "================================================================="
