#!/bin/bash
# stop.sh - Sentinel Core Graceful Shutdown

echo "================================================================="
echo "            SENTINEL CORE: GRACEFUL SHUTDOWN"
echo "================================================================="
PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

echo "[+] Stopping ML Consumer..."
pkill -f "consumer.py" || true

echo "[+] Stopping Ingestion Service..."
pkill -f "ingestion.py" || true

echo "[+] Stopping Ryu SDN Controller..."
pkill -f "ryu-manager" || true

echo "[+] Stopping Dionaea Honeypot..."
pkill -f "src/sdn/honeypot.py" || true

echo "[+] Stopping Relay API (FastAPI)..."
pkill -f "src.relay.app" || true
pkill -f "uvicorn" || true

echo "[+] Stopping Dashboard UI (Vite)..."
pkill -f "npm.*dev" || true
pkill -f "vite" || true

echo "[+] Stopping Suricata Sensor..."
sudo -n pkill suricata 2>/dev/null || true

echo "[+] Stopping Redis Server..."
sudo -n service redis-server stop 2>/dev/null || true
 
echo "[+] Cleaning up SDN Bridge (Optional)..."
# We don't delete the bridge by default to avoid losing connectivity if it's real hardware,
# but for the demo we might want a cleanup script.
# sudo ovs-vsctl del-br br-sentinel 2>/dev/null || true

echo "[+] Cleaning up sockets and locks..."
rm -f "$PROJECT_ROOT/.sentinel.lock" "$PROJECT_ROOT/.sentinel_state" || true

echo "================================================================="
echo "[SUCCESS] Sentinel Core stopped."
echo "================================================================="
