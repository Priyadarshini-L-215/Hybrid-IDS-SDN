#!/bin/bash
# stop.sh - Sentinel Core Graceful Shutdown

set -euo pipefail

echo "================================================================="
echo "            SENTINEL CORE: GRACEFUL SHUTDOWN"
echo "================================================================="
PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_FILE="$PROJECT_ROOT/.sentinel_state"

stop_pid() {
	local pid=$1
	local label=$2
	if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
		echo "[+] Stopping $label (PID: $pid)..."
		kill "$pid" 2>/dev/null || true
	fi
}

if [ -f "$STATE_FILE" ]; then
	while IFS='=' read -r key value; do
		case "$key" in
			relay_pid) stop_pid "$value" "Relay API" ;;
			consumer_pid) stop_pid "$value" "ML Consumer" ;;
			ingestion_pid) stop_pid "$value" "Ingestion Service" ;;
			honeypot_pid) stop_pid "$value" "Dionaea Honeypot" ;;
			ryu_pid) stop_pid "$value" "Ryu SDN Controller" ;;
			ui_pid) stop_pid "$value" "Dashboard UI" ;;
		esac
	done < "$STATE_FILE"
fi

echo "[+] Stopping ML Consumer..."
pkill -f "src/ml_engine/consumer.py" || true

echo "[+] Stopping Ingestion Service..."
pkill -f "src/ml_engine/ingestion.py" || true

echo "[+] Stopping Ryu SDN Controller..."
pkill -f "ryu-manager" || true

echo "[+] Stopping Dionaea Honeypot..."
pkill -f "src/sdn/honeypot.py" || true

echo "[+] Stopping Relay API (FastAPI)..."
pkill -f "relay.app:app" || true
pkill -f "uvicorn.*relay.app" || true

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
