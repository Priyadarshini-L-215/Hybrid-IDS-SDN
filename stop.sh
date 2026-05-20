#!/bin/bash
# stop.sh - Sentinel Core Graceful Shutdown

set -euo pipefail

echo "================================================================="
echo "            SENTINEL CORE: GRACEFUL SHUTDOWN"
echo "================================================================="

# Ensure sudo is cached for stopping root services
sudo -v || echo "[!] Warning: Sudo authentication failed. Some services may not stop."
PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_FILE="$PROJECT_ROOT/.sentinel_state"
LOCK_FILE="$PROJECT_ROOT/.sentinel.lock"

# Stop supervisor loop if it's running
if [ -f "$LOCK_FILE" ]; then
	START_PID=$(cat "$LOCK_FILE" 2>/dev/null || true)
	# Make sure we don't kill ourselves if start.sh's trap called this script
	if [ -n "$START_PID" ] && [ "$START_PID" != "$PPID" ] && kill -0 "$START_PID" 2>/dev/null; then
		echo "[+] Stopping Supervisor Loop (PID: $START_PID)..."
		kill -TERM "$START_PID" 2>/dev/null || true
		sleep 1
	fi
fi

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
			suricata_pid) stop_pid "$value" "Suricata Sensor" ;;
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
pkill -f "dionaea" || true

echo "[+] Stopping Relay API (FastAPI)..."
pkill -f "relay.app:app" || true
pkill -f "uvicorn.*relay.app" || true

echo "[+] Stopping Dashboard UI (Vite)..."
pkill -f "npm.*dev" || true
pkill -f "vite" || true
pkill -f "vite.js" || true

echo "[+] Stopping Suricata Sensor..."
sudo pkill -f suricata 2>/dev/null || true

echo "[+] Stopping Redis Server..."
sudo systemctl stop redis-server 2>/dev/null || true
sudo service redis-server stop 2>/dev/null || true

echo "[+] Stopping any lingering Python/Testing processes..."
pkill -f ".venv/bin/python" || true
pkill -f "pytest" || true

echo "[+] Cleaning up Network Infrastructure (SDN)..."
sudo ovs-vsctl del-br br-sentinel 2>/dev/null || true
sudo ip netns del honeypot 2>/dev/null || true

echo "[+] Cleaning up Mitigation Rules (Ipset/Iptables)..."
sudo iptables -D FORWARD -j SENTINEL_IPS 2>/dev/null || true
sudo iptables -D INPUT -j SENTINEL_IPS 2>/dev/null || true
sudo iptables -F SENTINEL_IPS 2>/dev/null || true
sudo iptables -X SENTINEL_IPS 2>/dev/null || true
sudo ipset destroy sentinel_blocks 2>/dev/null || true

echo "[+] Cleaning up sockets and locks..."
rm -f "$PROJECT_ROOT/.sentinel.lock" "$PROJECT_ROOT/.sentinel_state" || true
sudo rm -f /var/run/suricata.pid 2>/dev/null || true

echo "================================================================="
echo "[SUCCESS] Sentinel Core fully terminated and cleaned."
echo "================================================================="
