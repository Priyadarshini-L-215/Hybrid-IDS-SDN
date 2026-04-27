#!/bin/bash
# stop.sh - Sentinel Core Graceful Shutdown

echo "================================================================="
echo "            SENTINEL CORE: GRACEFUL SHUTDOWN"
echo "================================================================="

echo "[+] Stopping ML Consumer..."
pkill -f "consumer.py" || true
sleep 1
pkill -9 -f "consumer.py" || true

echo "[+] Stopping Flask Relay..."
pkill -f "flask" || true
sleep 0.5
pkill -9 -f "flask" || true

echo "[+] Stopping React UI..."
pkill -f "npm" || true
pkill -f "vite" || true
sleep 0.5
pkill -9 -f "npm" || true
pkill -9 -f "vite" || true

echo "[+] Stopping Suricata Sensor..."
sudo -n pkill suricata 2>/dev/null || true

echo "[+] Stopping Redis Server..."
sudo -n service redis-server stop 2>/dev/null || true

echo "================================================================="
echo "[SUCCESS] Sentinel Core stopped."
echo "================================================================="
