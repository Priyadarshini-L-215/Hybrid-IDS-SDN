#!/bin/bash
# stop.sh - Sentinel Core Graceful Shutdown

echo "================================================================="
echo "            SENTINEL CORE: GRACEFUL SHUTDOWN"
echo "================================================================="

echo "[+] Stopping ML Consumer..."
pkill -f "python src/ml_engine/consumer.py" || true

echo "[+] Stopping Flask Relay..."
pkill -f "flask run" || true
pkill -f "python -m flask run" || true

echo "[+] Stopping React UI..."
pkill -f "npm run dev" || true
pkill -f "vite" || true

echo "[+] Stopping Suricata Sensor..."
sudo pkill suricata || true

echo "[+] Stopping Redis Server..."
sudo service redis-server stop || true

echo "================================================================="
echo "[SUCCESS] Sentinel Core stopped."
echo "================================================================="
