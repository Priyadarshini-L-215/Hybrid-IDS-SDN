#!/bin/bash
# =================================================================
# Sentinel Core: WSL Environment Setup Script
# =================================================================
# This script installs Suricata, Python dependencies, and
# configures the environment for the ML Sensor.
# RUN THIS INSIDE WSL (UBUNTU) AS ROOT OR WITH SUDO.
# =================================================================

set -e

echo "-----------------------------------------------------------------"
echo "         SENTINEL CORE - WSL SENSOR SETUP"
echo "-----------------------------------------------------------------"

# 1. Update & Install System Dependencies
echo "[+] Updating system packages..."
sudo apt-get update -y
sudo apt-get install -y software-properties-common curl git python3-pip python3-venv

# 2. Install Suricata
echo "[+] Installing Suricata IDS/IPS..."
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt-get update -y
sudo apt-get install -y suricata

echo "[+] Configuring Suricata for EVE JSON output..."
# Ensure log directory exists
sudo mkdir -p /var/log/suricata
sudo chmod 777 /var/log/suricata

# 3. Install & Configure Redis
echo "[+] Installing Redis..."
sudo apt-get install -y redis-server redis-tools

echo "[+] Configuring Redis..."
sudo mkdir -p /etc/redis
sudo tee /etc/redis/sentinel-core.conf > /dev/null <<EOF
port 6379
bind 127.0.0.1
maxmemory 512mb
maxmemory-policy allkeys-lru
appendonly yes
appendfilename "redis-aof.aof"
daemonize yes
logfile /var/log/redis/redis-server.log
EOF

sudo mkdir -p /var/log/redis
sudo chown redis:redis /var/log/redis
sudo systemctl restart redis-server
echo "[OK] Redis configured and started"

# 4. Setup Python Environment
echo "[+] Installing Python ML dependencies..."
pip3 install --upgrade pip
pip3 install websockets pandas scikit-learn requests numpy redis

# 5. Configure Firewall (IPS Mode)
echo "[+] Checking firewall (nftables/iptables)..."
if command -v nft >/dev/null; then
    echo "[OK] nftables present for active mitigation."
else
    echo "[!] nftables not found. Installing..."
    sudo apt-get install -y nftables
fi

# 6. Finalize
echo "-----------------------------------------------------------------"
echo "[SUCCESS] WSL Sensor environment is ready."
echo "-----------------------------------------------------------------"
echo "Next Steps:"
echo "1. Run './start_ids.sh' in WSL to launch the sensor."
echo "2. Or use 'start.bat' from Windows for unified launch."
echo "-----------------------------------------------------------------"
