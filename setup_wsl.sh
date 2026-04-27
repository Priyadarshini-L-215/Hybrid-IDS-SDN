#!/bin/bash
# =================================================================
# Sentinel Core: WSL Environment Setup Script
# =================================================================
# This script installs Suricata, Python dependencies, and
# configures the environment for the ML Sensor.
# RUN THIS INSIDE WSL (UBUNTU) AS ROOT OR WITH SUDO.
# =================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$SCRIPT_DIR}"

echo "-----------------------------------------------------------------"
echo "         SENTINEL CORE - WSL SENSOR SETUP"
echo "-----------------------------------------------------------------"

# 1. Update & Install System Dependencies
echo "[+] Updating system packages..."
sudo apt-get update -y
sudo apt-get install -y software-properties-common curl git python3-pip python3-venv net-tools iproute2 sqlite3

# 2. Install Suricata
echo "[+] Installing Suricata IDS/IPS..."
if grep -qi "kali" /etc/os-release; then
    echo "[!] Kali Linux detected. Skipping PPA and using official repository..."
    sudo apt-get update -y
    sudo apt-get install -y suricata
else
    echo "[+] Ubuntu/Debian detected. Adding PPA..."
    sudo add-apt-repository -y ppa:oisf/suricata-stable || echo "[!] PPA failed, trying direct install..."
    sudo apt-get update -y
    sudo apt-get install -y suricata
fi

# Initialize Suricata rules
echo "[+] Updating Suricata rules..."
sudo suricata-update || echo "[!] suricata-update failed, skipping..."

echo "[+] Configuring Suricata for EVE JSON output..."
# Ensure log directory exists
sudo mkdir -p /var/log/suricata
sudo chmod 775 /var/log/suricata || true

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
sudo service redis-server restart || sudo /etc/init.d/redis-server restart
echo "[OK] Redis configured and started"

# 4. Setup Python Environment
echo "[+] Installing Python ML dependencies..."
python3 -m pip install --upgrade pip

if [ -f "$PROJECT_ROOT/requirements_wsl.txt" ]; then
    echo "[+] Installing Python dependencies from requirements_wsl.txt..."
    if ! python3 -m pip install -r "$PROJECT_ROOT/requirements_wsl.txt"; then
        echo "[!] Standard pip install failed. Retrying with --break-system-packages..."
        python3 -m pip install --break-system-packages -r "$PROJECT_ROOT/requirements_wsl.txt"
    fi
else
    echo "[WARNING] requirements_wsl.txt not found at $PROJECT_ROOT; installing minimal fallback set"
    python3 -m pip install torch websockets pandas scikit-learn requests numpy redis scapy
fi

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
