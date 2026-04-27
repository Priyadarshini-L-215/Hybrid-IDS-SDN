#!/bin/bash
# setup.sh - Unified Sentinel Core Setup for Native Linux (WSL Ubuntu)
set -e

echo "[+] Starting Sentinel Core Linux Setup..."

# 1. Install System Packages
echo "[+] Installing system dependencies (requires sudo)..."
sudo apt-get update
sudo apt-get install -y software-properties-common curl build-essential psmisc
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install -y suricata redis-server nmap nftables iptables python3-pip python3-venv

# 2. Install Node.js 20+
if ! command -v node >/dev/null 2>&1; then
    echo "[+] Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
else
    echo "[OK] Node.js is already installed."
fi

# 3. Create Python Virtual Environment
echo "[+] Creating Python virtual environment..."
if [ -d ".venv" ]; then
    echo "    Removing existing .venv..."
    rm -rf .venv
fi
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip

# 4. Install Python Requirements
echo "[+] Installing Python requirements..."
pip install -r requirements.txt

# 5. Install UI Dependencies
echo "[+] Installing React UI dependencies..."
cd ui
npm install
cd ..

echo "[+] Basic Suricata Configuration..."
sudo cp config/suricata/suricata.yaml /etc/suricata/suricata.yaml || true
sudo cp config/suricata/local.rules /var/lib/suricata/rules/local.rules || true
sudo systemctl enable suricata || true
sudo systemctl enable redis-server || true

echo "================================================================="
echo "[SUCCESS] Sentinel Core setup complete!"
echo "Run ./start.sh to launch the system."
echo "================================================================="
