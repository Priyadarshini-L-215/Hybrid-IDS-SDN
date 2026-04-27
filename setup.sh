#!/bin/bash
# setup.sh - Unified Sentinel Core Setup for Native Linux (Ubuntu)
set -e

echo "================================================================="
echo "            SENTINEL CORE: SYSTEM INSTALLER"
echo "================================================================="

# Function to check if a command exists
exists() {
  command -v "$1" >/dev/null 2>&1
}

# 1. Install System Packages
echo "[+] Checking system dependencies..."
MISSING_PKGS=""
for pkg in suricata redis-server nmap nftables iptables python3-pip python3-venv curl build-essential psmisc; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        MISSING_PKGS="$MISSING_PKGS $pkg"
    fi
done

if [ -n "$MISSING_PKGS" ]; then
    echo "[+] Installing missing packages: $MISSING_PKGS"
    sudo apt-get update
    sudo apt-get install -y software-properties-common
    sudo add-apt-repository -y ppa:oisf/suricata-stable
    sudo apt-get update
    sudo apt-get install -y $MISSING_PKGS
else
    echo "[OK] All system packages are already installed."
fi

# 2. Install Node.js 20+
if ! exists node; then
    echo "[+] Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
else
    NODE_VER=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VER" -lt 20 ]; then
        echo "[!] Node.js version $NODE_VER is too old. Upgrading..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
        sudo apt-get install -y nodejs
    else
        echo "[OK] Node.js is already installed ($(node -v))."
    fi
fi

# 3. Create Python Virtual Environment
echo "[+] Setting up Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "[OK] .venv created."
fi

source .venv/bin/activate
echo "[+] Upgrading pip and installing requirements..."
pip install --upgrade pip
pip install -r requirements.txt

# 4. Install UI Dependencies
echo "[+] Checking React UI dependencies..."
if [ ! -d "ui/node_modules" ]; then
    echo "[+] Installing node_modules in /ui..."
    cd ui
    npm install
    cd ..
else
    echo "[OK] node_modules already present."
fi

# 5. Suricata Configuration & Rules
echo "[+] Configuring Suricata..."
sudo cp config/suricata/suricata.yaml /etc/suricata/suricata.yaml || echo "[WARN] Could not copy suricata.yaml"
sudo mkdir -p /var/lib/suricata/rules/
sudo cp config/suricata/signatures.rules /var/lib/suricata/rules/local.rules || echo "[WARN] Could not copy signatures.rules"

# Initialize Suricata rules
if exists suricata-update; then
    echo "[+] Updating Suricata rules..."
    sudo suricata-update || echo "[WARN] suricata-update failed"
fi

# 6. Service Management
echo "[+] Enabling services..."
sudo systemctl enable suricata 2>/dev/null || true
sudo systemctl enable redis-server 2>/dev/null || true
sudo service redis-server start 2>/dev/null || true

echo "================================================================="
echo "[SUCCESS] Sentinel Core setup is COMPLETE!"
echo "To start the system, run: ./start.sh"
echo "================================================================="
