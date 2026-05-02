#!/bin/bash
# preflight.sh - Pre-flight Validation for Sentinel Core
# Verifies system is ready for setup or startup

set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$PROJECT_ROOT"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

FAILED=0
WARNINGS=0

# Helper functions
check_command() {
    if command -v "$1" &>/dev/null; then
        echo -e "${GREEN}✓${NC} Found: $1"
        return 0
    else
        echo -e "${RED}✗${NC} Missing: $1"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

check_python_version() {
    if ! command -v python3 &>/dev/null; then
        echo -e "${RED}✗${NC} Python 3 not found"
        FAILED=$((FAILED + 1))
        return 1
    fi

    local version=$(python3 --version 2>&1 | awk '{print $2}')
    local major=$(echo "$version" | cut -d. -f1)
    local minor=$(echo "$version" | cut -d. -f2)

    if [ "$major" -lt 3 ] || ([ "$major" -eq 3 ] && [ "$minor" -lt 10 ]); then
        echo -e "${RED}✗${NC} Python 3.10+ required, found: $version"
        FAILED=$((FAILED + 1))
        return 1
    else
        echo -e "${GREEN}✓${NC} Python version: $version"
        return 0
    fi
}

check_node_version() {
    if ! command -v node &>/dev/null; then
        echo -e "${RED}✗${NC} Node.js not found"
        FAILED=$((FAILED + 1))
        return 1
    fi

    local version=$(node --version 2>&1 | cut -dv -f2)
    local major=$(echo "$version" | cut -d. -f1)

    if [ "$major" -lt 20 ]; then
        echo -e "${RED}✗${NC} Node.js 20+ required, found: $version"
        FAILED=$((FAILED + 1))
        return 1
    else
        echo -e "${GREEN}✓${NC} Node.js version: $version"
        return 0
    fi
}

check_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}✓${NC} File exists: $1"
        return 0
    else
        echo -e "${RED}✗${NC} File missing: $1"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

check_directory() {
    if [ -d "$1" ]; then
        echo -e "${GREEN}✓${NC} Directory exists: $1"
        return 0
    else
        echo -e "${YELLOW}⚠${NC} Directory missing (will be created): $1"
        WARNINGS=$((WARNINGS + 1))
        return 1
    fi
}

check_writable() {
    local dir=$1
    if [ -d "$dir" ] && [ -w "$dir" ]; then
        echo -e "${GREEN}✓${NC} Directory writable: $dir"
        return 0
    elif [ ! -d "$dir" ]; then
        echo -e "${YELLOW}⚠${NC} Directory doesn't exist yet (will be created): $dir"
        WARNINGS=$((WARNINGS + 1))
        return 0
    else
        echo -e "${RED}✗${NC} Directory not writable: $dir"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

check_disk_space() {
    local available=$(df . | tail -1 | awk '{print $4}')
    local available_gb=$((available / 1048576))
    local required_gb=5

    if [ "$available_gb" -lt "$required_gb" ]; then
        echo -e "${RED}✗${NC} Low disk space: ${available_gb}GB available (${required_gb}GB+ required)"
        FAILED=$((FAILED + 1))
        return 1
    else
        echo -e "${GREEN}✓${NC} Disk space: ${available_gb}GB available"
        return 0
    fi
}

check_model_files() {
    local missing=0
    local models=("models/autoencoder.pth" "models/rf_model.pkl" "models/features.json")
    
    for model in "${models[@]}"; do
        if [ -f "$model" ]; then
            echo -e "${GREEN}✓${NC} Model file: $model"
        else
            echo -e "${YELLOW}⚠${NC} Model file missing: $model (needed for ML engine)"
            missing=$((missing + 1))
        fi
    done
    
    if [ $missing -gt 0 ]; then
        echo -e "${YELLOW}  (Models can be trained, but inference will fail without them)${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi
}

check_config_files() {
    if [ -f "config/sentinel_config.yaml" ]; then
        echo -e "${GREEN}✓${NC} Config file found: config/sentinel_config.yaml"
    else
        echo -e "${YELLOW}⚠${NC} Config file missing: config/sentinel_config.yaml (will use defaults)"
        WARNINGS=$((WARNINGS + 1))
    fi
}

check_sudo_privilege() {
    if sudo -n true 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Sudo access (no password prompt)"
    else
        echo -e "${YELLOW}⚠${NC} Sudo access available but may prompt for password"
        echo -e "${YELLOW}  To enable passwordless sudo for specific commands:${NC}"
        echo -e "${YELLOW}  sudo visudo${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi
}

check_internet() {
    if ping -c 1 8.8.8.8 &>/dev/null; then
        echo -e "${GREEN}✓${NC} Internet connectivity"
    else
        echo -e "${RED}✗${NC} No internet connectivity (required for package downloads)"
        FAILED=$((FAILED + 1))
    fi
}

# Main execution
main() {
    echo "======================================================================="
    echo "           SENTINEL CORE - PRE-FLIGHT VALIDATION"
    echo "======================================================================="
    echo ""

    echo "[+] Checking Required Binaries..."
    check_command python3
    check_command node
    check_command npm
    check_command git
    check_command curl
    check_command sudo
    check_command hping3
    check_command nmap
    
    echo "[+] Checking Python ML Dependencies..."
    python3 -c "import river" 2>/dev/null && echo -e "${GREEN}✓${NC} Found: river (drift detection)" || echo -e "${YELLOW}⚠${NC} Missing: river (drift detection will be disabled)"
    echo ""

    echo "[+] Checking Versions..."
    check_python_version
    check_node_version
    echo ""

    echo "[+] Checking File Structure..."
    check_file "setup.sh"
    check_file "start.sh"
    check_file "stop.sh"
    check_file "diag.sh"
    check_file "dev.sh"
    check_file "sdn_setup.sh"
    check_file "requirements.txt"
    check_file "ui/package.json"
    check_directory "config"
    check_directory "models"
    echo ""

    echo "[+] Checking Permissions..."
    check_writable "data/logs"
    check_writable "data"
    echo ""

    echo "[+] Checking Resources..."
    check_disk_space
    check_internet
    echo ""

    echo "[+] Checking Data Files..."
    check_model_files
    check_config_files
    echo ""

    echo "[+] Checking System Configuration..."
    check_sudo_privilege
    echo ""

    echo "======================================================================="
    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}[SUCCESS] All pre-flight checks passed!${NC}"
        if [ $WARNINGS -gt 0 ]; then
            echo -e "${YELLOW}[WARNINGS] $WARNINGS non-critical issues found${NC}"
        fi
        echo ""
        echo "Ready to run: ./setup.sh"
        return 0
    else
        echo -e "${RED}[FAILED] $FAILED critical issue(s) found${NC}"
        echo ""
        echo "Please resolve the issues above before proceeding."
        return 1
    fi
}

main "$@"
