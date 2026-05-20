#!/bin/bash
# setup.sh - Unified Sentinel Core Setup for Native Linux
# Features: State tracking, idempotent operations, comprehensive error handling

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SETUP_STATE_FILE="$PROJECT_ROOT/.setup_state"
SETUP_LOCK_FILE="$PROJECT_ROOT/.setup.lock"
SETUP_LOG_FILE="$PROJECT_ROOT/data/logs/setup.log"

# ============================================================================
# UTILITIES
# ============================================================================

# Logging with timestamps
log_info() {
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] [INFO] $1"
    echo "$msg" | tee -a "$SETUP_LOG_FILE"
}

log_error() {
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR] $1"
    echo "$msg" | tee -a "$SETUP_LOG_FILE" >&2
}

log_warn() {
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] [WARN] $1"
    echo "$msg" | tee -a "$SETUP_LOG_FILE"
}

log_success() {
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] [SUCCESS] $1"
    echo "$msg" | tee -a "$SETUP_LOG_FILE"
}

# State tracking
declare -A COMPLETED_STEPS

load_state() {
    if [ -f "$SETUP_STATE_FILE" ]; then
        log_info "Loading previous setup state from $SETUP_STATE_FILE"
        while IFS='=' read -r key value; do
            COMPLETED_STEPS[$key]=$value
        done < "$SETUP_STATE_FILE"
    fi
}

mark_complete() {
    local step=$1
    echo "$step=1" >> "$SETUP_STATE_FILE"
    COMPLETED_STEPS[$step]=1
    log_info "Marked step as complete: $step"
}

is_complete() {
    local step=$1
    [ "${COMPLETED_STEPS[$step]:-0}" = "1" ]
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ============================================================================
# SETUP STEPS
# ============================================================================

setup_logging_dir() {
    mkdir -p "$PROJECT_ROOT/data/logs"
    log_info "Created log directory: $PROJECT_ROOT/data/logs"
}

setup_system_packages() {
    if is_complete "system_packages"; then
        log_info "System packages already installed (skipping)"
        return 0
    fi

    log_info "Checking and installing system dependencies..."
    
    local required_pkgs=("python3-dev" "python3-pip" "python3-venv" "build-essential" "curl" "git" "psmisc" "net-tools" "nmap" "nftables" "iptables" "redis-server" "suricata" "ipset" "software-properties-common" "openvswitch-switch" "hping3" "tcpdump" "libgeoip-dev" "geoip-bin" "libsqlite3-dev")

    local missing_pkgs=()
    for pkg in "${required_pkgs[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg"; then
            missing_pkgs+=("$pkg")
        fi
    done

    if [ ${#missing_pkgs[@]} -eq 0 ]; then
        log_info "All system packages already installed"
        mark_complete "system_packages"
        return 0
    fi

    log_info "Updating package manager (resilient mode)..."
    # Allow release info changes (common in dev/beta distros)
    sudo apt-get update --allow-releaseinfo-change || log_warn "Apt update had some issues, continuing best-effort..."

    # Detect codename
    local codename
    codename=$(lsb_release -cs 2>/dev/null || grep "VERSION_CODENAME" /etc/os-release | cut -d= -f2 || echo "unknown")
    
    # Add Suricata PPA only if it supports the current codename
    if ! grep -q "ppa:oisf/suricata-stable" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
        log_info "Checking if Suricata PPA supports '$codename'..."
        if curl -sI "https://ppa.launchpadcontent.net/oisf/suricata-stable/ubuntu/dists/$codename/" | grep -q "200 OK"; then
            log_info "Adding Suricata stable repository..."
            sudo add-apt-repository -y ppa:oisf/suricata-stable || log_warn "Failed to add Suricata PPA"
            sudo apt-get update || true
        else
            log_warn "Suricata PPA does not yet support '$codename'. Using default repository."
        fi
    fi

    log_info "Installing missing packages: ${missing_pkgs[*]}"
    if ! sudo apt-get install -y "${missing_pkgs[@]}"; then
        log_error "Failed to install system packages. Please check your internet connection or repository settings."
        return 1
    fi

    mark_complete "system_packages"
    log_success "System packages installed successfully"
}

setup_nodejs() {
    if is_complete "nodejs"; then
        log_info "Node.js already set up (skipping)"
        return 0
    fi

    if command_exists node; then
        local version=$(node -v | cut -dv -f2)
        local major=$(echo "$version" | cut -d. -f1)
        if [ "$major" -ge 20 ]; then
            log_info "Node.js $version is sufficient (>= 20)"
            mark_complete "nodejs"
            return 0
        fi
    fi

    log_info "Installing Node.js 20+..."
    if ! curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -; then
        log_warn "Failed to add NodeSource repository, attempting direct install..."
    fi

    if ! sudo apt-get install -y nodejs; then
        log_error "Failed to install Node.js"
        return 1
    fi

    mark_complete "nodejs"
}

setup_python_venv() {
    local venv_python="$PROJECT_ROOT/.venv/bin/python"
    
    log_info "Verifying Python environment health..."
    
    # Check if venv exists and has critical packages
    local venv_healthy=false
    if [ -f "$venv_python" ]; then
        local check_cmd="import fastapi, uvicorn, redis, sklearn, requests"
        if [ "${DEV_INSTALL:-false}" = true ]; then
            check_cmd="$check_cmd, pytest, pytest_mock, responses, respx"
        fi
        if "$venv_python" -c "$check_cmd" 2>/dev/null; then
            venv_healthy=true
        fi
    fi

    if [ "$venv_healthy" = true ]; then
        log_info "Python environment is healthy (skipping)"
        mark_complete "python_venv"
        return 0
    else
        log_warn "Python environment is incomplete or missing. Starting repair..."
        # Force removal of the "complete" mark from the state file
        [ -f "$SETUP_STATE_FILE" ] && sed -i '/python_venv=1/d' "$SETUP_STATE_FILE"
        COMPLETED_STEPS["python_venv"]=0
    fi

    if [ ! -d "$PROJECT_ROOT/.venv" ]; then
        log_info "Creating Python virtual environment..."
        if ! python3 -m venv "$PROJECT_ROOT/.venv"; then
            log_error "Failed to create virtual environment"
            return 1
        fi
    fi

    log_info "Upgrading pip and compatibility tools..."
    # Set PYO3 flag for Python 3.14 compatibility with Rust-based packages
    export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1
    
    "$venv_python" -m pip install --upgrade pip "setuptools<70" wheel --break-system-packages 2>/dev/null || \
    log_warn "Pip/Setuptools upgrade had issues, continuing..."

    if command -v nvidia-smi &> /dev/null; then
        log_info "NVIDIA GPU detected. Installing CUDA-optimized PyTorch..."
        if ! "$venv_python" -m pip install torch==2.11.0 --index-url https://download.pytorch.org/whl/cu121 --break-system-packages; then
            log_warn "CUDA torch install failed, trying standard install..."
        fi
    else
        log_info "No NVIDIA GPU detected. Installing CPU-optimized PyTorch..."
        if ! "$venv_python" -m pip install torch==2.11.0 --index-url https://download.pytorch.org/whl/cpu --break-system-packages; then
            log_warn "CPU-optimized torch install failed, trying standard install..."
        fi
    fi

    log_info "Installing remaining Python dependencies from requirements.txt..."
    if ! "$venv_python" -m pip install -r "$PROJECT_ROOT/requirements.txt" --break-system-packages; then
        log_error "Critical Python dependencies failed to install."
        return 1
    fi

    if [ "${DEV_INSTALL:-false}" = true ]; then
        log_info "Installing developer/testing dependencies from requirements-dev.txt..."
        if [ -f "$PROJECT_ROOT/requirements-dev.txt" ]; then
            if ! "$venv_python" -m pip install -r "$PROJECT_ROOT/requirements-dev.txt" --break-system-packages; then
                log_warn "Failed to install some development dependencies, continuing..."
            fi
        else
            log_warn "requirements-dev.txt not found, skipping dev installation"
        fi
    fi

    log_success "Python venv and dependencies installed"
    mark_complete "python_venv"
}

setup_ui_dependencies() {
    if is_complete "ui_dependencies"; then
        log_info "UI dependencies already installed (skipping)"
        return 0
    fi

    if [ -d "$PROJECT_ROOT/ui/node_modules" ]; then
        log_info "node_modules already exists"
        
        # Quick validation - check if key packages exist
        if [ -f "$PROJECT_ROOT/ui/node_modules/.package-lock.json" ] || \
           [ -f "$PROJECT_ROOT/ui/node_modules/react/package.json" ]; then
            log_info "Existing node_modules appears valid, reusing"
            mark_complete "ui_dependencies"
            return 0
        else
            log_warn "node_modules appears incomplete, reinstalling..."
            rm -rf "$PROJECT_ROOT/ui/node_modules"
        fi
    fi

    log_info "Installing UI dependencies via npm..."
    cd "$PROJECT_ROOT/ui" || { log_error "Cannot cd to ui directory"; return 1; }
    
    if ! npm install --legacy-peer-deps; then
        log_error "Failed to install UI dependencies"
        cd "$PROJECT_ROOT" || return 1
        return 1
    fi

    cd "$PROJECT_ROOT" || return 1
    
    log_info "Fixing UI binary permissions..."
    # Support for both standard and NTFS/fuseblk mounts
    chmod -R +x "$PROJECT_ROOT/ui/node_modules/.bin" 2>/dev/null || true
    
    log_success "UI dependencies installed"
    mark_complete "ui_dependencies"
}

setup_suricata_config() {
    if is_complete "suricata_config"; then
        log_info "Suricata already configured (skipping)"
        return 0
    fi

    log_info "Configuring Suricata..."

    # Detect primary interface
    local primary_iface
    primary_iface=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5; exit}')
    
    if [ -z "$primary_iface" ]; then
        primary_iface=$(ip link show | grep 'state UP' | awk '{print $2}' | sed 's/://' | head -n 1)
    fi
    
    primary_iface=${primary_iface:-eth0}
    log_info "Detected primary network interface: $primary_iface"

    # Create temporary config with placeholders replaced
    local temp_config
    temp_config=$(mktemp)
    
    if ! cp "$PROJECT_ROOT/config/suricata/suricata.yaml" "$temp_config"; then
        log_error "Cannot find suricata.yaml template"
        rm -f "$temp_config"
        return 1
    fi

    # Replace placeholders
    sed -i "s|__REPO_ROOT__|$PROJECT_ROOT|g" "$temp_config"
    sed -i "s|__SURICATA_INTERFACE__|$primary_iface|g" "$temp_config"

    # Deploy configuration
    log_info "Deploying Suricata configuration (requires sudo)..."
    sudo mkdir -p /etc/suricata
    
    if ! sudo cp "$temp_config" /etc/suricata/suricata.yaml; then
        log_error "Failed to deploy suricata.yaml"
        rm -f "$temp_config"
        return 1
    fi

    # Keep local copy and also deploy to Suricata's active rule path expected by config.
    if ! sudo cp "$PROJECT_ROOT/config/suricata/signatures.rules" /etc/suricata/signatures.rules; then
        log_error "Failed to deploy signatures.rules"
        rm -f "$temp_config"
        return 1
    fi

    # suricata.yaml uses: default-rule-path: /var/lib/suricata/rules + rule-files: [suricata.rules]
    # Ensure rule file exists there to avoid startup failure on clean systems.
    sudo mkdir -p /var/lib/suricata/rules
    if ! sudo cp "$PROJECT_ROOT/config/suricata/signatures.rules" /var/lib/suricata/rules/suricata.rules; then
        log_error "Failed to deploy active suricata.rules"
        rm -f "$temp_config"
        return 1
    fi

    rm -f "$temp_config"

    # Validate Suricata config before marking setup complete.
    if command_exists suricata; then
        if ! sudo suricata -T -c /etc/suricata/suricata.yaml -v >/tmp/suricata_validate.log 2>&1; then
            log_error "Suricata config validation failed (see /tmp/suricata_validate.log)"
            return 1
        fi
    else
        log_warn "suricata binary not found during validation step"
    fi

    # Ensure log directory is writable
    sudo mkdir -p "$PROJECT_ROOT/data/logs"
    sudo chmod -R 777 "$PROJECT_ROOT/data"

    log_success "Suricata configuration deployed"
    mark_complete "suricata_config"
}

setup_suricata_rules() {
    if is_complete "suricata_rules"; then
        log_info "Suricata rules already updated (skipping)"
        return 0
    fi

    if command_exists suricata-update; then
        log_info "Updating Suricata rules (this may take a minute)..."
        if sudo suricata-update; then
            log_success "Suricata rules updated"
        else
            log_warn "Suricata rule update failed (may be a network issue)"
        fi
    else
        log_warn "suricata-update not found, skipping rule update"
    fi

mark_complete "suricata_rules"
}

setup_model_files() {
    if is_complete "model_files"; then
        log_info "Model files already synchronized (skipping)"
        return 0
    fi

    log_info "Synchronizing model files for 49-feature schema..."

    mkdir -p "$PROJECT_ROOT/models"

    # Check if 'new model' directory exists and has files
    if [ -d "$PROJECT_ROOT/new model" ]; then
        log_info "Found updated models in 'new model' directory. Synchronizing..."

        # Files to sync from 'new model'
        local files_to_sync=("rf_model.pkl" "scaler.pkl" "feature_order.pkl" "le_proto.pkl")

        for file in "${files_to_sync[@]}"; do
            if [ -f "$PROJECT_ROOT/new model/$file" ]; then
                log_info "Copying $file to models/..."
                cp "$PROJECT_ROOT/new model/$file" "$PROJECT_ROOT/models/$file"
            fi
        done
    fi

    # Ensure other required V4 files are present
    if [ ! -f "$PROJECT_ROOT/models/feature_order.json" ]; then
        if [ -f "$PROJECT_ROOT/models/feature_order_multi.json" ]; then
            log_info "Creating feature_order.json from feature_order_multi.json..."
            cp "$PROJECT_ROOT/models/feature_order_multi.json" "$PROJECT_ROOT/models/feature_order.json"
        elif [ -f "$PROJECT_ROOT/models/feature_names_v4.json" ]; then
            log_info "Creating feature_order.json from v4 names..."
            cp "$PROJECT_ROOT/models/feature_names_v4.json" "$PROJECT_ROOT/models/feature_order.json"
        fi
    fi

    generate_mock_models
    mark_complete "model_files"
}

generate_mock_models() {
    log_info "Verifying critical model files..."
    local models=(
        "rf_model.pkl"
        "scaler.pkl"
        "vae_encoder.keras"
        "vae_decoder.keras"
        "vae_scaler.pkl"
    )
    
    # Create a simple python script to generate dummy pkl and keras files
    local generator_script="$PROJECT_ROOT/scripts/generate_mocks.py"
    mkdir -p "$PROJECT_ROOT/scripts"
    
    cat > "$generator_script" << 'EOF'
import pickle
import os
import json

def generate_mocks(models_dir):
    import joblib, numpy as np, json
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import MinMaxScaler
    
    feature_count = 49
    X = np.random.rand(100, feature_count)
    y = np.random.randint(0, 2, 100)
    
    # 1. Functional RF Model
    rf_path = os.path.join(models_dir, "rf_model.pkl")
    if not os.path.exists(rf_path) or os.path.getsize(rf_path) < 100:
        model = RandomForestClassifier(n_estimators=5, max_depth=3).fit(X, y)
        model.is_mock = True
        joblib.dump(model, rf_path)
        print(f"Generated functional mock RF: {rf_path}")

    # 2. Functional Scaler
    scaler_path = os.path.join(models_dir, "scaler.pkl")
    if not os.path.exists(scaler_path) or os.path.getsize(scaler_path) < 100:
        scaler = MinMaxScaler().fit(X)
        scaler.is_mock = True
        joblib.dump(scaler, scaler_path)
        print(f"Generated functional mock Scaler: {scaler_path}")

    # 3. VAE Scaler
    vae_scaler_path = os.path.join(models_dir, "vae_scaler.pkl")
    if not os.path.exists(vae_scaler_path) or os.path.getsize(vae_scaler_path) < 100:
        scaler = MinMaxScaler().fit(X)
        scaler.is_mock = True
        joblib.dump(scaler, vae_scaler_path)
        print(f"Generated functional mock VAE Scaler: {vae_scaler_path}")

    # 4. Keras placeholders (need real files for keras.load_model to not crash)
    # Note: Keras models are harder to generate without keras installed in the setup environment
    # but we'll at least ensure the pkl files are fixed as they are the primary blocker for scores.

if __name__ == "__main__":
    import sys
    generate_mocks(sys.argv[1])
EOF

    log_info "Generating mock models for health checks..."
    # Try to use venv python if it exists, otherwise system python
    local python_bin="python3"
    [ -f "$PROJECT_ROOT/.venv/bin/python" ] && python_bin="$PROJECT_ROOT/.venv/bin/python"
    
    $python_bin "$generator_script" "$PROJECT_ROOT/models" || log_warn "Failed to generate mock models"
}

setup_services() {
    if is_complete "services"; then
        log_info "Services already enabled (skipping)"
        return 0
    fi

    log_info "Enabling services..."

    sudo systemctl enable redis-server 2>/dev/null || log_warn "Failed to enable redis-server"
    sudo systemctl enable suricata 2>/dev/null || log_warn "Failed to enable suricata"

    # Try to start redis now
    log_info "Starting Redis service..."
    if sudo systemctl start redis-server 2>/dev/null; then
        log_success "Redis started"
    else
        log_warn "Could not start Redis (it may be running, or check: sudo systemctl status redis-server)"
    fi

    mark_complete "services"
}

create_env_file() {
    if [ -f "$PROJECT_ROOT/.env" ]; then
        log_info ".env file already exists (skipping)"
        return 0
    fi

    log_info "Creating .env configuration file..."
    cat > "$PROJECT_ROOT/.env" << EOF
# Sentinel Core Environment Configuration
PROJECT_ROOT=$PROJECT_ROOT
PYTHONPATH=\$PROJECT_ROOT/src
VENV_PATH=\$PROJECT_ROOT/.venv
LOG_DIR=\$PROJECT_ROOT/data/logs
API_PORT=3000
WS_PORT=8777
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
LOG_LEVEL=INFO
MODEL_VERSION=v4.0
EOF

    log_success "Created .env file at $PROJECT_ROOT/.env"
}

setup_logrotate() {
    if is_complete "logrotate"; then
        log_info "Logrotate already configured (skipping)"
        return 0
    fi

    log_info "Configuring log rotation..."
    local lr_file="/etc/logrotate.d/sentinel_core"
    
    # Use copytruncate because our Python/Shell loggers keep handles open
    if sudo tee "$lr_file" >/dev/null << EOF
$PROJECT_ROOT/data/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    missingok
    copytruncate
    create 0644 $USER $USER
}
EOF
    then
        log_success "Logrotate configuration created at $lr_file"
        mark_complete "logrotate"
    else
        log_warn "Failed to create logrotate config (requires sudo)"
    fi
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    # Parse options
    DEV_INSTALL=false
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dev)
                DEV_INSTALL=true
                shift
                ;;
            *)
                echo "Unknown option: $1"
                echo "Usage: ./setup.sh [--dev]"
                exit 1
                ;;
        esac
    done
    export DEV_INSTALL

    echo "======================================================================="
    echo "           SENTINEL CORE: UNIFIED SYSTEM INSTALLER"
    echo "======================================================================="
    echo ""

    # Setup logging
    mkdir -p "$PROJECT_ROOT/data/logs"

    # Prevent concurrent setup
    if [ -f "$SETUP_LOCK_FILE" ]; then
        log_error "Setup is already running!"
        log_error "If this is stuck, remove: $SETUP_LOCK_FILE"
        exit 1
    fi
    
    trap "rm -f $SETUP_LOCK_FILE" EXIT
    touch "$SETUP_LOCK_FILE"

    # Run preflight checks first
    if [ -f "$PROJECT_ROOT/preflight.sh" ]; then
        log_info "Running pre-flight validation..."
        if ! bash "$PROJECT_ROOT/preflight.sh"; then
            log_error "Pre-flight validation failed. Please fix the issues above."
            exit 1
        fi
    fi

    # Load previous state
    load_state

    # Execute setup steps
    setup_logging_dir
    setup_system_packages || { log_error "System package setup failed"; exit 1; }
    setup_nodejs || { log_error "Node.js setup failed"; exit 1; }
    setup_python_venv || { log_error "Python venv setup failed"; exit 1; }
    setup_ui_dependencies || { log_error "UI dependencies setup failed"; exit 1; }
    setup_suricata_config || { log_error "Suricata configuration failed"; exit 1; }
    setup_suricata_rules
    setup_model_files || { log_error "Model file synchronization failed"; exit 1; }
    setup_services || { log_error "Service setup failed"; exit 1; }
    setup_logrotate
    create_env_file

    echo ""
    echo "======================================================================="
    log_success "SENTINEL CORE SETUP IS COMPLETE!"
    echo "======================================================================="
    echo ""
    echo "Next steps:"
    echo "  1. Run ./preflight.sh to verify the environment"
    echo "  2. Run ./start.sh to launch the system"
    echo ""
    echo "Setup log saved to: $SETUP_LOG_FILE"
    echo "======================================================================="
}

# Run main
main "$@"
