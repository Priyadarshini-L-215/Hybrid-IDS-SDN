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
    # Atomically rewrite state file without duplicate keys
    local tmp
    tmp=$(mktemp "$PROJECT_ROOT/.setup_state.XXXXXX")
    if [ -f "$SETUP_STATE_FILE" ]; then
        grep -v "^${step}=" "$SETUP_STATE_FILE" > "$tmp" || true
    fi
    echo "${step}=1" >> "$tmp"
    mv "$tmp" "$SETUP_STATE_FILE"
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
    
    # List of required packages
    local required_pkgs=(
        "python3-dev"
        "python3-pip"
        "python3-venv"
        "build-essential"
        "curl"
        "git"
        "psmisc"
        "net-tools"
        "nmap"
        "nftables"
        "iptables"
        "redis-server"
        "suricata"
        "ipset"
        "software-properties-common"
        "openvswitch-switch"
        "hping3"
        "tcpdump"
        "libgeoip-dev"
        "geoip-bin"
        "libsqlite3-dev"
    )

    # Check which packages are missing
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

    log_info "Missing packages: ${missing_pkgs[*]}"
    log_info "Installing missing packages (may require sudo password)..."

    # Update package manager
    sudo apt-get update || { log_error "apt-get update failed"; return 1; }

    # Add Suricata PPA for latest version
    if ! grep -q "ppa:oisf/suricata-stable" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
        log_info "Adding Suricata stable repository..."
        sudo add-apt-repository -y ppa:oisf/suricata-stable || log_warn "Failed to add Suricata PPA"
        sudo apt-get update
    fi

    # Install missing packages
    if ! sudo apt-get install -y "${missing_pkgs[@]}"; then
        log_error "Failed to install system packages"
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

    log_info "Checking Node.js..."

    if command_exists node; then
        local version=$(node -v | cut -dv -f2)
        local major=$(echo "$version" | cut -d. -f1)
        
        if [ "$major" -ge 20 ]; then
            log_info "Node.js $version already installed (meets requirements)"
            mark_complete "nodejs"
            return 0
        else
            log_warn "Node.js $version is too old, upgrading to 20+"
        fi
    else
        log_info "Node.js not found, installing Node.js 20+..."
    fi

    # Install Node.js 20 from NodeSource
    if ! sudo bash <(curl -fsSL https://deb.nodesource.com/setup_20.x); then
        log_error "Failed to add NodeSource repository"
        return 1
    fi

    if ! sudo apt-get install -y nodejs; then
        log_error "Failed to install Node.js"
        return 1
    fi

    local version=$(node -v)
    log_success "Node.js installed: $version"
    mark_complete "nodejs"
}

setup_python_venv() {
    if is_complete "python_venv"; then
        log_info "Python venv already set up (skipping)"
        return 0
    fi

    if [ -d "$PROJECT_ROOT/.venv" ]; then
        log_info "Virtual environment already exists, validating..."
        
        # Verify venv is valid
        if [ -f "$PROJECT_ROOT/.venv/bin/python" ]; then
            log_info "Existing venv appears valid, reusing it"
            mark_complete "python_venv"
            return 0
        else
            log_warn "Existing venv appears corrupted, recreating..."
            rm -rf "$PROJECT_ROOT/.venv"
        fi
    fi

    log_info "Creating Python virtual environment..."
    if ! python3 -m venv "$PROJECT_ROOT/.venv"; then
        log_error "Failed to create virtual environment"
        return 1
    fi

    # Activate venv
    # shellcheck source=/dev/null
    source "$PROJECT_ROOT/.venv/bin/activate"

    log_info "Virtual environment created, upgrading pip..."
    if ! pip install --upgrade pip setuptools wheel; then
        log_error "Failed to upgrade pip"
        return 1
    fi

    log_info "Installing Python dependencies from requirements.txt..."
    if ! pip install -r "$PROJECT_ROOT/requirements.txt"; then
        log_error "Failed to install Python dependencies"
        return 1
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
    
    if ! npm install; then
        log_error "Failed to install UI dependencies"
        cd "$PROJECT_ROOT" || return 1
        return 1
    fi

    cd "$PROJECT_ROOT" || return 1
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
        log_info "Model files already verified (skipping)"
        return 0
    fi

    log_info "Verifying model directory structure..."
    
    mkdir -p "$PROJECT_ROOT/models"
    
    # Check if manifest.json exists, if not, warn
    if [ ! -f "$PROJECT_ROOT/models/manifest.json" ]; then
        log_warn "models/manifest.json missing. System may start in fallback mode."
    fi

    # Ensure feature_order.json is present
    if [ ! -f "$PROJECT_ROOT/models/feature_order.json" ]; then
        if [ -f "$PROJECT_ROOT/models/feature_order.pkl" ]; then
            log_info "Attempting to generate feature_order.json from .pkl..."
            # This would normally be handled by a script, for now just log it
            log_warn "feature_order.json missing but .pkl found."
        fi
    fi

    mark_complete "model_files"
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
    echo "======================================================================="
    echo "           SENTINEL CORE: UNIFIED SYSTEM INSTALLER"
    echo "======================================================================="
    echo ""

    # Setup logging
    mkdir -p "$PROJECT_ROOT/data/logs"

    # Prevent concurrent setup with PID check
    if [ -f "$SETUP_LOCK_FILE" ]; then
        local stale_pid
        stale_pid=$(cat "$SETUP_LOCK_FILE" 2>/dev/null || true)
        if [ -n "$stale_pid" ] && kill -0 "$stale_pid" 2>/dev/null; then
            log_error "Setup is already running (PID: $stale_pid). Aborting."
            exit 1
        fi
        log_warn "Stale setup lock found. Removing..."
        rm -f "$SETUP_LOCK_FILE"
    fi
    
    trap "rm -f $SETUP_LOCK_FILE" EXIT INT TERM
    echo $$ > "$SETUP_LOCK_FILE"

    # Handle --force flag
    if [[ "${1:-}" == "--force" ]]; then
        log_warn "Force flag detected. Resetting setup state..."
        rm -f "$SETUP_STATE_FILE"
        # Reset memory state
        for key in "${!COMPLETED_STEPS[@]}"; do
            unset "COMPLETED_STEPS[$key]"
        done
    fi

    # Run preflight checks first
    if [ -f "$PROJECT_ROOT/preflight.sh" ]; then
        log_info "Running pre-flight validation..."
        if ! ./preflight.sh; then
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
