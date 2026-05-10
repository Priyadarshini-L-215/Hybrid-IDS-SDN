#!/bin/bash
# start.sh - Unified Sentinel Core Launcher with Health Checks
# Features: Dependency ordering, health checks, timeout management, PID tracking

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_FILE="$PROJECT_ROOT/.sentinel_state"
STATE_LOCK_FILE="$PROJECT_ROOT/.sentinel.lock"
STARTUP_LOG_FILE="$PROJECT_ROOT/data/logs/startup.log"
STARTUP_TIMEOUT=60
APP_PYTHON="$PROJECT_ROOT/.venv/bin/python"

# Force CPU-only ML startup unless the operator explicitly overrides it.
export KERAS_BACKEND="${KERAS_BACKEND:-torch}"
export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:--1}"
export TF_CPP_MIN_LOG_LEVEL="${TF_CPP_MIN_LOG_LEVEL:-2}"
export TF_ENABLE_ONEDNN_OPTS="${TF_ENABLE_ONEDNN_OPTS:-0}"

# ============================================================================
# UTILITIES
# ============================================================================

check_lock() {
    if [ -f "$STATE_LOCK_FILE" ]; then
        local pid
        pid=$(cat "$STATE_LOCK_FILE" 2>/dev/null || true)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            log_error "Sentinel is already running (PID: $pid). Use ./stop.sh first."
            exit 1
        fi
        log_warn "Stale lock file found. Removing..."
        rm -f "$STATE_LOCK_FILE"
    fi
    echo $$ > "$STATE_LOCK_FILE"
}

wait_for_port() {
    local port=$1
    local name=$2
    local timeout=${3:-30}
    log_info "Waiting for $name on port $port (timeout: ${timeout}s)..."
    local elapsed=0
    while [ $elapsed -lt "$timeout" ]; do
        if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
            log_success "$name is responsive on port $port"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    log_error "$name (port $port) failed to start"
    return 1
}

log_info() {
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] [INFO] $1"
    echo "$msg" | tee -a "$STARTUP_LOG_FILE"
}

log_error() {
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR] $1"
    echo "$msg" | tee -a "$STARTUP_LOG_FILE" >&2
}

log_success() {
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] [SUCCESS] $1"
    echo "$msg" | tee -a "$STARTUP_LOG_FILE"
}

log_warn() {
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] [WARN] $1"
    echo "$msg" | tee -a "$STARTUP_LOG_FILE"
}

# Setup logging
setup_logging() {
    mkdir -p "$PROJECT_ROOT/data/logs"
    : > "$STARTUP_LOG_FILE"
}

source_env_file() {
    if [ -f "$PROJECT_ROOT/.env" ]; then
        # shellcheck disable=SC1091
        set -a
        source "$PROJECT_ROOT/.env"
        set +a
    fi
}

# Activate virtual environment (Auto-setup if missing)
activate_venv() {
    if [ ! -d "$PROJECT_ROOT/.venv" ] || [ ! -d "$PROJECT_ROOT/ui/node_modules" ]; then
        log_warn "Missing environment or dependencies. Running auto-setup..."
        if ! ./setup.sh; then
            log_error "Auto-setup failed. Please run ./setup.sh manually."
            exit 1
        fi
    fi

    # shellcheck source=/dev/null
    if ! source "$PROJECT_ROOT/.venv/bin/activate"; then
        log_error "Failed to activate virtual environment"
        exit 1
    fi

    # Verify venv Python has required packages
    if ! "$PROJECT_ROOT/.venv/bin/python" -c "import structlog; import yaml; import fastapi" 2>/dev/null; then
        log_warn "Virtual environment missing required packages. Attempting repair..."
        if ! ./setup.sh; then
            log_error "Venv repair failed"
            exit 1
        fi
    fi

    log_info "Environment ready"
    
    # Run configuration validator
    log_info "Validating configuration and model files..."
    if ! "$PROJECT_ROOT/.venv/bin/python" "$PROJECT_ROOT/src/common/config_validator.py"; then
        log_error "Configuration validation failed. Check the errors above."
        exit 1
    fi
}

# Load configuration from Python
load_config() {
    export PYTHONPATH="$PROJECT_ROOT/src:${PYTHONPATH:-}"
    source_env_file

    if ! SURICATA_SOCKET=$("$APP_PYTHON" -c "import sys; sys.path.insert(0, '$PROJECT_ROOT/src'); from common.config import SURICATA_SOCKET; print(SURICATA_SOCKET)" 2>/dev/null); then
        log_warn "Could not load SURICATA_SOCKET from config. Using default."
        SURICATA_SOCKET="/tmp/sentinel_suricata.sock"
    fi

    if ! API_PORT=$("$APP_PYTHON" -c "import sys; sys.path.insert(0, '$PROJECT_ROOT/src'); from common.config import API_PORT; print(API_PORT)" 2>/dev/null); then
        log_warn "Could not load API_PORT from config, using default 3000"
        API_PORT=3000
    fi

    SDN_ENABLED=$("$APP_PYTHON" -c "import sys; sys.path.insert(0, '$PROJECT_ROOT/src'); from common.config import SDN_ENABLED; print(str(SDN_ENABLED).lower())" 2>/dev/null || echo "false")

    log_info "Loaded config: API_PORT=$API_PORT, SDN_ENABLED=$SDN_ENABLED"
}

verify_models() {
    log_info "Verifying critical model files..."
    local missing=0
    local critical_files=(
        "models/rf_model.pkl"
        "models/scaler.pkl"
        "models/vae_encoder.keras"
        "models/vae_decoder.keras"
    )
    
    for f in "${critical_files[@]}"; do
        if [ ! -f "$PROJECT_ROOT/$f" ]; then
            log_warn "Missing critical model file: $f"
            missing=$((missing + 1))
        fi
    done
    
    if [ $missing -gt 0 ]; then
        log_warn "Some model files are missing. Inference may be degraded or fail."
        log_info "Tip: Run ./setup.sh to synchronize models from 'new model' directory."
    else
        log_success "All critical model files verified"
    fi
}

# ============================================================================
# HEALTH CHECKS
# ============================================================================

is_port_available() {
    local port=$1
    ! nc -z 127.0.0.1 "$port" 2>/dev/null
}

is_process_running() {
    local pattern=$1
    pgrep -f "$pattern" >/dev/null 2>&1
}

wait_for_condition() {
    local name=$1
    local check_cmd=$2
    local timeout=$3
    
    log_info "Waiting for $name (timeout: ${timeout}s)..."
    
    local elapsed=0
    while [ $elapsed -lt "$timeout" ]; do
        if eval "$check_cmd" 2>/dev/null; then
            log_success "$name is ready"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    log_error "$name did not start within ${timeout}s"
    return 1
}

# ============================================================================
# SERVICE MANAGEMENT
# ============================================================================

ensure_sudo_access() {
    log_info "Checking sudo access for system services..."
    if ! sudo -n true 2>/dev/null; then
        log_warn "Sudo password may be required"
        sudo -v || { log_error "Sudo access denied"; exit 1; }
    fi
    log_success "Sudo access confirmed"
}

cleanup_stale_processes() {
    log_info "Cleaning up stale processes and sockets..."
    pkill -9 -f "src/ml_engine/consumer.py" 2>/dev/null || true
    pkill -9 -f "src/ml_engine/ingestion.py" 2>/dev/null || true
    pkill -9 -f "relay.app:app" 2>/dev/null || true
    pkill -9 -f "uvicorn.*relay.app" 2>/dev/null || true
    # UI dev server should be managed separately per implementation plan
    # pkill -9 -f "npm.*dev" 2>/dev/null || true
    pkill -9 -f "ryu-manager" 2>/dev/null || true
    pkill -9 -f "src/sdn/honeypot.py" 2>/dev/null || true
    
    # Cleanup stale sockets
    sudo rm -f /tmp/sentinel_suricata.sock 2>/dev/null || true
    sudo rm -f /tmp/suricata_sentinel.pid 2>/dev/null || true
    
    sleep 2
    log_success "Cleanup complete"
}

cleanup_on_interrupt() {
    log_warn "Interrupt received, stopping Sentinel Core..."
    "$PROJECT_ROOT/stop.sh" >/dev/null 2>&1 || true
}

start_redis() {
    log_info "Starting Redis..."
    sudo systemctl start redis-server 2>/dev/null || true
    if wait_for_condition "Redis Connectivity" "redis-cli ping 2>/dev/null | grep -q PONG" 15; then
        return 0
    fi
    return 1
}

start_sdn_infrastructure() {
    if [ "$SDN_ENABLED" != "true" ]; then return 0; fi
    log_info "Starting SDN Infrastructure (OVS Setup)..."
    sudo ./sdn_setup.sh
}

start_ryu_controller() {
    if [ "$SDN_ENABLED" != "true" ]; then return 0; fi
    log_info "Starting Ryu SDN Controller..."
    ryu-manager src/sdn/sentinel_controller.py --ofp-tcp-listen-port 6653 >> data/logs/ryu.log 2>&1 &
    local pid=$!
    echo "ryu_pid=$pid" >> "$STATE_FILE"
    wait_for_condition "Ryu REST API" "nc -z 127.0.0.1 8080" 15
}

start_honeypot() {
    if [ "$SDN_ENABLED" != "true" ]; then return 0; fi
    log_info "Starting Dionaea Honeypot Sink..."
    # Start in the honeypot namespace
    sudo ip netns exec honeypot python3 src/sdn/honeypot.py >> data/logs/honeypot.log 2>&1 &
    local pid=$!
    echo "honeypot_pid=$pid" >> "$STATE_FILE"
    log_success "Honeypot active (PID: $pid)"
}

start_ingestion() {
    log_info "Starting Ingestion Bridge..."
    "$APP_PYTHON" "$PROJECT_ROOT/src/ml_engine/ingestion.py" >> "$PROJECT_ROOT/data/logs/ingestion.log" 2>&1 &
    local pid=$!
    echo "ingestion_pid=$pid" >> "$STATE_FILE"
    wait_for_condition "Ingestion Socket" "test -S $SURICATA_SOCKET" 30
}

start_suricata() {
    log_info "Starting Suricata sensor..."

    cleanup_stale_suricata_pidfile() {
        local pidfile=$1
        if [ ! -f "$pidfile" ]; then
            return 0
        fi

        local pid
        pid=$(tr -d '[:space:]' < "$pidfile" 2>/dev/null || true)

        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            log_info "Suricata pidfile is active: $pidfile (PID $pid)"
            return 0
        fi

        log_warn "Removing stale Suricata pidfile: $pidfile"
        sudo rm -f "$pidfile"
    }

    cleanup_stale_suricata_pidfile "/tmp/suricata_sentinel.pid"
    cleanup_stale_suricata_pidfile "/var/run/suricata.pid"
    cleanup_stale_suricata_pidfile "/run/suricata.pid"

    local suricata_cmd
    suricata_cmd=$(command -v suricata 2>/dev/null || true)
    if [ -z "$suricata_cmd" ]; then
        log_error "suricata binary not found"
        return 1
    fi

    # Template the suricata config
    local template_file="$PROJECT_ROOT/config/suricata/suricata.yaml"
    local active_file="$PROJECT_ROOT/config/suricata/suricata.yaml.active"
    
    if [ -f "$template_file" ]; then
        log_info "Templating Suricata config..."
        # Find default interface if not provided
        local interface
        interface=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5}' | head -n 1)
        interface=${interface:-eth0}
        
        sed -e "s|__REPO_ROOT__|$PROJECT_ROOT|g" \
            -e "s|__SURICATA_INTERFACE__|$interface|g" \
            "$template_file" > "$active_file"
        log_success "Suricata config ready (interface: $interface)"
    else
        log_error "Suricata template config not found at $template_file"
        return 1
    fi

    if command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
        sudo systemctl stop suricata >/dev/null 2>&1 || true
        # We start directly if using custom config, as systemd service usually points to /etc/suricata
    fi

    log_info "Starting Suricata directly with project config..."
    sudo pkill -f "suricata -c .*suricata.yaml.active" >/dev/null 2>&1 || true
    
    # Start Suricata in daemon mode with project config
    sudo "$suricata_cmd" --af-packet -c "$active_file" -D >> "$PROJECT_ROOT/data/logs/suricata-start.log" 2>&1
    sleep 3

    if is_process_running "suricata"; then
        local suricata_pid
        suricata_pid=$(pgrep -f "suricata -c .*suricata.yaml.active" | head -n 1 || true)
        if [ -n "$suricata_pid" ]; then
            echo "suricata_pid=$suricata_pid" >> "$STATE_FILE"
        fi
        log_success "Suricata active with project config (PID: $suricata_pid)"
        return 0
    fi

    log_error "Suricata failed to start with project config"
    tail -n 30 "$PROJECT_ROOT/data/logs/suricata-start.log" >> "$STARTUP_LOG_FILE" 2>&1 || true
    return 1
}

start_consumer() {
    log_info "Starting ML Consumer (Schema: 49 features)..."
    "$APP_PYTHON" "$PROJECT_ROOT/src/ml_engine/consumer.py" >> "$PROJECT_ROOT/data/logs/consumer.log" 2>&1 &
    local pid=$!
    echo "consumer_pid=$pid" >> "$STATE_FILE"
    
    # Wait for consumer heartbeat or at least confirm it stayed alive
    log_info "Waiting for ML Engine to initialize models..."
    sleep 5
    
    if is_process_running "consumer.py"; then
        log_success "ML Consumer active (PID: $pid)"
        return 0
    else
        log_error "ML Consumer failed to start. Check data/logs/consumer.log"
        return 1
    fi
}

start_relay() {
    log_info "Starting Relay API..."
    "$APP_PYTHON" -m uvicorn relay.app:app --host 0.0.0.0 --port "$API_PORT" >> "$PROJECT_ROOT/data/logs/relay.log" 2>&1 &
    local pid=$!
    echo "relay_pid=$pid" >> "$STATE_FILE"
    wait_for_port "$API_PORT" "Relay API"
}

start_ui() {
    log_info "Ensuring Dashboard UI is built..."
    cd "$PROJECT_ROOT/ui"
    
    if [ ! -d "dist" ]; then
        log_warn "UI dist directory missing. Running npm run build..."
        npm run build || { log_error "UI build failed"; return 1; }
    fi
    cd "$PROJECT_ROOT"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    setup_logging
    source_env_file
    check_lock
    
    echo "================================================================="
    ensure_sudo_access
    
    # Start Redis first because the validator needs it
    start_redis || exit 1
    
    # Ensure state file is fresh and track interrupts
    : > "$STATE_FILE"
    trap cleanup_on_interrupt INT TERM
    
    activate_venv
    load_config
    verify_models
    cleanup_stale_processes
    start_sdn_infrastructure
    start_ryu_controller
    start_honeypot
    start_ingestion || exit 1
    start_suricata || log_warn "Suricata failed to start"
    start_consumer || exit 1
    start_relay || exit 1
    start_ui

    log_success "SENTINEL CORE IS NOW ACTIVE"
    echo "Dashboard: http://127.0.0.1:${API_PORT}"
    
    # Keep alive if not interactive (e.g. running under systemd)
    if [ ! -t 1 ]; then
        log_info "Running in non-interactive mode. Staying alive..."
        while true; do sleep 60; done
    else
        # Tail logs if interactive
        log_info "Interactive mode. Tailing logs..."
        tail -f "$PROJECT_ROOT/data/logs/relay.log" "$PROJECT_ROOT/data/logs/consumer.log"
    fi
}

main "$@"
