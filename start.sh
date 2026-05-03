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

# ============================================================================
# UTILITIES
# ============================================================================

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
        log_warn "Could not load API_PORT from config, using default 5000"
        API_PORT=5000
    fi

    if ! UI_PORT=$("$APP_PYTHON" -c "import sys; sys.path.insert(0, '$PROJECT_ROOT/src'); from common.config import UI_PORT; print(UI_PORT)" 2>/dev/null); then
        log_warn "Could not load UI_PORT from config, using default 3000"
        UI_PORT=3000
    fi

    SDN_ENABLED=$("$APP_PYTHON" -c "import sys; sys.path.insert(0, '$PROJECT_ROOT/src'); from common.config import SDN_ENABLED; print(str(SDN_ENABLED).lower())" 2>/dev/null || echo "false")

    log_info "Loaded config: API_PORT=$API_PORT, UI_PORT=$UI_PORT, SDN_ENABLED=$SDN_ENABLED"
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
    log_info "Cleaning up stale processes..."
    pkill -f "src/ml_engine/consumer.py" 2>/dev/null || true
    pkill -f "src/ml_engine/ingestion.py" 2>/dev/null || true
    pkill -f "relay.app:app" 2>/dev/null || true
    pkill -f "uvicorn.*relay.app" 2>/dev/null || true
    pkill -f "npm.*dev" 2>/dev/null || true
    pkill -f "ryu-manager" 2>/dev/null || true
    pkill -f "src/sdn/honeypot.py" 2>/dev/null || true
    sleep 1
    log_success "Stale processes cleaned up"
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
    log_info "Starting ML Consumer..."
    "$APP_PYTHON" "$PROJECT_ROOT/src/ml_engine/consumer.py" >> "$PROJECT_ROOT/data/logs/consumer.log" 2>&1 &
    local pid=$!
    echo "consumer_pid=$pid" >> "$STATE_FILE"
    sleep 3
    is_process_running "consumer.py"
}

start_relay() {
    log_info "Starting Relay API..."
    "$APP_PYTHON" -m uvicorn relay.app:app --host 0.0.0.0 --port "$API_PORT" >> "$PROJECT_ROOT/data/logs/relay.log" 2>&1 &
    local pid=$!
    echo "relay_pid=$pid" >> "$STATE_FILE"
    wait_for_condition "Relay API" "nc -z 127.0.0.1 $API_PORT" 15
}

start_ui() {
    log_info "Starting Dashboard UI..."
    cd "$PROJECT_ROOT/ui"
    
    # Check if UI is built
    if [ ! -d "dist" ]; then
        log_warn "UI dist directory missing. Running npm run build..."
        npm run build || { log_error "UI build failed"; return 1; }
    fi

    export VITE_BACKEND_PORT=$API_PORT
    export VITE_PORT=$UI_PORT
    PORT=$UI_PORT npm run dev -- --host 0.0.0.0 --port "$UI_PORT" >> "$PROJECT_ROOT/data/logs/ui.log" 2>&1 &
    local pid=$!
    cd "$PROJECT_ROOT"
    echo "ui_pid=$pid" >> "$STATE_FILE"
    wait_for_condition "Dashboard UI" "nc -z 127.0.0.1 $UI_PORT" 15
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    echo "================================================================="
    echo "            SENTINEL CORE: HYBRID ML-POWERED IPS"
    echo "            SDN-ENHANCED EDITION"
    echo "================================================================="
    
    setup_logging
    activate_venv
    load_config
    ensure_sudo_access
    cleanup_stale_processes
    trap cleanup_on_interrupt INT TERM

    # Startup sequence
    # Ensure state file is fresh
    : > "$STATE_FILE"
    
    start_redis || exit 1
    start_sdn_infrastructure
    start_ryu_controller
    start_honeypot
    start_ingestion || exit 1
    start_suricata || log_warn "Suricata failed to start"
    start_consumer || exit 1
    start_relay || exit 1
    start_ui

    log_success "SENTINEL CORE IS NOW ACTIVE"
    echo "Dashboard: http://127.0.0.1:${UI_PORT}"
    
    # Tail logs if interactive
    if [ -t 1 ]; then
        # Use a more descriptive log tail
        tail -f "$PROJECT_ROOT/data/logs/relay.log" "$PROJECT_ROOT/data/logs/consumer.log"
    fi
}

main "$@"
