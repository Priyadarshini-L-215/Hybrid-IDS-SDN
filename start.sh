#!/bin/bash
# start.sh - Unified Sentinel Core Launcher with Health Checks
# Features: Dependency ordering, health checks, supervisor loop, parallel startup

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

# Choose GPU or CPU based on environment and available hardware.
export KERAS_BACKEND="${KERAS_BACKEND:-torch}"
if [ -z "${CUDA_VISIBLE_DEVICES+x}" ]; then
    if command -v nvidia-smi >/dev/null 2>&1; then
        export CUDA_VISIBLE_DEVICES="0"
    else
        export CUDA_VISIBLE_DEVICES="-1"
    fi
fi
export TF_CPP_MIN_LOG_LEVEL="${TF_CPP_MIN_LOG_LEVEL:-2}"
export TF_ENABLE_ONEDNN_OPTS="${TF_ENABLE_ONEDNN_OPTS:-0}"

# ============================================================================
# UTILITIES
# ============================================================================

log_info() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [INFO] $1" | tee -a "$STARTUP_LOG_FILE"; }
log_error() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR] $1" | tee -a "$STARTUP_LOG_FILE" >&2; }
log_success() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [SUCCESS] $1" | tee -a "$STARTUP_LOG_FILE"; }
log_warn() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [WARN] $1" | tee -a "$STARTUP_LOG_FILE"; }

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

keep_sudo_alive() {
    while true; do
        sudo -n true 2>/dev/null || true
        sleep 60
    done
}

wait_for_condition() {
    local name=$1; local check_cmd=$2; local timeout=$3
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

update_state() {
    local key=$1
    local value=$2
    local temp_file
    temp_file=$(mktemp "$PROJECT_ROOT/.sentinel_state.XXXXXX")
    if [ -f "$STATE_FILE" ]; then
        grep -v "^${key}=" "$STATE_FILE" > "$temp_file" || true
    fi
    echo "${key}=${value}" >> "$temp_file"
    mv "$temp_file" "$STATE_FILE"
}

# ============================================================================
# SERVICE MANAGEMENT
# ============================================================================

ensure_sudo_access() {
    log_info "Checking sudo access..."
    if ! sudo -n -v 2>/dev/null; then
        if [ -t 0 ]; then
            log_info "Sudo credentials not cached. Prompting for sudo password..."
            if ! sudo -v 2>/dev/null; then
                log_warn "Sudo authentication failed or not interactive. Continuing in non-privileged mode..."
                return 0
            fi
        else
            log_warn "Sudo access not available (non-interactive). Continuing in non-privileged mode..."
            return 0
        fi
    fi
    keep_sudo_alive &
    SUDO_KEEP_ALIVE_PID=$!
}

cleanup() {
    log_warn "Cleanup triggered. Stopping services..."
    [ -n "${SUDO_KEEP_ALIVE_PID:-}" ] && kill "$SUDO_KEEP_ALIVE_PID" 2>/dev/null || true
    "$PROJECT_ROOT/stop.sh" >/dev/null 2>&1 || true
    rm -f "$STATE_LOCK_FILE"
}

trap cleanup EXIT INT TERM

activate_venv() {
    if [ ! -x "$APP_PYTHON" ]; then
        log_error "Virtual environment missing or broken. Please run ./setup.sh"
        exit 1
    fi

    if [ -f "$PROJECT_ROOT/.venv/bin/activate" ]; then
        # shellcheck source=/dev/null
        source "$PROJECT_ROOT/.venv/bin/activate"
    else
        log_warn "No activate script found in virtual environment; using interpreter directly."
    fi

    export PATH="$PROJECT_ROOT/.venv/bin:$PATH"
}

# Set Python path to include src (safely handle existing PYTHONPATH)
export PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

start_redis() {
    log_info "Starting Redis..."
    sudo systemctl start redis-server 2>/dev/null || true
    wait_for_condition "Redis" "redis-cli ping | grep -q PONG" 15
}

start_ingestion() {
    log_info "Starting Ingestion Bridge..."
    "$APP_PYTHON" "$PROJECT_ROOT/src/ml_engine/ingestion.py" >> "$PROJECT_ROOT/data/logs/ingestion.log" 2>&1 &
    update_state "ingestion_pid" "$!"
}

start_suricata() {
    log_info "Starting Suricata..."
    local interface
    interface=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5}' | head -n 1 || echo "eth0")
    
    if ! ip link show "$interface" >/dev/null 2>&1; then
        log_error "Network interface $interface not found"
        return 1
    fi

    local config_active="$PROJECT_ROOT/config/suricata/suricata.yaml.active"
    sed -e "s|__REPO_ROOT__|$PROJECT_ROOT|g" -e "s|__SURICATA_INTERFACE__|$interface|g" \
        "$PROJECT_ROOT/config/suricata/suricata.yaml" > "$config_active"
    
    # Remove stale PID if present
    sudo rm -f /var/run/suricata.pid >/dev/null 2>&1
    
    sudo pkill -f "suricata -c .*suricata.yaml.active" >/dev/null 2>&1 || true
    sudo suricata --af-packet -c "$config_active" -D >> "$PROJECT_ROOT/data/logs/suricata.log" 2>&1
    sleep 2
    local spid
    spid=$(pgrep -f "suricata -c .*suricata.yaml.active" | head -n 1 || true)
    [ -n "$spid" ] && update_state "suricata_pid" "$spid"
}

start_consumer() {
    log_info "Starting ML Consumer..."
    "$APP_PYTHON" "$PROJECT_ROOT/src/ml_engine/consumer.py" >> "$PROJECT_ROOT/data/logs/consumer.log" 2>&1 &
    update_state "consumer_pid" "$!"
}

start_relay() {
    log_info "Starting Relay API..."
    # Kill any existing processes on port 8000
    sudo fuser -k 8000/tcp >/dev/null 2>&1 || true
    
    "$PROJECT_ROOT/.venv/bin/python" -m uvicorn relay.app:app --host 0.0.0.0 --port 8000 --reload > "$PROJECT_ROOT/data/logs/relay.log" 2>&1 &
    local relay_pid=$!
    update_state "relay_pid" "$relay_pid"

    # Wait for Relay API to be healthy
    local RELAY_TIMEOUT=60
    local count=0
    log_info "Waiting for Relay API (timeout: ${RELAY_TIMEOUT}s)..."
    while ! curl -s http://localhost:8000/api/health > /dev/null; do
        sleep 1
        count=$((count + 1))
        if [ $count -ge $RELAY_TIMEOUT ]; then
            log_error "Relay API did not start within ${RELAY_TIMEOUT}s"
            cat "$PROJECT_ROOT/data/logs/relay.log" | tail -n 20
            exit 1
        fi
    done
    log_success "Relay API is ready"

    # Verify Suricata (give it more time if needed)
    local suricata_pid
    suricata_pid=$(grep "suricata_pid=" "$STATE_FILE" | cut -d'=' -f2 || true)
    if [ -n "$suricata_pid" ] && ! kill -0 "$suricata_pid" 2>/dev/null; then
        log_warn "Suricata PID $suricata_pid is not running. Checking if it's still initializing..."
        sleep 10
        if kill -0 "$suricata_pid" 2>/dev/null; then
             log_success "Suricata is now running"
        else
             log_warn "Suricata failed to start. Monitoring system anyway..."
        fi
    fi
}

start_ui() {
    log_info "Starting React UI..."
    cd "$PROJECT_ROOT/ui" || { log_error "Cannot cd to ui directory"; return 1; }

    # Kill any existing processes on port 3000
    sudo fuser -k 3000/tcp >/dev/null 2>&1 || true

    if [ ! -f "$PROJECT_ROOT/ui/node_modules/vite/bin/vite.js" ]; then
        log_warn "Vite binary missing. Installing UI dependencies..."
        if ! npm install --legacy-peer-deps; then
            log_error "Failed to install UI dependencies"
            cd "$PROJECT_ROOT" || return 1
            return 1
        fi
    fi

    # Start Vite via node directly to bypass permission issues on NTFS/fuseblk
    VITE_PORT=3000 VITE_BACKEND_PORT=8000 node ./node_modules/vite/bin/vite.js --host 127.0.0.1 >> "$PROJECT_ROOT/data/logs/ui.log" 2>&1 &
    update_state "ui_pid" "$!"
    cd "$PROJECT_ROOT" || return 1
}

monitor_services() {
    log_info "Starting supervisor loop..."
    while true; do
        local state_content=""
        if [ -f "$STATE_FILE" ]; then
            state_content=$(cat "$STATE_FILE" 2>/dev/null || true)
        fi
        while IFS='=' read -r key pid; do
            [ -z "$key" ] || [ -z "$pid" ] && continue
            if ! kill -0 "$pid" 2>/dev/null; then
                log_warn "Service $key (PID $pid) died. Attempting restart..."
                case "$key" in
                    ingestion_pid) start_ingestion ;;
                    consumer_pid) start_consumer ;;
                    relay_pid) start_relay ;;
                    ui_pid) start_ui ;;
                esac
            fi
        done <<< "$state_content"
        sleep 10
    done
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    mkdir -p "$PROJECT_ROOT/data/logs"
    check_lock
    ensure_sudo_access
    
    echo "================================================================="
    echo "           SENTINEL CORE: BOOT SEQUENCE ACTIVE"
    echo "================================================================="

    start_redis || exit 1
    activate_venv
    
    # Clean state
    : > "$STATE_FILE"
    
    # Parallel startup where possible
    start_ingestion
    start_suricata || log_warn "Suricata failed to start"
    start_consumer
    start_relay || exit 1
    start_ui
    
    log_success "SENTINEL CORE IS ACTIVE"
    echo "View Dashboard: http://localhost:3000"
    echo "================================================================="
    
    monitor_services
}

main "$@"
