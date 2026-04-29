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

    log_info "Environment ready"
}

# Load configuration from Python
load_config() {
    export PYTHONPATH="$PROJECT_ROOT/src:${PYTHONPATH:-}"

    if ! SURICATA_SOCKET=$(python3 -c "from src.common.config import SURICATA_SOCKET; print(SURICATA_SOCKET)" 2>/dev/null); then
        log_warn "Could not load SURICATA_SOCKET from config, using default"
        SURICATA_SOCKET="/tmp/sentinel_suricata.sock"
    fi

    if ! API_PORT=$(python3 -c "from src.common.config import API_PORT; print(API_PORT)" 2>/dev/null); then
        log_warn "Could not load API_PORT from config, using default 5000"
        API_PORT=5000
    fi

    if ! UI_PORT=$(python3 -c "from src.common.config import UI_PORT; print(UI_PORT)" 2>/dev/null); then
        log_warn "Could not load UI_PORT from config, using default 3000"
        UI_PORT=3000
    fi

    log_info "Loaded config: API_PORT=$API_PORT, UI_PORT=$UI_PORT, SURICATA_SOCKET=$SURICATA_SOCKET"
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

get_process_pid() {
    local pattern=$1
    pgrep -f "$pattern" 2>/dev/null | head -n 1
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
        if [ $((elapsed % 5)) -eq 0 ]; then
            echo -ne "[$(date +'%H:%M:%S')] Still waiting for $name... (${elapsed}s/${timeout}s)\n" | tee -a "$STARTUP_LOG_FILE"
        fi
    done

    log_error "$name did not start within ${timeout}s"
    return 1
}

check_port_conflict() {
    local port=$1
    local service=$2

    if ! is_port_available "$port"; then
        local pid
        pid=$(lsof -i :"$port" -t 2>/dev/null | head -n 1)
        
        if [ -n "$pid" ]; then
            log_warn "Port $port occupied by PID $pid ($service)"
            log_warn "Attempting to stop conflicting process..."
            
            if kill "$pid" 2>/dev/null; then
                sleep 1
                if is_port_available "$port"; then
                    log_success "Port $port freed"
                    return 0
                fi
            fi

            log_error "Cannot free port $port"
            return 1
        fi
    fi
    return 0
}

# ============================================================================
# SERVICE MANAGEMENT
# ============================================================================

ensure_sudo_access() {
    log_info "Checking sudo access for Suricata management..."
    if ! sudo -n true 2>/dev/null; then
        log_warn "Sudo password may be required for Suricata"
        sudo -v || { log_error "Sudo access denied"; exit 1; }
    fi
    log_success "Sudo access confirmed"
}

cleanup_stale_processes() {
    log_info "Cleaning up stale processes..."

    # Kill stale processes (gracefully first)
    pkill -f "src/ml_engine/consumer.py" 2>/dev/null || true
    pkill -f "src/ml_engine/ingestion.py" 2>/dev/null || true
    pkill -f "src.relay.app" 2>/dev/null || true
    pkill -f "npm.*dev" 2>/dev/null || true

    sleep 1

    # Force kill if still running
    pkill -9 -f "src/ml_engine/consumer.py" 2>/dev/null || true
    pkill -9 -f "src/ml_engine/ingestion.py" 2>/dev/null || true
    pkill -9 -f "src.relay.app" 2>/dev/null || true

    log_success "Stale processes cleaned up"
}

cleanup_stale_sockets() {
    log_info "Cleaning up stale sockets..."

    if [ -S "$SURICATA_SOCKET" ]; then
        rm -f "$SURICATA_SOCKET"
        log_info "Removed stale socket: $SURICATA_SOCKET"
    fi
}

start_redis() {
    if is_process_running "redis-server"; then
        log_success "Redis is already running"
        return 0
    fi

    log_info "Starting Redis..."
    if sudo systemctl start redis-server 2>/dev/null; then
        if wait_for_condition "Redis" "redis-cli ping 2>/dev/null | grep -q PONG" 10; then
            return 0
        fi
    fi

    log_error "Failed to start Redis"
    return 1
}

start_ingestion() {
    if is_process_running "src/ml_engine/ingestion.py"; then
        log_warn "Ingestion process already running, skipping start"
        if [ -S "$SURICATA_SOCKET" ]; then
            log_success "Ingestion socket already exists"
            return 0
        fi
    fi

    > "$PROJECT_ROOT/data/logs/ingestion.log"
    log_info "Starting Ingestion Bridge..."

    python3 "$PROJECT_ROOT/src/ml_engine/ingestion.py" >> "$PROJECT_ROOT/data/logs/ingestion.log" 2>&1 &
    local pid=$!
    
    log_info "Ingestion process started (PID: $pid)"

    if wait_for_condition "Ingestion Socket" "test -S $SURICATA_SOCKET" 30; then
        echo "ingestion_pid=$pid" >> "$STATE_FILE"
        return 0
    else
        log_error "Ingestion socket not created"
        log_error "Last log entries:"
        tail -n 15 "$PROJECT_ROOT/data/logs/ingestion.log" | tee -a "$STARTUP_LOG_FILE"
        kill $pid 2>/dev/null || true
        return 1
    fi
}

start_suricata() {
    log_info "Preparing Suricata IDS sensor..."

    # Stop any running instance
    sudo systemctl stop suricata 2>/dev/null || true
    sudo service suricata stop 2>/dev/null || true
    sleep 1

    # Clean up PID file
    sudo rm -f /var/run/suricata.pid 2>/dev/null || true

    log_info "Starting Suricata sensor..."
    if sudo systemctl start suricata 2>/dev/null; then
        sleep 5  # Grace period for Suricata to initialize

        if is_process_running "suricata"; then
            log_success "Suricata is running"
            return 0
        fi
    else
        log_error "systemctl start suricata failed"
    fi

    log_error "Failed to start Suricata"
    return 1
}

start_consumer() {
    if is_process_running "src/ml_engine/consumer.py"; then
        log_warn "Consumer process already running, skipping start"
        return 0
    fi

    > "$PROJECT_ROOT/data/logs/consumer.log"
    log_info "Starting ML Consumer..."

    python3 "$PROJECT_ROOT/src/ml_engine/consumer.py" >> "$PROJECT_ROOT/data/logs/consumer.log" 2>&1 &
    local pid=$!

    log_info "Consumer process started (PID: $pid)"
    echo "consumer_pid=$pid" >> "$STATE_FILE"

    sleep 2

    if is_process_running "consumer.py"; then
        log_success "ML Consumer is running"
        return 0
    else
        log_error "ML Consumer failed to start"
        log_error "Last log entries:"
        tail -n 15 "$PROJECT_ROOT/data/logs/consumer.log" | tee -a "$STARTUP_LOG_FILE"
        return 1
    fi
}

build_ui() {
    if [ -d "$PROJECT_ROOT/ui/dist" ]; then
        log_info "React UI build already exists (skipping rebuild)"
        return 0
    fi

    log_info "Building React UI (this may take a minute)..."
    cd "$PROJECT_ROOT/ui" || return 1

    if npm run build; then
        cd "$PROJECT_ROOT" || return 1
        log_success "React UI build complete"
        return 0
    else
        cd "$PROJECT_ROOT" || return 1
        log_error "Failed to build React UI"
        return 1
    fi
}

start_relay() {
    if is_process_running "src/relay/app.py"; then
        log_warn "Relay API already running, skipping start"
        return 0
    fi

    if ! is_port_available "$API_PORT"; then
        log_error "Port $API_PORT is already in use. Cannot start Relay API."
        return 1
    fi

    log_info "Starting Relay API on port $API_PORT..."
    python3 "$PROJECT_ROOT/src/relay/app.py" >> "$PROJECT_ROOT/data/logs/relay.log" 2>&1 &
    local pid=$!
    
    log_info "Relay process started (PID: $pid)"
    echo "relay_pid=$pid" >> "$STATE_FILE"

    if wait_for_condition "Relay API" "nc -z 127.0.0.1 $API_PORT" 15; then
        return 0
    else
        log_error "Relay API failed to start on port $API_PORT"
        return 1
    fi
}

start_ui() {
    if is_process_running "npm.*dev"; then
        log_warn "UI dev server already running, skipping start"
        return 0
    fi

    if ! is_port_available "$UI_PORT"; then
        log_error "Port $UI_PORT is already in use. Cannot start Dashboard UI."
        return 1
    fi

    log_info "Starting Dashboard UI on port $UI_PORT..."
    cd "$PROJECT_ROOT/ui" || return 1
    
    # Pass port as environment variable to Vite
    export VITE_BACKEND_PORT=$API_PORT
    export VITE_PORT=$UI_PORT
    PORT=$UI_PORT npm run dev -- --host 0.0.0.0 --port "$UI_PORT" >> "$PROJECT_ROOT/data/logs/ui.log" 2>&1 &
    local pid=$!

    cd "$PROJECT_ROOT" || return 1

    log_info "UI process started (PID: $pid)"
    echo "ui_pid=$pid" >> "$STATE_FILE"

    if wait_for_condition "Dashboard UI" "nc -z 127.0.0.1 $UI_PORT" 15; then
        return 0
    else
        log_warn "Dashboard UI may still be starting..."
        return 0
    fi
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    echo "================================================================="
    echo "            SENTINEL CORE: HYBRID ML-POWERED IPS"
    echo "            Startup Sequence"
    echo "================================================================="
    echo ""

    setup_logging

    # Parse arguments
    local CLEAN_START=0
    local FORCE_REBUILD=0
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --clean) CLEAN_START=1; shift ;;
            --rebuild) FORCE_REBUILD=1; shift ;;
            *) shift ;;
        esac
    done

    # Prevent concurrent starts
    if [ -f "$STATE_LOCK_FILE" ]; then
        log_error "Another startup instance is running"
        log_error "Remove $STATE_LOCK_FILE if stuck"
        exit 1
    fi

    trap "rm -f $STATE_LOCK_FILE" EXIT
    touch "$STATE_LOCK_FILE"

    if [ "$CLEAN_START" -eq 1 ]; then
        log_info "Clean start requested..."
    fi

    if [ "$FORCE_REBUILD" -eq 1 ]; then
        log_info "Forced rebuild requested. Removing old UI build..."
        rm -rf "$PROJECT_ROOT/ui/dist"
    fi

    # Clear previous state
    rm -f "$STATE_FILE"

    # Pre-flight
    activate_venv
    load_config
    ensure_sudo_access
    cleanup_stale_processes
    cleanup_stale_sockets

    echo ""
    log_info "Starting core services with dependency ordering..."
    echo ""

    # Service startup sequence (ordered by dependencies)
    start_redis || { log_error "Failed to start Redis"; exit 1; }
    
    if [ "$CLEAN_START" -eq 1 ]; then
        log_info "Flushing Redis state..."
        redis-cli flushall || true
    fi
    echo ""

    start_ingestion || { log_error "Failed to start Ingestion"; exit 1; }
    echo ""

    start_suricata || log_warn "Suricata startup had issues (continuing anyway)"
    echo ""

    start_consumer || { log_error "Failed to start Consumer"; exit 1; }
    echo ""

    build_ui || { log_error "Failed to build UI"; exit 1; }
    echo ""

    start_relay || { log_error "Failed to start Relay"; exit 1; }
    echo ""

    start_ui || log_warn "UI startup had issues (continuing anyway)"
    echo ""

    # Verification
    log_info "Performing post-startup verification..."
    sleep 3

    local all_healthy=1
    if is_process_running "redis-server"; then
        log_success "✓ Redis is running"
    else
        log_error "✗ Redis is NOT running"; all_healthy=0
    fi

    if is_process_running "ingestion.py"; then
        log_success "✓ Ingestion Bridge is running"
    else
        log_error "✗ Ingestion Bridge is NOT running"; all_healthy=0
    fi

    if is_process_running "consumer.py"; then
        log_success "✓ ML Consumer is running"
    else
        log_error "✗ ML Consumer is NOT running"; all_healthy=0
    fi

    if is_process_running "src/relay/app.py" || is_process_running "uvicorn"; then
        log_success "✓ FastAPI Relay is running"
    else
        log_error "✗ FastAPI Relay is NOT running"; all_healthy=0
    fi

    if is_process_running "npm.*dev"; then
        log_success "✓ React UI is running"
    else
        log_error "✗ React UI is NOT running"; all_healthy=0
    fi

    echo ""
    echo "================================================================="
    if [ $all_healthy -eq 1 ]; then
        log_success "SENTINEL CORE IS NOW ACTIVE"
    else
        log_error "SOME SERVICES FAILED TO START"
    fi
    echo "================================================================="
    echo ""
    echo "[SERVICES]"
    echo "- Dashboard:         http://127.0.0.1:${UI_PORT}"
    echo "- WebSocket/REST:    http://127.0.0.1:${API_PORT}"
    echo "- Ingestion Log:     tail -f data/logs/ingestion.log"
    echo "- Consumer Log:      tail -f data/logs/consumer.log"
    echo "- Startup Log:       tail -f data/logs/startup.log"
    echo ""
    echo "[DIAGNOSTICS]"
    echo "- Check status:      ./diag.sh"
    echo "- Stop system:       ./stop.sh"
    echo ""
    echo "================================================================="

    # Tail logs if interactive
    if [ -t 1 ]; then
        log_info "Running in interactive mode. Press Ctrl+C to detach."
        tail -f "$PROJECT_ROOT/data/logs/consumer.log" &
        local tail_pid=$!
        
        # Wait for Ctrl+C
        trap "kill $tail_pid 2>/dev/null; exit" INT
        wait $tail_pid
    fi

    return $((1 - all_healthy))
}

# Auto-recovery logic
if [[ "${1:-}" == "--no-retry" ]]; then
    shift
    main "$@"
else
    if ! main "$@"; then
        echo ""
        echo "================================================================="
        echo -e "\033[1;33m[WARN] STARTUP FAILED! Attempting automatic recovery...\033[0m"
        echo "================================================================="
        echo ""
        
        # 1. Run Pre-flight to see what's wrong
        ./preflight.sh || true
        
        echo ""
        echo "[+] Running setup to repair environment..."
        if ./setup.sh; then
            echo ""
            echo -e "\033[0;32m[SUCCESS] Setup complete. Retrying startup...\033[0m"
            echo ""
            exec "$0" --no-retry "$@"
        else
            echo ""
            echo -e "\033[0;31m[ERROR] Automatic recovery failed. Please check data/logs/setup.log\033[0m"
            exit 1
        fi
    fi
fi

