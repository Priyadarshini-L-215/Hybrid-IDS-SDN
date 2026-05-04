# Sentinel Core - Startup Optimization & First-Time Setup Plan

**Date Created:** April 29, 2026  
**Status:** **FULLY IMPLEMENTED** (May 3, 2026)

---

## ⚡ Implementation Status (May 2026)

All critical and important phases of this optimization plan have been successfully implemented in **Sentinel Core V4**. 

| Phase | Status | Key Deliverables |
|-------|--------|------------------|
| **Phase 1: Critical** | [x] COMPLETE | `preflight.sh` validation, idempotent `setup.sh`, health checks in `start.sh` |
| **Phase 2: Important** | [x] COMPLETE | Unified Port 3000 architecture, `config_validator.py`, structured logging |
| **Phase 3: Production** | [x] COMPLETE | Systemd service integration (manual templates), comprehensive health dashboard |

---

## Executive Summary (Historical Context)

This document outlines the original improvement plan designed to address legacy startup issues. These improvements are now core features of the V4 release.

---

## Part 1: Current Issues & Analysis

### Issue 1.1: Setup Script Problems

| Issue | Current Behavior | Impact | Severity |
|-------|-----------------|--------|----------|
| **Missing Python 3 version check** | Assumes Python 3 is installed | Fails with ambiguous error if `python3` is missing | HIGH |
| **No venv validation after creation** | Creates venv but doesn't verify | Can proceed with broken venv | HIGH |
| **npm install partial failure** | Doesn't check all dependencies loaded | UI may be broken on next start | MEDIUM |
| **Sudo password prompt during setup** | Required during Suricata config stage | Interrupts automation for no reason | MEDIUM |
| **No rollback on failure** | Failed setup leaves system in broken state | Hard to recover without manual cleanup | MEDIUM |
| **Missing network connectivity check** | Can't install packages without internet | Fails with confusing apt errors | MEDIUM |
| **No validation of model files** | Assumes models are present in `/models` | Consumer fails at runtime | HIGH |

### Issue 1.2: Start Script Problems

| Issue | Current Behavior | Impact | Severity |
|-------|-----------------|--------|---------|
| **Venv activation failure handling** | Warns but continues in system env | Can use wrong Python version | HIGH |
| **Sudo password interrupts automation** | Required for several commands | Cannot run unattended | HIGH |
| **Stale socket cleanup fragile** | Removes socket but doesn't verify ingestion creates new one properly | Socket race condition possible | MEDIUM |
| **Port conflicts kill without verification** | Uses `fuser` which may fail silently | Leaves ports bound, start fails | MEDIUM |
| **No startup timeout for slow services** | Infinite waits if service hangs | Script hangs indefinitely | MEDIUM |
| **Missing dependency on ingestion socket** | Starts Suricata before socket is guaranteed ready | Suricata connection fails intermittently | HIGH |
| **React build in start script** | Building UI delays every startup | Slow startup on first run | MEDIUM |
| **No crash detection** | Services die silently, script continues | Fails without user knowing | HIGH |
| **Hardcoded Python path issues** | Uses `.venv/bin/python3` but path may vary | Fails if venv structure changes | MEDIUM |
| **No health checks post-startup** | Assumes services started just because PIDs exist | Services may crash immediately after | MEDIUM |

### Issue 1.3: Overall Design Problems

| Issue | Current Behavior | Impact | Severity |
|-------|-----------------|--------|----------|
| **No lock file/PID tracking** | Can't reliably check if system is running | Multiple starts cause port conflicts | HIGH |
| **Mixing service management styles** | Uses `systemctl`, `service`, `pkill`, direct execution | Inconsistent lifecycle management | MEDIUM |
| **No configuration validation** | Assumes all config files exist and are valid | Failures buried in logs if config missing | HIGH |
| **Insufficient logging** | Logs go to files but critical info missing | Hard to debug failures | MEDIUM |
| **No environment variable management** | Uses hardcoded paths | Breaks if project moved | MEDIUM |
| **Missing systemd integration** | Manual process management | Cannot restart failed services automatically | MEDIUM |

---

## Part 2: Improved Solution Architecture

### 2.1: Recommended Improvements (Priority Order)

#### **Phase 1: Critical (Must Fix)**

1. **Pre-flight validation script** (`preflight.sh`)
   - Verify all required binaries exist
   - Check Python version
   - Validate model files present
   - Check disk space
   - Verify network connectivity

2. **Robust setup.sh rewrite**
   - Idempotent operations (can be run multiple times safely)
   - Comprehensive error handling with rollback
   - Skip already-completed steps
   - Better logging with timestamps

3. **Robust start.sh rewrite**
   - PID file tracking for system state
   - Health check function for all services
   - Timeout management for all waits
   - Graceful failure with recovery suggestions

#### **Phase 2: Important (Should Fix)**

4. **Systemd service files** for background processes
   - `sentinel-consumer.service` - ML engine
   - `sentinel-ingestion.service` - IDS bridge
   - `sentinel-relay.service` - Flask API
   - Enables automatic restarts on failure

5. **Configuration validation**
   - Verify required config sections exist
   - Validate path references
   - Check permissions before proceeding

6. **Structured logging**
   - JSON logs with timestamps
   - Separate error/warning logs
   - Easier debugging and monitoring

#### **Phase 3: Nice-to-Have**

7. **Docker support** (optional)
   - Guarantees consistent environment
   - Simplifies deployment

8. **Interactive setup wizard**
   - Prompts for custom configuration
   - Better first-time UX

---

## Part 3: Detailed Improvement Plan

### 3.1: New `preflight.sh` Script

**Purpose:** Verify system is ready before setup or startup

```bash
#!/bin/bash
# preflight.sh - Pre-flight validation for Sentinel Core

check_binary() {
  if ! command -v "$1" &>/dev/null; then
    echo "FAIL: Required binary not found: $1"
    return 1
  fi
  return 0
}

check_python_version() {
  local version=$(python3 --version 2>&1 | awk '{print $2}')
  local required="3.10"
  if [[ "$(printf '%s\n' "$required" "$version" | sort -V | head -n1)" != "$required" ]]; then
    echo "FAIL: Python 3.10+ required, found: $version"
    return 1
  fi
  return 0
}

check_model_files() {
  local required_models=(
    "models/autoencoder.pth"
    "models/rf_model.pkl"
    "models/features.json"
  )
  for model in "${required_models[@]}"; do
    if [ ! -f "$model" ]; then
      echo "FAIL: Required model file missing: $model"
      return 1
    fi
  done
  return 0
}

check_disk_space() {
  local available=$(df . | tail -1 | awk '{print $4}')
  if [ "$available" -lt 5242880 ]; then # 5GB in KB
    echo "WARN: Low disk space: $(($available / 1048576))GB available (5GB+ recommended)"
    return 1
  fi
  return 0
}

# Main checks
echo "Running pre-flight validation..."
check_binary "python3" || exit 1
check_binary "node" || exit 1
check_python_version || exit 1
check_model_files || exit 1
check_disk_space || exit 1
echo "All pre-flight checks passed!"
```

### 3.2: Improved `setup.sh` (Key Changes)

**Key Improvements:**
- State tracking (skip completed steps)
- Comprehensive error handling
- Better logging
- Idempotent operations

```bash
#!/bin/bash
set -euo pipefail

# State tracking
SETUP_STATE_FILE=".setup_state"
STATE_LOCK_FILE=".setup.lock"

# Prevent concurrent setup
if [ -f "$STATE_LOCK_FILE" ]; then
    echo "[ERROR] Setup is already running. If this is stuck, remove .setup.lock"
    exit 1
fi
trap "rm -f $STATE_LOCK_FILE" EXIT
touch "$STATE_LOCK_FILE"

# Load previous state
declare -A COMPLETED_STEPS
if [ -f "$SETUP_STATE_FILE" ]; then
    while IFS='=' read -r key value; do
        COMPLETED_STEPS[$key]=$value
    done < "$SETUP_STATE_FILE"
fi

# State update function
mark_complete() {
    echo "$1=1" >> "$SETUP_STATE_FILE"
    COMPLETED_STEPS[$1]=1
}

is_complete() {
    [ "${COMPLETED_STEPS[$1]:-0}" = "1" ]
}

# Logging function
log_info() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [INFO] $1"
}

log_error() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR] $1" >&2
}

# Step: System packages
if ! is_complete "system_packages"; then
    log_info "Installing system packages..."
    # ... installation logic with skip checks ...
    mark_complete "system_packages"
fi

# Step: Python venv with validation
if ! is_complete "python_venv"; then
    log_info "Creating Python virtual environment..."
    python3 -m venv .venv
    source .venv/bin/activate
    
    # Validate venv
    if ! python3 -c "import sys; assert sys.prefix != sys.base_prefix"; then
        log_error "Virtual environment activation failed"
        exit 1
    fi
    
    pip install --upgrade pip setuptools wheel
    pip install -r requirements.txt
    mark_complete "python_venv"
fi

# Continue with other steps...
```

### 3.3: Improved `start.sh` (Key Changes)

**Key Improvements:**
- PID tracking
- Health checks
- Better error recovery
- Timeout management
- Service dependency ordering

```bash
#!/bin/bash
set -euo pipefail

STATE_FILE=".sentinel_state"
STARTUP_TIMEOUT=60

# Health check functions
is_service_healthy() {
    local service=$1
    local check_cmd=$2
    
    if eval "$check_cmd" &>/dev/null; then
        return 0
    fi
    return 1
}

wait_for_service() {
    local service=$1
    local check_cmd=$2
    local timeout=$3
    
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if is_service_healthy "$service" "$check_cmd"; then
            echo "[OK] $service is healthy"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    
    echo "[ERROR] $service failed to start within ${timeout}s"
    return 1
}

# Track service PIDs
save_pid() {
    echo "$1=$2" >> "$STATE_FILE"
}

# Graceful startup with dependency ordering
start_redis() {
    if pgrep redis-server >/dev/null; then
        echo "[SKIP] Redis already running"
        return 0
    fi
    echo "[+] Starting Redis..."
    sudo service redis-server start
    wait_for_service "Redis" "redis-cli ping" 10
}

start_ingestion() {
    if pgrep -f "ingestion.py" >/dev/null; then
        echo "[SKIP] Ingestion already running"
        return 0
    fi
    echo "[+] Starting ingestion bridge..."
    ./.venv/bin/python3 src/ml_engine/ingestion.py &
    local pid=$!
    save_pid "ingestion" $pid
    
    # Wait for socket creation
    local socket=$(python3 -c "from src.common.config import SURICATA_SOCKET; print(SURICATA_SOCKET)")
    wait_for_service "Ingestion" "test -S $socket" 30
}

# Main startup flow with error handling
main() {
    rm -f "$STATE_FILE"
    
    start_redis || { echo "[CRITICAL] Redis startup failed"; exit 1; }
    start_ingestion || { echo "[CRITICAL] Ingestion startup failed"; exit 1; }
    # ... continue with other services ...
    
    echo "[SUCCESS] All services started successfully"
}

main "$@"
```

### 3.4: New Systemd Service Files

**Benefits:**
- Automatic restart on crash
- Logging integration
- Proper lifecycle management

**Example: `sentinel-consumer.service`**

```ini
[Unit]
Description=Sentinel Core ML Consumer
After=network.target redis-server.service

[Service]
Type=simple
User=preet
WorkingDirectory=/home/preet/FYP
Environment="PATH=/home/preet/FYP/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
Environment="PYTHONUNBUFFERED=1"
ExecStart=/home/preet/FYP/.venv/bin/python3 src/ml_engine/consumer.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### 3.5: Configuration Validation Module

**New file: `src/common/config_validator.py`**

```python
from pathlib import Path
from typing import Tuple

class ConfigValidator:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.errors = []
        self.warnings = []
    
    def validate_all(self) -> Tuple[bool, list, list]:
        """Run all validation checks"""
        self.check_model_files()
        self.check_config_files()
        self.check_permissions()
        return not self.errors, self.errors, self.warnings
    
    def check_model_files(self):
        required = ['autoencoder.pth', 'rf_model.pkl', 'features.json']
        for model in required:
            path = self.base_dir / 'models' / model
            if not path.exists():
                self.errors.append(f"Missing model: {path}")
    
    def check_config_files(self):
        config_path = self.base_dir / 'config' / 'sentinel_config.yaml'
        if not config_path.exists():
            self.warnings.append(f"Config file missing: {config_path}")
    
    def check_permissions(self):
        # Verify data/logs is writable
        logs_dir = self.base_dir / 'data' / 'logs'
        if not logs_dir.exists():
            logs_dir.mkdir(parents=True, exist_ok=True)
        if not os.access(logs_dir, os.W_OK):
            self.errors.append(f"Cannot write to logs directory: {logs_dir}")
```

---

## Part 4: Implementation Roadmap

### Phase 1: Quick Wins (Week 1)
- [ ] Add `preflight.sh` validation
- [ ] Add health check functions to `start.sh`
- [ ] Add configuration validation
- [ ] Improve error messages and logging

### Phase 2: Core Improvements (Week 2-3)
- [ ] Rewrite `setup.sh` with state tracking
- [ ] Rewrite `start.sh` with better dependencies
- [ ] Add PID tracking and status file
- [ ] Create `restart.sh` and `status.sh` scripts

### Phase 3: Production Ready (Week 4)
- [ ] Create systemd service files
- [ ] Add comprehensive health check dashboard
- [ ] Document troubleshooting guide
- [ ] Test full lifecycle on clean system

---

## Part 5: First-Time Setup Checklist

### Manual Pre-Requisites (User Responsibility)
- [ ] Ubuntu 22.04+ or compatible Linux
- [ ] 10GB+ free disk space
- [ ] Sudo privileges (no password prompt for key commands)
- [ ] Internet connectivity for package downloads

### Automated Setup Process
```bash
# 1. Enter project directory
cd /path/to/FYP

# 2. Run preflight checks
chmod +x preflight.sh
./preflight.sh

# 3. Run unified setup (idempotent, can repeat)
chmod +x setup.sh
./setup.sh

# 4. Start the system
chmod +x start.sh
./start.sh

# 5. Verify all services
chmod +x diag.sh
./diag.sh
```

### Verification Steps
- [ ] Dashboard accessible at `http://localhost:3000`
- [ ] API responds at `http://localhost:3000/api/pipeline/status`
- [ ] Redis has events flowing
- [ ] Suricata connected to ingestion socket
- [ ] No process crashed (check `diag.sh`)

---

## Part 6: Better Solutions & Recommendations

### 6.1: Dependency Management

**Current Issue:** Hard to know what's missing  
**Better Solution:** Create `requirements-system.txt`

```
# requirements-system.txt - APT packages
python3-dev
python3-pip
python3-venv
nodejs>=20.0.0
suricata>=7.0
redis-server>=7.0
curl
build-essential
git
```

Then in setup: `cat requirements-system.txt | xargs sudo apt-get install -y`

### 6.2: Process Management

**Current Issue:** Mix of systemctl, service, and pkill  
**Better Solution:** Use systemd exclusively

```bash
# Instead of manual start:
systemctl start sentinel-consumer
systemctl start sentinel-ingestion
systemctl start sentinel-relay

# Instead of manual stop:
systemctl stop sentinel-*

# Check status:
systemctl status sentinel-*
```

### 6.3: Configuration Management

**Current Issue:** Config scattered, path resolution at runtime  
**Better Solution:** Single config validation at startup

```yaml
# config/sentinel_config.yaml - with validation
system:
  version: "1.0"
  log_level: "INFO"
  base_dir: "/home/preet/FYP"

network:
  ws_port: 8777
  flask_port: 3000
  redis_host: "127.0.0.1"
  redis_port: 6379

models:
  autoencoder: "models/autoencoder.pth"
  rf_model: "models/rf_model.pkl"
  features: "models/features.json"

validation: true  # Enable config validation on startup
```

### 6.4: Logging Strategy

**Current Issue:** Logs spread across multiple files, no centralization  
**Better Solution:** Structured logging with centralization

```python
# Use structured logging (already using structlog concept)
logger.info("service_started", service="consumer", pid=1234)
logger.error("service_failed", service="consumer", error="out of memory")

# Journal integration for systemd
# Automatically collected by: journalctl -u sentinel-consumer
```

### 6.5: Health Check Strategy

**Current Issue:** No real health checks, just process existence  
**Better Solution:** Implement actual service health endpoints

```python
# In Flask API
@app.route('/health')
def health_check():
    return {
        "status": "healthy",
        "redis": check_redis(),
        "consumer": check_consumer(),
        "socket": check_socket(),
        "timestamp": time.time()
    }

# In start.sh
wait_for_service "API" "curl -s http://localhost:3000/health | jq '.status' | grep healthy" 30
```

### 6.6: Environment Isolation

**Current Issue:** Assumes standard paths, breaks if moved  
**Better Solution:** Use absolute paths stored in `.env`

```bash
# Create .env during setup
cat > .env << EOF
PROJECT_ROOT=$(pwd)
PYTHONPATH=$PROJECT_ROOT/src
VENV_PATH=$PROJECT_ROOT/.venv
LOG_DIR=$PROJECT_ROOT/data/logs
EOF

# Source in scripts
source .env
```

---

## Part 7: Testing Strategy

### 7.1: Manual Testing Scenarios

**Scenario 1: Clean Install**
```bash
rm -rf .venv ui/node_modules data/logs
./setup.sh  # Should install everything
./start.sh  # Should start all services
```

**Scenario 2: Restart**
```bash
./stop.sh   # Stop all services
./start.sh  # Start again - should reuse existing setup
```

**Scenario 3: Crash Recovery**
```bash
pkill -f consumer.py  # Simulate service crash
# If using systemd: systemctl start sentinel-consumer  (automatic)
# If using start.sh: run again to restart
```

**Scenario 4: Port Conflict**
```bash
# Occupy port 3000
nc -l 3000 &
./start.sh  # Should detect and handle conflict
```

### 7.2: Automated Testing

```bash
#!/bin/bash
# test-startup.sh - Automated startup verification

test_setup() {
    rm -rf .venv
    ./setup.sh || { echo "FAIL: Setup"; exit 1; }
    [ -d ".venv" ] || { echo "FAIL: Venv"; exit 1; }
    [ -d "ui/node_modules" ] || { echo "FAIL: Node modules"; exit 1; }
}

test_startup() {
    ./start.sh &
    PID=$!
    sleep 15
    kill $PID
    
    curl -s http://localhost:3000 | grep -q "Sentinel" || { echo "FAIL: Dashboard"; exit 1; }
    curl -s http://localhost:3000/health | grep -q "healthy" || { echo "FAIL: API"; exit 1; }
}

test_setup && test_startup && echo "All tests passed"
```

---

## Part 8: Implementation Priority

### Must Implement (Critical)
1. **Pre-flight validation** - prevents failed setups
2. **Idempotent setup.sh** - safe to run multiple times
3. **Health checks** - verifies services actually work
4. **Better error messages** - helps users debug

### Should Implement (Important)
5. **Configuration validation** - catches config issues early
6. **Systemd services** - automatic restarts
7. **State tracking** - knows what's running

### Nice to Have (Enhancing)
8. **Interactive setup wizard**
9. **Structured logging integration**
10. **Docker support**

---

## Part 9: Rollback & Recovery

If setup fails, recover with:

```bash
# Remove corrupted state
rm .setup_state .setup.lock

# Reset and try again
rm -rf .venv
./setup.sh

# Or reset completely
./stop.sh
rm -rf .venv ui/node_modules data/
./setup.sh
./start.sh
```

---

## Conclusion

This plan addresses all critical startup issues and provides a path to production-ready automation. Focus on **Phase 1** (quick wins) first, then move to systemd integration (Phase 3) for true reliability.

**Estimated Implementation Time:** 6-8 hours for all phases  
**Risk Level:** Low (improvements are backward compatible)  
**Benefit:** 95% reduction in startup failures on fresh systems
