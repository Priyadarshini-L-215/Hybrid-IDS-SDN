# Sentinel Core - Startup Guide

## Quick Start

### Option 1: Full System (Recommended)
```bash
cd D:\projects\FYP
.\start.bat
```
This launches:
- WSL IDS Pipeline (Suricata + ML Consumer)
- Flask Backend API relay
- React Dashboard UI
- Redis (if enabled)

### Option 2: Legacy Mode (Polling)
```bash
.\start.bat --legacy
```
Uses single-threaded polling instead of Redis queue.

### Option 3: Force Full Setup
```bash
.\start.bat --force-setup
```
Skips setup stamp and re-runs all dependency checks.

### Option 4: WSL-Only (IDS Pipeline Only)
```bash
wsl bash start_wsl_only.sh
```
Useful for testing just the IDS without UI.

---

## Pipeline Modes

### Redis Queue (Optimized) - Default
**When**: `USE_REDIS_QUEUE=1` (default)
**Features**:
- Async file watching (10ms detection)
- Redis message queue
- 4 parallel workers
- Batch flushing (1s interval or 50 events)

**Expected Performance**:
- Latency: 10-50ms per event (5-10x faster)
- Throughput: 500-1000+ events/sec (10x higher)

**Requires**:
- Redis server running in WSL
- Redis Python client (auto-installed)

### Legacy Polling (Compatibility)
**When**: `USE_REDIS_QUEUE=0`
**Features**:
- 100ms polling interval
- Single-threaded processing
- Direct database writes
- File rotation handling

**Expected Performance**:
- Latency: 50-185ms per event
- Throughput: 40-100 events/sec

**Requires**:
- No additional dependencies
- Works if Redis unavailable

---

## What start.bat Does

1. **Verification** (30s)
   - Checks WSL installation
   - Verifies Python venv
   - Validates UI dependencies
   - Installs Suricata if missing
   - Starts Redis (if enabled)

2. **Cleanup** (5s)
   - Stops old processes
   - Clears stale terminal windows

3. **Launch** (10s)
   - WSL IDS Pipeline in terminal "IDS Core (WSL)"
   - Flask Backend in terminal "Backend (Relay)"
   - React UI in terminal "Frontend (SOC)"

4. **Monitoring** (ongoing)
   - Displays URLs for each service
   - Shows pipeline mode (Redis or Legacy)
   - Provides troubleshooting tips

---

## Accessing the System

| Service | URL | Notes |
|---------|-----|-------|
| Dashboard | http://localhost:5173 | React UI |
| WebSocket | ws://127.0.0.1:8765 | Real-time alerts |
| Flask API | http://localhost:5000 | REST endpoints |
| Redis | redis://127.0.0.1:6379 | Message queue (Redis mode only) |

---

## Troubleshooting

### Issue: "WSL2 is required but not found"
**Solution**:
```powershell
# Install WSL2
wsl --install
wsl --list --online
wsl --install -d Ubuntu-22.04
```

### Issue: "Suricata not found in WSL"
**Solution**:
```bash
wsl -u root bash -c "apt-get update && apt-get install -y suricata"
```

### Issue: "Redis not running" (in Redis mode)
**Solution**:
```bash
wsl -u root bash -c "apt-get install -y redis-server && redis-server --daemonize yes"
wsl redis-cli ping  # Should return PONG
```

### Issue: "Consumer crashed immediately"
**Solution**:
```bash
wsl tail -f data/logs/consumer.log
# Check last 30 lines for error details
```

### Issue: "Python dependencies missing"
**Solution**:
```bash
wsl pip3 install websockets pandas scikit-learn redis
```

### Issue: Port Already in Use
**Solution**:
```powershell
# Find and kill process using port
netstat -ano | findstr :5173   # UI port
netstat -ano | findstr :5000   # Flask port
netstat -ano | findstr :8765   # WebSocket port

# Kill by PID
taskkill /PID <PID> /F
```

### Issue: "Redis connection refused" (with legacy mode working)
**Solution**:
```bash
# Fall back to legacy:
start.bat --legacy

# Or check Redis:
wsl redis-cli ping
wsl redis-cli INFO server
```

---

## Monitoring

### View Consumer Logs (Real-time)
```bash
wsl tail -f data/logs/consumer.log
```

### Check Redis Queue Depth
```bash
wsl redis-cli LLEN sentinel_alerts_queue
```

### Check Redis Memory
```bash
wsl redis-cli INFO memory
```

### Check Process Status
```bash
# WSL processes
wsl ps aux | grep consumer.py
wsl ps aux | grep suricata
wsl ps aux | grep redis-server

# Windows processes
tasklist | findstr consumer
tasklist | findstr Flask
tasklist | findstr Vite
```

---

## Stopping the System

### Graceful Shutdown
```bash
.\stop.bat
```
This:
- Stops Flask backend
- Stops React frontend
- Stops IDS pipeline
- Gracefully shuts down Redis
- Cleans up child processes

### Force Kill (If graceful fails)
```powershell
taskkill /F /FI "WINDOWTITLE eq *IDS Core*"
taskkill /F /FI "WINDOWTITLE eq *Backend*"
taskkill /F /FI "WINDOWTITLE eq *Frontend*"
wsl -u root pkill -9 redis-server
```

---

## Environment Variables

### On Windows (PowerShell)
```powershell
# Use Redis pipeline
$env:USE_REDIS_QUEUE = "1"

# Use legacy polling
$env:USE_REDIS_QUEUE = "0"

# Then launch
.\start.bat
```

### In WSL
```bash
# Use Redis pipeline
export USE_REDIS_QUEUE=1

# Use legacy polling
export USE_REDIS_QUEUE=0

# Then launch
bash start_ids.sh
```

---

## Performance Validation

### Run Validation Suite
```bash
cd D:\projects\FYP
pytest tests/
```

Expected output:
```
✓ PASS: Redis Connection
✓ PASS: Queue Operations
✓ PASS: AsyncFileWatcher
✓ PASS: WorkerPool
✓ PASS: Pipeline Mode
✓ PASS: Configuration

Result: 6/6 tests passed
Status: SYSTEM READY FOR DEPLOYMENT
```

### Test with Simulated Traffic
```bash
# Generate test alerts
wsl python3 src/dashboard/nmap_runner.py
```

### Measure Latency
Check `data/logs/consumer.log` for timestamps:
- "extract_time": Feature extraction duration (0.5-2ms)
- "predict_time": ML prediction duration (0.1-5ms)
- Total per-event: ~10-50ms (Redis) or ~50-185ms (Legacy)

---

## Quick Reference

| Command | Purpose |
|---------|---------|
| `.\start.bat` | Start full system (Redis optimized) |
| `.\start.bat --legacy` | Start with legacy polling |
| `.\start.bat --force-setup` | Force full dependency check |
| `.\stop.bat` | Graceful shutdown |
| `wsl bash start_wsl_only.sh` | Start IDS pipeline only |
| `pytest tests/` | Validate System |
| `wsl tail -f data/logs/consumer.log` | View consumer logs |
| `wsl redis-cli LLEN sentinel_alerts_queue` | Check queue depth |

---

## Getting Help

1. **Check Logs**: `wsl tail -f data/logs/consumer.log`
2. **Validate Setup**: `pytest tests/`
3. **Check Processes**: `wsl ps aux | grep -E "consumer|suricata|redis"`
4. **Verify Connectivity**: `wsl redis-cli ping` (should return PONG)
5. **Review Documentation**: See `REDIS_IMPLEMENTATION.md`

---

**Happy Monitoring!** 🛡️
