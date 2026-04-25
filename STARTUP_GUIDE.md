# Sentinel Core - Startup Guide

## Quick Start

### Option 1: Full System (Recommended)
```bash
cd D:\projects\FYP
.\start.bat
```
This launches:
- **IDS Core (WSL)**: Suricata + Redis + ML Consumer
- **Backend (Relay)**: Flask Bridge
- **Frontend (SOC)**: React Dashboard
- **Redis**: Automated initialization in WSL

### Option 2: Legacy Mode (Polling)
```bash
.\start.bat --legacy
```
Uses single-threaded polling instead of the high-performance Redis queue.

---

## Pipeline Modes

### Redis Queue (Optimized) - Default
**When**: `USE_REDIS_QUEUE=1` (default)
**Features**:
- **Async File Watching**: Sub-10ms event detection.
- **Worker Pool**: 4 parallel threads for feature extraction and ML inference.
- **Redis Ingestion**: Decouples packet capture from analysis.

**Expected Performance**:
- **Latency**: 10-30ms end-to-end.
- **Throughput**: 1000+ events/sec.

### Legacy Polling (Compatibility)
**When**: `USE_REDIS_QUEUE=0`
**Features**:
- 100ms polling interval.
- Single-threaded processing.
- No Redis dependency.

---

## What start.bat Does

1. **System Check**: Verifies WSL2, Python venv, and Node.js.
2. **Auto-Provisioning**: Installs Suricata, Redis, and dependencies if missing.
3. **Synchronization**: Ensures WSL is ready before launching the Windows relay.
4. **Multi-Terminal Orchestration**: Spawns independent windows for each component for easier debugging.

---

## Access & Diagnostics

| Service | URL / Path | Notes |
|---------|------------|-------|
| **Dashboard** | http://localhost:3000 | Primary SOC Interface |
| **Relay Status** | http://localhost:5000/api/pipeline/status | **Live Diagnostics** |
| **Flask API** | http://localhost:5000 | Backend REST Root |
| **Consumer Logs** | `wsl tail -f data/logs/consumer.log` | Real-time sensor logs |

---

## Troubleshooting

### Issue: Pipeline Interruption (Relay Failure)
**Solution**: 
1. Check the live diagnostic endpoint: http://localhost:5000/api/pipeline/status
2. It will tell you exactly which component (WSL, Redis, Consumer) is failing.
3. Use the **Reconnect** button in the dashboard or call:
   `Invoke-RestMethod -Method Post http://localhost:5000/api/relay/reconnect`

### Issue: "WSL2 is required but not found"
**Solution**:
```powershell
wsl --install
wsl --install -d Ubuntu-22.04
```

### Issue: Redis Connection Refused
**Solution**:
```bash
wsl -u root redis-server --daemonize yes
wsl redis-cli ping  # Should return PONG
```

### Issue: Database Locking (SQLite)
**Solution**:
The system now uses **WAL (Write-Ahead Logging)** mode. If locks persist, ensure no stale Python processes are holding the file:
```bash
wsl fuser data/alerts.db
```

---

## Performance Validation

### Run Validation Suite
```bash
pytest tests/
```

Expected output:
```
✓ PASS: Redis Connection
✓ PASS: AsyncFileWatcher Initialization
✓ PASS: WorkerPool Concurrency
✓ PASS: WAL Mode Verification
✓ PASS: WebSocket Bridge Integrity

Result: 5/5 tests passed
```

### Measure Latency
The system includes **Tracer Probes**. Check `consumer.log` for T1-T5 timestamps to measure precision latency across the WSL↔Windows bridge.

---

## Quick Reference

| Command | Purpose |
|---------|---------|
| `.\start.bat` | Start full system (Optimized) |
| `.\stop.bat` | Graceful shutdown |
| `wsl bash check_system_status.sh` | Full system health check |
| `wsl tail -f data/logs/consumer.log` | View sensor activity |
| `wsl redis-cli LLEN sentinel_alerts_queue` | Check queue depth |

---

**Happy Monitoring!** 🛡️
