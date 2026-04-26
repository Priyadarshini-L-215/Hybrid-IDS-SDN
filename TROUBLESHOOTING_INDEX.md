# Sentinel Core - Troubleshooting Resource Index

**Last Updated**: 2026-04-26
**Focus**: WebSocket Connection Failure (WinError 1225)
**Status**: ✓ Optimized

---

## The Issue

Flask relay (Windows) cannot connect to consumer WebSocket (WSL):
```
[WARNING] [Relay] Pipeline interruption: [WinError 1225]
The remote computer refused the network connection.
```

**Translation**: The WebSocket server isn't listening on `ws://127.0.0.1:8765` or the port is blocked.

---

## Your Troubleshooting Toolkit

### 📊 Diagnostic Tools (Run These First)

**From WSL**:
```bash
wsl bash diagnose_websocket.sh
```
↳ Comprehensive check of consumer, port, logs, and dependencies.

**From Windows PowerShell**:
```powershell
powershell -NoProfile .\diagnose_connection.ps1
```
↳ Windows-side connectivity test, Flask status, and WSL communication check.

**Live System Status (Browser)**:
- **URL**: `http://localhost:5000/api/pipeline/status`
- ↳ Instant feedback on the health of WSL sensor, Redis, and Relay connectivity.

---

### 📖 Documentation (Read Based on Situation)

#### 1. **WEBSOCKET_TROUBLESHOOTING.md** 👈 START HERE
**For**: "WebSocket connection issues (WinError 1225)"
**Contains**:
- Root cause analysis
- 5 common issues with detailed solutions
- Windows Firewall configuration
- Monitoring during startup
- Quick fix commands

#### 2. **ONBOARDING_ANALYSIS.md**
**For**: "I want the complete technical reference"
**Contains**:
- System architecture deep dive
- Data flow (Input → Processing → Output)
- Module organization
- Setup & Entry points reference

#### 3. **STARTUP_GUIDE.md**
**For**: "How do I install and start the system?"
**Contains**:
- Prerequisites
- Unified setup vs Manual setup
- Launch options
- Version requirements

---

### 🛠️ Quick Reference Commands

```bash
# DIAGNOSTICS
wsl bash diagnose_websocket.sh              # Full WSL check
powershell -NoProfile .\diagnose_connection.ps1  # Full Windows check
wsl bash check_system_status.sh              # Health dashboard status

# QUICK CHECKS
wsl pgrep -f consumer.py                    # Is process running?
wsl netstat -tlnp | grep 8765              # Is port listening?
wsl -u root systemctl status suricata       # Is Suricata active?
wsl tail -n 20 data/logs/consumer.log       # Any errors in logs?

# MOST LIKELY FIX (Try this first)
wsl bash start_ids.sh                       # Restart consumer

# NUCLEAR OPTION (If all else fails)
wsl --shutdown
# Wait 10 seconds
wsl bash start_ids.sh
```

---

## Problem Decision Tree

```
Run: wsl bash diagnose_websocket.sh
        |
        ├─→ [✗ Consumer not running]
        │   └─→ Try: wsl bash start_ids.sh
        │       └─→ Still fails? → Check data/logs/consumer.log
        │
        ├─→ [✓ Consumer running] + [✗ Port not listening]
        │   └─→ Check logs: wsl tail -n 50 data/logs/consumer.log
        │
        ├─→ [✓ All checks green] + [Flask still can't connect]
        │   └─→ Try WSL IP: wsl hostname -I
        │
        └─→ [Need more help]
            └─→ Read: WEBSOCKET_TROUBLESHOOTING.md (complete reference)
```

---

## Success Verification

After applying a fix, verify with this checklist:

- [ ] Consumer process visible: `wsl ps aux | grep consumer.py`
- [ ] Port listening: `wsl netstat -tlnp | grep 8765` (shows LISTEN)
- [ ] Suricata active: `wsl -u root systemctl is-active suricata` (shows `active`)
- [ ] EVE file recent: `wsl stat data/logs/eve.json` (check timestamp)
- [ ] No errors in logs: `wsl tail -n 10 data/logs/consumer.log` (no ERROR lines)
- [ ] Flask connected: `wsl tail -f data/logs/consumer.log | grep "Success"` (appears within 10s)

---

## File Locations

All files in: `d:\projects\FYP\`

**Diagnostic tools**:
- `diagnose_websocket.sh` - WSL diagnostics
- `diagnose_connection.ps1` - Windows diagnostics
- `check_system_status.sh` - Health dashboard

**Documentation**:
- `WEBSOCKET_TROUBLESHOOTING.md` - **START HERE** for connection issues
- `STARTUP_GUIDE.md` - How to start system
- `README.md` - System overview
- `SYSTEM_ARCHITECTURE.md` - Technical architecture
- `ONBOARDING_ANALYSIS.md` - Complete technical deep dive
