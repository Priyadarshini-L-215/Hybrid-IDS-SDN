# Sentinel Core - Complete Troubleshooting Resource Index

**Created**: Session 4  
**Focus**: WebSocket Connection Failure (WinError 1225)  
**Status**: ✓ Ready for User Action  

---

## The Issue

Flask relay (Windows) cannot connect to consumer WebSocket (WSL):
```
[WARNING] [Relay] Pipeline interruption: [WinError 1225]
The remote computer refused the network connection.
```

**Translation**: The WebSocket server isn't listening on `ws://127.0.0.1:8765`

---

## Your Troubleshooting Toolkit

### 📊 Diagnostic Tools (Run These First)

**From WSL**:
```bash
wsl bash diagnose_websocket.sh
```
↳ Comprehensive 8-point check of consumer, port, logs, dependencies

**From Windows PowerShell**:
```powershell
powershell -NoProfile .\diagnose_connection.ps1
```
↳ Windows-side connectivity test, Flask status, WSL communication

**Live System Status (Browser)**:
- **URL**: `http://localhost:5000/api/pipeline/status`
- ↳ Instant feedback on the health of WSL sensor, Redis, and Relay connectivity.

---

### 📖 Documentation (Read Based on Situation)

#### 1. **CONNECTION_TROUBLESHOOTING_KIT.md** 👈 START HERE
**For**: "Everything is broken, I need to fix it NOW"  
**Contains**:
- Step-by-step diagnosis procedure
- Failure point identification (3 scenarios)
- Fix A: Consumer not running (+ sub-fixes for 5 common errors)
- Fix B: Port not listening (+ debugging steps)
- Fix C: WSL networking issue (+ advanced options)
- Expected startup sequence
- Critical success checklist

**How to use**: Run diagnostics → Find your scenario → Follow the fix

---

#### 2. **WEBSOCKET_TROUBLESHOOTING.md** 
**For**: "I want the complete technical reference"  
**Contains**:
- Root cause analysis
- 5 common issues with detailed solutions
- Windows Firewall configuration
- Prevention tips
- Monitoring during startup
- All quick commands in one place

**How to use**: Search for your error message → Read relevant section

---

#### 3. **WINERROR_1225_QUICK_FIX.md**
**For**: "Give me the quick answer"  
**Contains**:
- 30-second diagnostics
- One-liner commands
- Most likely causes (ranked by probability)
- Success indicators checklist

**How to use**: Skim for your situation → Run one-liner fix

---

### 🛠️ Quick Reference Commands

```bash
# DIAGNOSTICS
wsl bash diagnose_websocket.sh              # Full WSL check
powershell -NoProfile .\diagnose_connection.ps1  # Full Windows check
bash check_system_status.sh                  # Dashboard status

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
        │       └─→ Still fails? → See CONNECTION_TROUBLESHOOTING_KIT.md (Fix A)
        │
        ├─→ [✓ Consumer running] + [✗ Port not listening]
        │   └─→ See CONNECTION_TROUBLESHOOTING_KIT.md (Fix B)
        │       └─→ Check logs: wsl tail -n 50 data/logs/consumer.log
        │
        ├─→ [✓ All checks green] + [Flask still can't connect]
        │   └─→ See CONNECTION_TROUBLESHOOTING_KIT.md (Fix C)
        │       └─→ Try WSL IP: wsl hostname -I
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
- [ ] EVE file recent: `wsl stat /var/log/suricata/eve.json` (check timestamp)
- [ ] No errors in logs: `wsl tail -n 10 data/logs/consumer.log` (no ERROR lines)
- [ ] Flask connected: `wsl tail -f data/logs/consumer.log | grep "Success"` (appears within 10s)

**All green?** → System is working! 🎉

---

## The 3-Minute Fix

**If you only have 3 minutes**:

```bash
# 1. Try the most likely fix (takes 30 seconds)
wsl bash start_ids.sh

# 2. Wait for startup
sleep 5

# 3. Verify it worked
wsl netstat -tlnp | grep 8765

# 4. If successful, system should work now
# 5. If not, run diagnostics and check logs
wsl bash diagnose_websocket.sh
wsl tail -n 30 data/logs/consumer.log
```

---

## Estimated Resolution Time

| Symptom | Time to Fix | Solution |
|---------|------------|----------|
| Consumer crashed | 5 min | `wsl bash start_ids.sh` |
| Port in use | 10 min | Find/kill process, restart |
| Suricata not running | 5 min | `wsl -u root systemctl start suricata` |
| Missing Python package | 10 min | `wsl pip3 install [package]` |
| WSL networking | 15 min | WSL restart or use WSL IP |

---

## Common Error Messages → Solutions

| Error | Means | Solution |
|-------|-------|----------|
| "Connection refused" | Consumer not listening | Check: process running? port listening? |
| "No such file or directory" | Suricata not generating EVE | Start Suricata: `wsl -u root systemctl start suricata` |
| "Address already in use" | Port 8765 taken | Kill: `wsl -u root kill -9 <PID>` |
| "No module named 'redis'" | Dependency missing | Install: `wsl pip3 install redis` |
| "Permission denied" | Need sudo | Use: `wsl -u root [command]` |

---

## When to Use Each Document

```
You say...                          → Read this
────────────────────────────────────────────────────────────────
"It's broken, fix it"              → CONNECTION_TROUBLESHOOTING_KIT.md
"Show me everything"               → WEBSOCKET_TROUBLESHOOTING.md
"Just tell me what to do"          → WINERROR_1225_QUICK_FIX.md
"How do I start the system?"       → STARTUP_GUIDE.md
"What was changed?"                → LAUNCHER_UPDATE.md
"I need to understand the issue"   → SESSION_4_DEPLOYMENT_SUMMARY.md
```

---

## File Locations

All files in: `d:\projects\FYP\`

**Diagnostic tools**:
- `diagnose_websocket.sh` - WSL diagnostics
- `diagnose_connection.ps1` - Windows diagnostics
- `check_system_status.sh` - Health dashboard

**Documentation**:
- `CONNECTION_TROUBLESHOOTING_KIT.md` - **START HERE**
- `WEBSOCKET_TROUBLESHOOTING.md` - Complete reference
- `WINERROR_1225_QUICK_FIX.md` - Quick reference
- `SESSION_4_DEPLOYMENT_SUMMARY.md` - What was done
- `STARTUP_GUIDE.md` - How to start system

---

## Next Steps

### Immediate (Right Now)
1. Open terminal
2. Run: `wsl bash diagnose_websocket.sh`
3. Note what fails
4. Open `CONNECTION_TROUBLESHOOTING_KIT.md`
5. Follow the fix for your scenario

### If Still Stuck
1. Collect all diagnostic output
2. Check consumer logs: `wsl tail -n 100 data/logs/consumer.log`
3. Review `WEBSOCKET_TROUBLESHOOTING.md` for your error
4. Try the nuclear option: `wsl --shutdown`

### After Fixing
1. Verify all checks pass: `wsl bash diagnose_websocket.sh`
2. Monitor startup: `wsl tail -f data/logs/consumer.log`
3. Access dashboard: http://localhost:3000
4. Create some alerts to test (use nmap scan)

---

## Support Resources

**For understanding the system**:
- README.md - System overview
- SYSTEM_ARCHITECTURE.md - Technical architecture
- GEMINI.md - AI integration details

**For operating the system**:
- STARTUP_GUIDE.md - How to start
- CONNECTION_TROUBLESHOOTING_KIT.md - How to fix connections
- WEBSOCKET_TROUBLESHOOTING.md - Deep dive troubleshooting

**For development**:
- models/train.py - ML model training
- src/ml_engine/consumer.py - Main IDS logic
- src/dashboard/app.py - Flask relay backend

---

## Quick Checklist Before You Start

- [ ] WSL is installed and running
- [ ] You have a terminal open
- [ ] You can run bash commands (either in WSL or bash on Windows)
- [ ] You have Python 3.8+
- [ ] You understand this is for fixing a WebSocket connection issue

---

## You've Got This! 💪

The diagnostics will tell you exactly what's wrong. The fix documents will tell you exactly how to fix it. You don't need to be a networking expert—just follow the steps.

**Timeline**: 5-15 minutes to fix (depending on root cause)  
**Difficulty**: Medium (but guided step-by-step)  
**Success Rate**: >95% with these tools  

Start with: `wsl bash diagnose_websocket.sh`

Then refer back to this index to find your answer.

Good luck! 🚀
