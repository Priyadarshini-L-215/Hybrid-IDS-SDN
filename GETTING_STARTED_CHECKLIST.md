# ✅ Startup Improvement - Getting Started Checklist

**Status:** All improvements delivered and ready to use  
**Created:** April 29, 2026  
**Time to implement:** 15 minutes for first-time setup

---

## 📋 Files Delivered

Check these files exist in your project:

- [ ] **preflight.sh** (6.4 KB) - System validation
- [ ] **setup.sh** (13.1 KB) - Robust setup
- [ ] **start.sh** (14.6 KB) - Production startup
- [ ] **STARTUP_OPTIMIZATION_PLAN.md** (15 KB) - Complete analysis
- [ ] **IMPLEMENTATION_GUIDE.md** (12 KB) - How-to guide
- [ ] **QUICK_START_SUMMARY.md** (8 KB) - Quick reference
- [ ] **DELIVERY_SUMMARY.md** (6 KB) - Overview

**Location:** `/home/preet/FYP/`

---

## 🎯 Phase 1: Understand (5 minutes)

- [ ] Read QUICK_START_SUMMARY.md
- [ ] Understand the 3 scripts: preflight → setup → start
- [ ] Understand the improvements (state tracking, health checks)

---

## 🔧 Phase 2: Validate (2 minutes)

```bash
cd /home/preet/FYP
./preflight.sh
```

**Expected Output:**
```
[OK] Found: python3
[OK] Found: node
[OK] Python version: 3.12+
[OK] Node.js version: 20+
[OK] File exists: setup.sh
[OK] Directory exists: models
[OK] Disk space: XGB available
...
[SUCCESS] All pre-flight checks passed!
```

**If FAILED:**
- [ ] Note which checks failed
- [ ] Fix the issues (read preflight output)
- [ ] Run preflight again

**If PASSED:**
- [ ] Proceed to Phase 3

---

## 🔨 Phase 3: Setup (10 minutes)

```bash
./setup.sh
```

**Expected Output:**
```
[INFO] Checking system dependencies...
[INFO] Installing missing packages...
[INFO] Creating Python virtual environment...
[INFO] Installing Python dependencies...
[INFO] Installing UI dependencies...
[INFO] Configuring Suricata...
[SUCCESS] SENTINEL CORE SETUP IS COMPLETE!
```

**What It Does:**
- ✅ Installs system packages (redis, suricata, etc.)
- ✅ Creates Python virtual environment
- ✅ Installs Python dependencies
- ✅ Installs Node.js UI dependencies
- ✅ Configures Suricata sensor
- ✅ Creates .env configuration file
- ✅ Saves progress in .setup_state

**If SUCCESSFUL:**
- [ ] Proceed to Phase 4

**If FAILED:**
- [ ] Check data/logs/setup.log for errors
- [ ] Fix the reported issue
- [ ] Run ./setup.sh again (will resume)

---

## 🚀 Phase 4: Startup (1 minute)

```bash
./start.sh
```

**Expected Output:**
```
[INFO] Virtual environment activated
[INFO] Loaded config: WS_PORT=8777
[SUCCESS] Redis is ready
[SUCCESS] Ingestion socket ready
[SUCCESS] Suricata is running
[SUCCESS] ML Consumer is running
[OK] Ingestion Bridge is running
[OK] ML Consumer is running
[OK] FastAPI Relay is running
[OK] React UI is running

[SUCCESS] SENTINEL CORE IS NOW ACTIVE

[SERVICES]
- Dashboard:         http://127.0.0.1:3000
- WebSocket API:     ws://127.0.0.1:8777
- REST API:          http://127.0.0.1:5000
```

**What It Does:**
- ✅ Activates Python virtual environment
- ✅ Loads configuration
- ✅ Starts Redis
- ✅ Starts Ingestion Bridge
- ✅ Starts Suricata sensor
- ✅ Starts ML Consumer
- ✅ Starts FastAPI Relay
- ✅ Builds and starts React UI
- ✅ Verifies all services running
- ✅ Saves PIDs in .sentinel_state

**If SUCCESSFUL:**
- [ ] Proceed to Phase 5

**If FAILED:**
- [ ] Check data/logs/startup.log for errors
- [ ] Run ./diag.sh to check what's running
- [ ] Run ./stop.sh then ./start.sh to retry

---

## ✅ Phase 5: Verification (2 minutes)

```bash
./diag.sh
```

**Expected Output:**
```
[OK] Process running: Suricata IDS
[OK] Process running: Ingestion Bridge
[OK] Process running: Redis Queue
[OK] Process running: ML Consumer
[OK] Process running: Flask Relay
[OK] Process running: React UI

[OK] Port 6379 open: Redis
[OK] Port 8777 open: Consumer WebSocket
[OK] Port 5000 open: Flask Relay API
[OK] Port 3000 open: React UI

[OK] Ipset 'sentinel_blocks' active
[OK] Iptables chain 'SENTINEL_IPS' is active
[OK] Suricata log is live
```

**All checks passed?**
- [ ] Yes → Proceed to Phase 6
- [ ] No → Run ./stop.sh, then troubleshoot using logs

---

## 🎉 Phase 6: Test Access (1 minute)

**Open in browser:**
- [ ] http://localhost:3000 → Dashboard should load
- [ ] http://localhost:5000/api/pipeline/status → JSON response

**Expected Results:**
- ✅ Dashboard loads (should show Sentinel UI)
- ✅ API responds with JSON data
- ✅ No error messages in browser console

**If Working:**
- [ ] All phases complete! ✅

**If Not Working:**
- [ ] Check data/logs/startup.log
- [ ] Run ./diag.sh to verify services
- [ ] Check browser console for errors

---

## 📊 Post-Startup Checks

After successful startup, verify these logs exist:

- [ ] `data/logs/setup.log` - Setup history
- [ ] `data/logs/startup.log` - Startup history
- [ ] `data/logs/ingestion.log` - IDS bridge activity
- [ ] `data/logs/consumer.log` - ML engine activity
- [ ] `data/logs/relay.log` - API server activity

**Check latest log:**
```bash
tail -50 data/logs/startup.log
```

---

## 🔄 Daily Usage Pattern

### Morning: Start System
```bash
./start.sh
```

### Anytime: Check Health
```bash
./diag.sh
```

### Evening: Stop System
```bash
./stop.sh
```

### When Needed: View Logs
```bash
tail -f data/logs/consumer.log
```

---

## 🆘 Troubleshooting Quick Links

**If setup fails:**
- [ ] Run ./preflight.sh to diagnose
- [ ] Check data/logs/setup.log for details
- [ ] See IMPLEMENTATION_GUIDE.md → Troubleshooting

**If startup fails:**
- [ ] Run ./diag.sh to check status
- [ ] Check data/logs/startup.log for details
- [ ] See IMPLEMENTATION_GUIDE.md → Troubleshooting

**If ports are occupied:**
- [ ] start.sh should auto-detect
- [ ] If not, check IMPLEMENTATION_GUIDE.md

**If services crash:**
- [ ] Check data/logs/consumer.log
- [ ] Run ./stop.sh then ./start.sh again

**Complete reset if stuck:**
```bash
./stop.sh
rm .setup_state .sentinel_state
./preflight.sh
./setup.sh
./start.sh
```

---

## 📚 Documentation Reference

| Need | Document | Section |
|------|----------|---------|
| Quick overview | QUICK_START_SUMMARY.md | All |
| Step-by-step guide | IMPLEMENTATION_GUIDE.md | All |
| Troubleshooting | IMPLEMENTATION_GUIDE.md | Troubleshooting |
| What's improved | DELIVERY_SUMMARY.md | What's Different |
| Deep analysis | STARTUP_OPTIMIZATION_PLAN.md | All |

---

## ⏱️ Time Breakdown

| Phase | Time | Task |
|-------|------|------|
| 1. Understand | 5 min | Read overview |
| 2. Validate | 2 min | Run preflight.sh |
| 3. Setup | 10 min | Run setup.sh |
| 4. Startup | 1 min | Run start.sh |
| 5. Verify | 2 min | Run diag.sh |
| 6. Test | 1 min | Open browser |
| **Total** | **21 min** | Complete setup |

---

## ✨ Key Features You Now Have

- ✅ System validation before setup
- ✅ Idempotent setup (can run anytime)
- ✅ Resume interrupted setup
- ✅ Health checks after startup
- ✅ Port conflict detection & recovery
- ✅ Timestamped logs for debugging
- ✅ State tracking (.setup_state, .sentinel_state)
- ✅ Detailed error messages
- ✅ Graceful error recovery

---

## 🎯 Success Indicators

You'll know it's working when:

- ✅ preflight.sh shows mostly [OK] checks
- ✅ setup.sh completes with [SUCCESS]
- ✅ start.sh shows all services running
- ✅ diag.sh shows all [OK] status
- ✅ Dashboard loads at http://localhost:3000
- ✅ No errors in data/logs/startup.log

---

## 🚀 Ready? Start Now!

```bash
cd /home/preet/FYP
./preflight.sh
```

Then follow the output!

---

## 📝 Notes for Your Records

After successful setup, record:

- [ ] Date setup completed: _______________
- [ ] Any issues encountered: _______________
- [ ] Custom configuration used (.env): _______________
- [ ] Maintenance contact: _______________

---

## 🎉 Congratulations!

You've successfully implemented the Sentinel Core startup improvements!

**Next:** Use `./start.sh` daily to start your system.

**Questions?** Check the documentation files or review the scripts.

**Everything working?** You're done! 🎊

---

**Last Updated:** April 29, 2026  
**All files ready to use** ✅
