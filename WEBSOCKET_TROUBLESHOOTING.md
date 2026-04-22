# WebSocket Connection Troubleshooting Guide

## Issue: WinError 1225 - Connection Refused

**What it means**: The Flask relay on Windows is trying to connect to `ws://127.0.0.1:8765` but getting "The remote computer refused the network connection."

**Root causes**:
1. ❌ Consumer process isn't running in WSL
2. ❌ WebSocket server isn't binding to the port
3. ❌ Firewall blocking WSL↔Windows communication
4. ❌ Port 8765 already in use
5. ❌ Network misconfiguration

---

## Diagnosis Steps

### Step 1: Run Diagnostics
```bash
wsl bash diagnose_websocket.sh
```

This will check:
- Consumer process status
- WebSocket port listening
- Suricata status
- EVE JSON file
- Consumer logs
- Python dependencies
- Network connectivity

### Step 2: Check Consumer Logs
```bash
wsl tail -f data/logs/consumer.log
```

Look for:
- `[WS] WebSocket server online at ws://0.0.0.0:8765` = Success
- `ERROR` or `Exception` = Check error message
- `Traceback` = Python error occurred

### Step 3: Verify Port is Listening
```bash
wsl netstat -tlnp | grep 8765
```

Expected output:
```
tcp  0  0 0.0.0.0:8765  0.0.0.0:*  LISTEN  <PID>/python3
```

If nothing shows, the consumer isn't listening.

### Step 4: Check Process Status
```bash
wsl ps aux | grep consumer.py
```

Should show a running Python process. If not found, consumer crashed.

---

## Common Issues & Fixes

### Issue A: Consumer Not Running

**Symptoms**:
- `diagnose_websocket.sh` shows "Consumer is NOT running"
- No process for consumer.py in `ps aux`

**Fix**:
```bash
# Start the consumer
wsl bash start_ids.sh

# If it crashes, check logs
wsl tail -f data/logs/consumer.log

# Look for Python errors like:
# - ImportError: No module named 'redis'
# - FileNotFoundError: /var/log/suricata/eve.json
# - Address already in use
```

**If it keeps crashing**:
1. Check Python dependencies:
   ```bash
   wsl pip3 install websockets pandas scikit-learn redis
   ```

2. Check Suricata is running:
   ```bash
   wsl -u root systemctl start suricata
   ```

3. Check EVE file exists:
   ```bash
   wsl ls -lh /var/log/suricata/eve.json
   ```

---

### Issue B: Consumer Running But Port Not Listening

**Symptoms**:
- `ps aux` shows consumer.py running
- `netstat -tlnp` shows nothing on port 8765
- Consumer logs show initialization errors

**Fix**:
```bash
# Check consumer logs for errors
wsl tail -n 50 data/logs/consumer.log

# Common errors:
# "Address already in use" → Port is taken by something else
# "Permission denied" → May need root
# "Socket error" → Network misconfiguration
```

**If port is in use**:
```bash
# Find what's using port 8765
wsl netstat -tlnp | grep 8765

# Kill the process using it
wsl -u root kill -9 <PID>

# Restart consumer
wsl bash start_ids.sh
```

---

### Issue C: Consumer Running & Listening But Flask Still Can't Connect

**Symptoms**:
- `netstat` shows port 8765 listening
- Consumer logs show success
- Flask relay still gets WinError 1225

**This is a Windows↔WSL networking issue**

**Fix**:
1. Check WSL networking mode:
   ```powershell
   # In Windows PowerShell
   wsl -- cat /proc/sys/net/ipv4/ip_forward
   # Should return: 1
   ```

2. Verify WSL is using bridge networking:
   ```powershell
   # Test connectivity from Windows
   Test-NetConnection -ComputerName 127.0.0.1 -Port 8765
   ```

3. If connection fails, try using WSL's actual IP:
   ```bash
   # In WSL, get the IP address
   wsl hostname -I
   ```
   
   Then test from Windows:
   ```powershell
   Test-NetConnection -ComputerName <WSL_IP> -Port 8765
   ```

4. If WSL IP works but localhost doesn't, update Flask relay to use:
   ```python
   # Get WSL IP
   wsl_ip = subprocess.check_output(['wsl', 'hostname', '-I']).decode().strip().split()[0]
   WS_URI = f"ws://{wsl_ip}:8765"
   ```

---

### Issue D: Suricata Not Running

**Symptoms**:
- EVE file hasn't been updated
- No alerts are being generated
- Consumer logs show "No events to process"

**Fix**:
```bash
# Start Suricata
wsl -u root systemctl start suricata

# Verify it's running
wsl -u root systemctl status suricata

# Check it's generating EVE logs
wsl tail -f /var/log/suricata/eve.json
```

---

### Issue E: Redis Not Running (Redis Mode)

**Symptoms**:
- Startup logs show "Redis not running"
- Consumer falls back to legacy mode
- Queue is empty: `redis-cli LLEN sentinel_alerts_queue`

**Fix**:
```bash
# Start Redis
wsl -u root redis-server --daemonize yes --logfile /var/log/redis/redis-server.log

# Verify it's running
wsl redis-cli ping
# Should return: PONG

# Check queue
wsl redis-cli LLEN sentinel_alerts_queue
```

---

## Quick Diagnostic Commands

```bash
# Everything at once
wsl bash diagnose_websocket.sh

# Just the port
wsl netstat -tlnp | grep 8765

# Just the process
wsl ps aux | grep consumer.py

# Just the logs (last 30 lines)
wsl tail -n 30 data/logs/consumer.log

# Just test connectivity
wsl python3 -c "import socket; s=socket.socket(); s.connect(('127.0.0.1', 8765)); s.close(); print('OK')"
```

---

## Windows Firewall & Network Settings

### If connectivity still fails after above steps:

1. **Check Windows Firewall**:
   ```powershell
   # Open Windows Defender Firewall with Advanced Security
   # Allow Python inbound/outbound on port 8765
   ```

2. **WSL Specific**:
   ```powershell
   # Restart WSL
   wsl --shutdown
   wsl --list --running  # Should be empty
   # Then start again: wsl bash start_ids.sh
   ```

3. **Nuclear option** (if all else fails):
   ```powershell
   # Factory reset WSL
   wsl --unregister Ubuntu-22.04
   wsl --install -d Ubuntu-22.04
   # Re-run setup: .\start.bat --force-setup
   ```

---

## Monitoring During Startup

Use this to watch everything during startup:

```bash
# Terminal 1: Watch the consumer starting
wsl tail -f data/logs/consumer.log

# Terminal 2: Watch the port
while true; do wsl netstat -tlnp | grep 8765; sleep 1; done

# Terminal 3: Start consumer
wsl bash start_ids.sh
```

---

## Expected Startup Flow

```
[IDS] Starting ML consumer...
[IDS] Pipeline: Redis Queue (or Legacy Polling)
[IDS] Waiting for consumer to initialize...
[IDS] Consumer process running (PID XXXX)
[IDS] Verifying WebSocket server is listening...
[IDS] WebSocket server is listening on port 8765
[IDS] Consumer running (PID XXXX)
[IDS] WebSocket: ws://0.0.0.0:8765
[IDS] Logs: /path/to/data/logs/consumer.log

[SUCCESS] IDS Pipeline Online and Ready
```

If you don't see "WebSocket server is listening", check the logs for the error.

---

## Getting More Verbose Logging

If the standard logs don't show the issue:

```bash
# Run consumer with full Python output
wsl python3 -u src/ml_engine/consumer.py

# This will show all print statements and errors in real-time
# Press Ctrl+C to stop
```

---

## Still Not Working?

Collect this information:

```bash
# 1. Full diagnostic output
wsl bash diagnose_websocket.sh > /tmp/diagnostics.txt

# 2. Full consumer log (last 100 lines)
wsl tail -n 100 data/logs/consumer.log > /tmp/consumer.log

# 3. Check if Flask relay is even trying
wsl tail -f data/logs/consumer.log  # While relay is running

# 4. Check exact error message
# Copy the "WinError" message completely
```

Then review:
- `STARTUP_GUIDE.md` - General troubleshooting
- `REDIS_IMPLEMENTATION.md` - Redis-specific issues
- Consumer logs - Python errors

---

## Prevention

To avoid this in the future:

1. **Before running `start.bat`, verify**:
   ```bash
   # Check WSL can connect to itself
   wsl python3 -c "import socket; s=socket.socket(); s.connect(('127.0.0.1', 8765)); s.close()" || echo "FAIL"
   ```

2. **Always use `diagnose_websocket.sh` after changes**:
   ```bash
   wsl bash diagnose_websocket.sh
   ```

3. **Keep consumer running under supervision**:
   ```bash
   wsl bash -c "while true; do python3 src/ml_engine/consumer.py; sleep 5; done"
   ```

---

**Need help?** Check the logs! Most issues are visible in `data/logs/consumer.log`.
