#!/bin/bash
# Sentinel Core - WebSocket Connection Diagnostics
# Use this to diagnose why the Flask relay can't connect to the consumer

echo "=========================================="
echo "  WebSocket Connection Diagnostics"
echo "=========================================="
echo

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$SCRIPT_DIR}"

cd "$PROJECT_ROOT"

# 1. Check if consumer process exists
echo "[1] Consumer Process Status"
if pgrep -f "consumer.py" > /dev/null; then
    PID=$(pgrep -f "consumer.py")
    echo "  ✓ Consumer is running (PID: $PID)"
    ps aux | grep -E "consumer.py|PID" | grep -v grep
else
    echo "  ✗ Consumer is NOT running"
    echo "  → Start with: wsl bash start_ids.sh"
fi
echo

# 2. Check if WebSocket port is listening
echo "[2] WebSocket Port (8765) Status"
if ss -tlnp 2>/dev/null | grep -q ":8765"; then
    echo "  ✓ Port 8765 is listening"
    ss -tlnp 2>/dev/null | grep 8765
else
    echo "  ✗ Port 8765 is NOT listening"
    if pgrep -f "consumer.py" > /dev/null; then
        echo "  → Consumer running but port not responding"
        echo "  → Check consumer logs for startup errors"
    fi
fi
echo

# 3. Check Suricata status
echo "[3] Suricata IDS Status"
if systemctl is-active --quiet suricata; then
    echo "  ✓ Suricata is running"
else
    echo "  ✗ Suricata is NOT running"
    echo "  → Start with: sudo systemctl start suricata"
fi
echo

# 4. Check EVE JSON file
echo "[4] Suricata EVE JSON File"
if [ -f "/var/log/suricata/eve.json" ]; then
    SIZE=$(wc -c < /var/log/suricata/eve.json)
    LINES=$(wc -l < /var/log/suricata/eve.json)
    echo "  ✓ EVE file exists"
    echo "    Size: $SIZE bytes"
    echo "    Lines: $LINES"
    echo "    Permissions: $(ls -l /var/log/suricata/eve.json | awk '{print $1, $3, $4}')"
    if [ $LINES -gt 0 ]; then
        echo "    Last line: $(tail -n 1 /var/log/suricata/eve.json | head -c 80)..."
    fi
else
    echo "  ✗ EVE file NOT found at /var/log/suricata/eve.json"
fi
echo

# 5. Check consumer logs
echo "[5] Consumer Log Status"
if [ -f "data/logs/consumer.log" ]; then
    LINES=$(wc -l < data/logs/consumer.log)
    echo "  ✓ Consumer log exists ($LINES lines)"
    echo
    echo "  Last 20 lines:"
    echo "  ----"
    tail -n 20 data/logs/consumer.log | sed 's/^/  /'
    echo "  ----"
else
    echo "  ✗ Consumer log NOT found"
fi
echo

# 6. Check Redis status (if using Redis mode)
echo "[6] Redis Status"
if redis-cli ping >/dev/null 2>&1; then
    echo "  ✓ Redis is running"
    DEPTH=$(redis-cli LLEN sentinel_alerts_queue 2>/dev/null || echo "N/A")
    echo "    Queue depth: $DEPTH"
else
    echo "  ✗ Redis is NOT running (may be normal in legacy mode)"
fi
echo

# 7. Check Python dependencies
echo "[7] Python Dependencies"
python3 -c "import websockets" 2>/dev/null && echo "  ✓ websockets" || echo "  ✗ websockets"
python3 -c "import pandas" 2>/dev/null && echo "  ✓ pandas" || echo "  ✗ pandas"
python3 -c "import sklearn" 2>/dev/null && echo "  ✓ scikit-learn" || echo "  ✗ scikit-learn"
python3 -c "import redis" 2>/dev/null && echo "  ✓ redis" || echo "  ✗ redis"
echo

# 8. Network connectivity
echo "[8] Network Connectivity"
echo "  Checking localhost:8765 accessibility..."
if timeout 2 python3 -c "import socket; s=socket.socket(); s.connect(('127.0.0.1', 8765)); s.close()" 2>/dev/null; then
    echo "  ✓ localhost:8765 is reachable"
else
    echo "  ✗ localhost:8765 is NOT reachable"
fi
echo

# 9. Summary and recommendations
echo "=========================================="
echo "  Diagnostics Summary"
echo "=========================================="

ISSUES=0

if ! pgrep -f "consumer.py" > /dev/null; then
    echo "[!] Consumer process not running"
    ISSUES=$((ISSUES + 1))
fi

if ! ss -tlnp 2>/dev/null | grep -q ":8765"; then
    echo "[!] WebSocket port not listening"
    ISSUES=$((ISSUES + 1))
fi

if ! systemctl is-active --quiet suricata; then
    echo "[!] Suricata not running"
    ISSUES=$((ISSUES + 1))
fi

if [ ! -f "/var/log/suricata/eve.json" ]; then
    echo "[!] EVE JSON file not found"
    ISSUES=$((ISSUES + 1))
fi

if [ $ISSUES -eq 0 ]; then
    echo "✓ All checks passed - system appears healthy"
    echo ""
    echo "If Flask relay still can't connect:"
    echo "  1. Check Windows firewall settings"
    echo "  2. Verify WSL networking configuration"
    echo "  3. Run: wsl netstat -tlnp | grep 8765"
    echo "  4. Check Flask logs for connection errors"
else
    echo "Found $ISSUES issue(s) to resolve."
    echo ""
    if ! pgrep -f "consumer.py" > /dev/null; then
        echo "To fix consumer not running:"
        echo "  wsl bash start_ids.sh"
    fi
    if ! systemctl is-active --quiet suricata; then
        echo "To fix Suricata not running:"
        echo "  wsl -u root systemctl start suricata"
    fi
fi

echo ""
echo "=========================================="
