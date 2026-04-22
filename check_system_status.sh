#!/bin/bash
# Sentinel Core - Comprehensive System Status Check
# Usage: ./check_system_status.sh

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         Sentinel Core - System Status Check        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"
echo ""

# ===== WINDOWS-SIDE CHECKS =====
echo -e "${YELLOW}[Windows-Side]${NC}"
echo ""

# 1. WSL Available
echo -n "  WSL installed: "
if command -v wsl &> /dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    echo -e "    ${GRAY}WSL not installed or not in PATH${NC}"
fi

# 2. Flask Process
echo -n "  Flask running: "
if pgrep -f "python.*app.py" > /dev/null 2>&1; then
    FLASK_PID=$(pgrep -f "python.*app.py")
    echo -e "${GREEN}✓${NC} (PID: $FLASK_PID)"
else
    echo -e "${RED}✗${NC}"
fi

# 3. Flask Port
echo -n "  Flask port 5000: "
if netstat -tuln 2>/dev/null | grep -q ":5000"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

# 4. WebSocket Port (Test from Windows)
echo -n "  WebSocket 127.0.0.1:8999: "
if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/8999" 2>/dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC} (Consumer may not be listening)"
fi

echo ""

# ===== WSL-SIDE CHECKS =====
echo -e "${YELLOW}[WSL-Side]${NC}"
echo ""

# Check if WSL is running
if ! wsl true 2>/dev/null; then
    echo -e "${RED}✗ WSL is not responding${NC}"
    exit 1
fi

# 1. Suricata
echo -n "  Suricata running: "
if wsl -u root systemctl is-active suricata &>/dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

# 2. Suricata EVE JSON
echo -n "  EVE JSON file: "
if wsl test -f /var/log/suricata/eve.json; then
    SIZE=$(wsl ls -lh /var/log/suricata/eve.json | awk '{print $5}')
    UPDATED=$(wsl stat -c %y /var/log/suricata/eve.json | cut -d' ' -f1-2)
    echo -e "${GREEN}✓${NC} (${SIZE}, updated: ${UPDATED})"
else
    echo -e "${RED}✗${NC}"
fi

# 3. Consumer Process
echo -n "  Consumer running: "
CONSUMER_PID=$(wsl pgrep -f "consumer.py" 2>/dev/null)
if [ -n "$CONSUMER_PID" ]; then
    echo -e "${GREEN}✓${NC} (PID: $CONSUMER_PID)"
else
    echo -e "${RED}✗${NC}"
fi

# 4. WebSocket Port in WSL
echo -n "  WebSocket listening: "
if wsl netstat -tlnp 2>/dev/null | grep -q ":8999"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

# 5. Redis (if Redis mode)
echo -n "  Redis running: "
if wsl redis-cli ping &>/dev/null 2>&1; then
    QUEUE_SIZE=$(wsl redis-cli LLEN sentinel_alerts_queue 2>/dev/null || echo "0")
    echo -e "${GREEN}✓${NC} (queue: $QUEUE_SIZE events)"
else
    echo -e "${RED}✗${NC} (Legacy mode may be active)"
fi

# 6. Python Dependencies
echo -n "  Python deps: "
MISSING=0
for pkg in websockets pandas scikit-learn redis; do
    if ! wsl python3 -c "import $pkg" 2>/dev/null; then
        MISSING=$((MISSING+1))
    fi
done
if [ $MISSING -eq 0 ]; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC} (Missing: $MISSING packages)"
fi

echo ""

# ===== PIPELINE STATUS =====
echo -e "${YELLOW}[Pipeline Status]${NC}"
echo ""

# Check Redis mode
USE_REDIS=$(wsl echo $USE_REDIS_QUEUE 2>/dev/null || echo "unknown")
echo "  Pipeline mode: $([ "$USE_REDIS" == "1" ] && echo -e "${GREEN}Redis Queue${NC}" || echo -e "${YELLOW}Legacy Polling${NC}")"

# Check database
echo -n "  Database: "
if wsl test -f data/alerts.db; then
    ALERT_COUNT=$(wsl sqlite3 data/alerts.db "SELECT COUNT(*) FROM alerts;" 2>/dev/null || echo "?")
    echo -e "${GREEN}✓${NC} ($ALERT_COUNT alerts)"
else
    echo -e "${RED}✗${NC}"
fi

echo ""

# ===== CONNECTION CHAIN =====
echo -e "${YELLOW}[Connection Chain]${NC}"
echo ""

# 1. Suricata → EVE JSON
echo -n "  Suricata → EVE JSON: "
if wsl test -f /var/log/suricata/eve.json -a -s /var/log/suricata/eve.json; then
    LINES=$(wsl wc -l < /var/log/suricata/eve.json)
    echo -e "${GREEN}✓${NC} ($LINES lines)"
else
    echo -e "${RED}✗${NC}"
fi

# 2. Consumer → WebSocket
echo -n "  Consumer → WebSocket: "
if [ -n "$CONSUMER_PID" ] && wsl netstat -tlnp 2>/dev/null | grep -q ":8999"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

# 3. Flask → Consumer WebSocket
echo -n "  Flask → Consumer WS: "
if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/8999" 2>/dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

# 4. Browser → Flask
echo -n "  Browser → Flask: "
if netstat -tuln 2>/dev/null | grep -q ":5000"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

echo ""

# ===== RECENT LOGS =====
echo -e "${YELLOW}[Recent Logs]${NC}"
echo ""

echo -e "${GRAY}Flask relay (last 3 errors):${NC}"
wsl grep -i "error\|exception\|failed" data/logs/consumer.log 2>/dev/null | tail -3 | sed 's/^/  /'

echo ""

# ===== SUMMARY =====
echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"

# Count issues
ISSUES=0
[ ! -n "$CONSUMER_PID" ] && ISSUES=$((ISSUES+1))
! wsl netstat -tlnp 2>/dev/null | grep -q ":8999" && ISSUES=$((ISSUES+1))
! timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/8999" 2>/dev/null && ISSUES=$((ISSUES+1))
! wsl -u root systemctl is-active suricata &>/dev/null && ISSUES=$((ISSUES+1))

if [ $ISSUES -eq 0 ]; then
    echo -e "${GREEN}✓ All systems healthy!${NC}"
    echo ""
    echo "  System is running normally. Dashboard should be receiving alerts."
    echo "  Access UI at: http://localhost:3000"
else
    echo -e "${RED}✗ System has $ISSUES issue(s)${NC}"
    echo ""
    echo "  Quick fixes:"
    echo "    1. Check consumer: wsl bash diagnose_websocket.sh"
    echo "    2. Restart consumer: wsl bash start_ids.sh"
    echo "    3. Restart WSL: wsl --shutdown"
    echo "    4. Full diagnostics: powershell -NoProfile .\diagnose_connection.ps1"
fi

echo ""
