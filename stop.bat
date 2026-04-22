@echo off
title Sentinel Core - Clean Shutdown
echo =================================================================
echo             SENTINEL CORE: GRACEFUL SHUTDOWN
echo =================================================================
echo.

echo [+] Stopping Dashboard Backend...
taskkill /F /FI "WINDOWTITLE eq Backend (Relay)*" /T 2>nul

echo [+] Stopping React Frontend...
taskkill /F /FI "WINDOWTITLE eq Frontend (SOC)*" /T 2>nul

echo [+] Stopping Core IDS Sensor (WSL)...
wsl -u root pkill -9 -f "consumer.py" 2>nul
wsl -u root pkill -9 -f "suricata" 2>nul
wsl -u root systemctl stop suricata 2>nul || echo.
taskkill /F /FI "WINDOWTITLE eq IDS Core (WSL)*" /T 2>nul

echo [+] Stopping Redis Server (WSL)...
wsl -u root bash -c "redis-cli shutdown 2>/dev/null" || echo.
wsl -u root pkill -9 redis-server 2>/dev/null || echo.

echo.
echo =================================================================
echo [SUCCESS] Sentinel Core stopped.
echo =================================================================
echo.
echo Tips:
echo   - To start again:        start.bat
echo   - Force re-setup:         start.bat --force-setup
echo   - Use legacy mode:        start.bat --legacy
echo   - Check logs:             wsl tail -f data/logs/consumer.log
echo.
echo Thank you for using Sentinel Core.
echo =================================================================
echo.
if /I "%~1"=="--no-pause" goto :eof
pause
