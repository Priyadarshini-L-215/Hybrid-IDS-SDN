@echo off
title Anti-Gravity IDS Shutdown
echo =================================================================
echo             ANTI-GRAVITY IDS CLEAN SHUTDOWN
echo =================================================================
echo.

echo [+] Stopping Dashboard Backend...
taskkill /F /FI "WINDOWTITLE eq Backend (Flask)*" /T 2>nul

echo [+] Stopping React Frontend...
taskkill /F /FI "WINDOWTITLE eq Frontend (Vite)*" /T 2>nul

echo [+] Stopping Core IDS Sensor (WSL)...
wsl -u root pkill -9 -f "consumer.py" 2>nul
wsl -u root pkill -9 -f "suricata" 2>nul
wsl -u root systemctl stop suricata 2>nul
taskkill /F /FI "WINDOWTITLE eq IDS Core (WSL)*" /T 2>nul

echo.
echo [SUCCESS] Specialized project processes terminated.
echo.
pause
