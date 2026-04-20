@echo off
setlocal
title Hybrid IDS Launcher

echo =================================================================
echo             HYBRID IDS MANAGEMENT SYSTEM
echo =================================================================

:: 1. Launch WSL Suricata Sensor
echo [+] Launching Suricata Sensor in WSL...
:: Cleanup old instances and start new one with auto-sudo
:: Ensure the script has Linux line endings and run it
start "Suricata Sensor" wsl bash -c "sed -i 's/\r$//' /mnt/d/projects/FYP/start_suricata.sh; bash /mnt/d/projects/FYP/start_suricata.sh"

:: 2. Launch Flask Backend
echo [+] Launching Flask Dashboard Backend...
start "Backend" cmd /k ".venv\Scripts\python.exe src\dashboard\app.py"

:: 3. Launch Vite Frontend
echo [+] Launching React Frontend...
cd ui
start "Frontend" cmd /k npm run dev
cd ..

echo.
echo =================================================================
echo [SUCCESS] All components are initializing.
echo.
echo - Dashboard (UI): http://localhost:5173
echo - API Backend:    http://localhost:5000
echo.
echo INSTRUCTIONS:
echo 1. Keep all terminal windows open.
echo 2. Check the "Suricata Sensor" window for logs.
echo 3. Use the WSL IP (172.25.24.205) for testing.
echo =================================================================
echo.
pause
