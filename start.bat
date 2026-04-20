@echo off
setlocal EnableExtensions
title Anti-Gravity IDS Launcher

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "PYTHON_EXE=%ROOT%\.venv\Scripts\python.exe"
set "UI_DIR=%ROOT%\ui"
set "BACKEND_APP=%ROOT%\src\dashboard\app.py"
set "START_IDS_SH=%ROOT%\start_ids.sh"

echo =================================================================
echo             ANTI-GRAVITY HYBRID IDS LAUNCHER
echo =================================================================
echo [+] Project root: %ROOT%
echo [+] Cleaning up existing instances...
call "%ROOT%\stop.bat"
echo.

:: 1. Launch WSL Engine (Suricata + ML Consumer + WebSocket)
echo [+] Launching WSL Pipeline (Suricata + ML Engine + WebSocket)...
where wsl >nul 2>&1
if errorlevel 1 (
    echo [ERROR] WSL is not installed. Failed to launch core IDS sensor.
    pause
    exit /b 1
)

:: Convert Windows path to WSL path and run
for /f "delims=" %%I in ('wsl wslpath "%START_IDS_SH%"') do set "WSL_SCRIPT=%%I"
start "IDS Core (WSL)" wsl -u root bash -lc "sed -i 's/\r$//' '%WSL_SCRIPT%' && bash '%WSL_SCRIPT%'"

:: 2. Launch Flask Backend (Windows)
echo [+] Launching Flask Dashboard Backend...
if not exist "%PYTHON_EXE%" (
    echo [ERROR] Python virtual environment not found at %PYTHON_EXE%
    pause
    exit /b 1
)
start "Backend (Flask)" /D "%ROOT%" cmd /k "echo [DASHBOARD] Starting Relay... && .venv\Scripts\python.exe %BACKEND_APP%"

:: 3. Launch React Frontend
echo [+] Launching React Frontend (Vite)...
if exist "%UI_DIR%\node_modules" (
    start "Frontend (Vite)" /D "%UI_DIR%" cmd /k "npm run dev"
) else (
    echo [INFO] node_modules not found. Installing UI dependencies...
    start "Frontend (Vite)" /D "%UI_DIR%" cmd /k "npm install && npm run dev"
)

echo.
echo =================================================================
echo [SUCCESS] IDS components are launching in separate windows.
echo.
echo - Dashboard UI: http://localhost:5173
echo - Backend API:  http://localhost:5000
echo - Core Sensor:   Running in WSL
echo =================================================================
echo.
pause
