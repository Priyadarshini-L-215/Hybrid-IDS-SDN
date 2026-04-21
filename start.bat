@echo off
setlocal EnableExtensions
title Sentinel Core - Unified Launcher

:: --- CONFIGURATION ---
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "PYTHON_EXE=%ROOT%\.venv\Scripts\python.exe"
set "UI_DIR=%ROOT%\ui"
set "BACKEND_APP=%ROOT%\src\dashboard\app.py"
set "START_IDS_SH=%ROOT%\start_ids.sh"
set "WSL_SETUP_SH=%ROOT%\setup_wsl.sh"
set "SETUP_STAMP=%ROOT%\.sentinel_setup_complete"
set "FORCE_SETUP=0"

if /I "%~1"=="--force-setup" set "FORCE_SETUP=1"

echo =================================================================
echo             SENTINEL CORE: HYBRID ML-POWERED IPS
echo =================================================================
echo.

:: 0. Integrity Check / First-Time Setup
echo [+] Preparing startup...

:: Check for WSL (always quick-check this)
where wsl >nul 2>&1
if errorlevel 1 (
    echo [ERROR] WSL2 is required but not found. 
    echo Please install WSL and Ubuntu 22.04 before continuing.
    pause
    exit /b 1
)

if "%FORCE_SETUP%"=="1" (
    echo [!] Forced setup verification requested.
)

if exist "%SETUP_STAMP%" if not "%FORCE_SETUP%"=="1" (
    if exist "%PYTHON_EXE%" if exist "%UI_DIR%\node_modules" (
        echo [OK] Setup stamp found. Skipping slow dependency checks.
        goto :post_setup
    )
    echo [!] Setup stamp exists but required dependencies are missing.
    echo [+] Falling back to full setup verification.
)

echo [+] Running first-time/full setup verification...

:: Check for Python Venv
if not exist "%PYTHON_EXE%" (
    echo [!] Windows environment not detected.
    echo [+] Running setup.bat...
    call "%ROOT%\setup.bat" --no-pause
)

:: Check for UI Dependencies
if not exist "%UI_DIR%\node_modules" (
    echo [!] UI dependencies not found.
    echo [+] Running npm install...
    cd /d "%UI_DIR%" && call npm install && cd /d "%ROOT%"
)

:: Check for WSL Dependencies (Suricata)
echo [+] Checking WSL sensor environment...
wsl -u root bash -c "command -v suricata >/dev/null 2>&1"
if errorlevel 1 (
    echo [!] Suricata not found in WSL. 
    echo [+] Running setup_wsl.sh...
    for /f "delims=" %%I in ('wsl wslpath "%WSL_SETUP_SH%"') do set "WSL_SETUP_SCRIPT=%%I"
    wsl -u root bash -lc "chmod +x '%WSL_SETUP_SCRIPT%' && '%WSL_SETUP_SCRIPT%'"
)

if not exist "%SETUP_STAMP%" (
    >"%SETUP_STAMP%" echo setup_completed=true
    >>"%SETUP_STAMP%" echo completed_at=%date% %time%
    >>"%SETUP_STAMP%" echo note=Delete this file or run start.bat --force-setup to re-run full checks.
)

:post_setup
echo.
echo [+] All systems verified. Initializing launcher...
echo.

:: 1. Cleanup old instances
echo [+] Purging stale processes...
call "%ROOT%\stop.bat"
echo.

:: 2. Launch WSL Engine
echo [+] Launching WSL Pipeline (Suricata + ML Engine)...
for /f "delims=" %%I in ('wsl wslpath "%START_IDS_SH%"') do set "WSL_SCRIPT=%%I"
for /f "delims=" %%I in ('wsl wslpath "%ROOT%"') do set "WSL_ROOT=%%I"
start "IDS Core (WSL)" wsl -u root bash -lc "export PROJECT_ROOT='%WSL_ROOT%'; sed -i 's/\r$//' '%WSL_SCRIPT%' && bash '%WSL_SCRIPT%'"

:: 3. Launch Flask Backend
echo [+] Launching Flask Dashboard Backend...
start "Backend (Relay)" /D "%ROOT%" cmd /k "echo [BACKEND] Initializing AI Relay... && .venv\Scripts\python.exe %BACKEND_APP%"

:: 4. Launch React Frontend
echo [+] Launching Sentinel Core Dashboard (React)...
start "Frontend (SOC)" /D "%UI_DIR%" cmd /k "echo [UI] Starting Dashboard... && npm run dev"

echo.
echo =================================================================
echo [SUCCESS] Sentinel Core is now ACTIVE.
echo =================================================================
echo.
echo - Dashboard:  http://localhost:5173
echo - API Relay:  http://localhost:5000
echo - Core Logs:  tail -f data/logs/consumer.log
echo.
echo Leave these windows open. Use stop.bat to terminate the system.
echo =================================================================
echo.
pause
