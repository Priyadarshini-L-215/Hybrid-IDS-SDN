@echo off
setlocal EnableExtensions EnableDelayedExpansion
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
set "USE_REDIS_QUEUE=1"

if /I "%~1"=="--force-setup" set "FORCE_SETUP=1"
if /I "%~1"=="--legacy" set "USE_REDIS_QUEUE=0"
if /I "%~2"=="--legacy" set "USE_REDIS_QUEUE=0"

echo =================================================================
echo             SENTINEL CORE: HYBRID ML-POWERED IPS
echo =================================================================
if "%USE_REDIS_QUEUE%"=="1" (
    echo             Pipeline: Redis Queue ^(Optimized^)
) else (
    echo             Pipeline: Legacy Polling ^(Compatibility Mode^)
)
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

:: Check for Python venv (Redis client required)
if not exist "%PYTHON_EXE%" (
    echo [ERROR] Python virtual environment not found.
    echo Please run: python -m venv .venv
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

:: Check for UI Dependencies
if not exist "%UI_DIR%\node_modules" (
    echo [!] UI dependencies not found.
    echo [+] Running npm install...
    cd /d "%UI_DIR%"
    call npm install
    if errorlevel 1 (
        echo [ERROR] npm install failed. Fix UI dependencies and re-run start.bat.
        cd /d "%ROOT%"
        pause
        exit /b 1
    )
    cd /d "%ROOT%"
)

:: Check for WSL Dependencies (Suricata + Redis)
echo [+] Checking WSL sensor environment...
wsl -u root bash -c "command -v suricata >/dev/null 2>&1"
if errorlevel 1 (
    echo [!] Suricata not found in WSL. 
    echo [+] Running setup_wsl.sh...
    for /f "delims=" %%I in ('wsl wslpath "%WSL_SETUP_SH%"') do set "WSL_SETUP_SCRIPT=%%I"
    wsl -u root bash -lc "chmod +x '%WSL_SETUP_SCRIPT%' && '%WSL_SETUP_SCRIPT%'"
    if errorlevel 1 (
        echo [ERROR] WSL setup failed. Check setup_wsl.sh output and retry.
        pause
        exit /b 1
    )
)

if "%USE_REDIS_QUEUE%"=="1" (
    echo [+] Checking Redis availability...
    wsl -u root bash -c "redis-cli ping >/dev/null 2>&1"
    if errorlevel 1 (
        echo [!] Redis not running. Installing and starting Redis...
        for /f "delims=" %%I in ('wsl wslpath "%WSL_SETUP_SH%"') do set "WSL_SETUP_SCRIPT=%%I"
        wsl -u root bash -lc "apt-get update -qq && apt-get install -y redis-server redis-tools 2>&1 | tail -3"
        if errorlevel 1 (
            echo [WARNING] Redis install failed. Falling back to legacy mode.
            set "USE_REDIS_QUEUE=0"
        ) else (
            wsl -u root bash -c "redis-server --daemonize yes --logfile /var/log/redis/redis-server.log"
            wsl -u root bash -c "sleep 1 && redis-cli ping"
            if errorlevel 1 (
                echo [ERROR] Failed to start Redis. Falling back to legacy mode.
                set "USE_REDIS_QUEUE=0"
            ) else (
                echo [+] Redis started successfully.
            )
        )
    ) else (
        echo [+] Redis is running.
    )
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
call "%ROOT%\stop.bat" --no-pause
echo.

:: 2. Launch WSL Engine
echo [+] Launching WSL Pipeline (Suricata + ML Engine)...
if "%USE_REDIS_QUEUE%"=="1" (
    echo [+] Mode: Redis Queue Pipeline ^(Optimized^)
) else (
    echo [+] Mode: Legacy Polling ^(Compatibility^)
)
for /f "delims=" %%I in ('wsl wslpath "%START_IDS_SH%"') do set "WSL_SCRIPT=%%I"
for /f "delims=" %%I in ('wsl wslpath "%ROOT%"') do set "WSL_ROOT=%%I"
start "IDS Core (WSL)" wsl -u root bash -lc "export PROJECT_ROOT='%WSL_ROOT%' USE_REDIS_QUEUE=%USE_REDIS_QUEUE%; sed -i 's/\r$//' '%WSL_SCRIPT%' && bash '%WSL_SCRIPT%'"

:: 3. Launch Flask Backend
echo [+] Waiting for WSL consumer to be ready...
set "WSL_READY=0"
for /f "tokens=1" %%I in ('wsl hostname -I 2^>nul') do set "WSL_IP=%%I"
if not defined WSL_IP set "WSL_IP=127.0.0.1"

for /L %%i in (1,1,30) do (
    if "!WSL_READY!"=="0" (
        :: Try proper WebSocket handshake instead of raw TCP to avoid server errors
        "%PYTHON_EXE%" "%ROOT%\scratch\check_ws_ready.py" ws://!WSL_IP!:8999 >nul 2>&1
        if not errorlevel 1 (
            set "WSL_READY=1"
            echo [+] WSL Consumer is ONLINE on !WSL_IP!:8999
        ) else (
            :: Fallback attempt on localhost in case WSL IP is unroutable
            "%PYTHON_EXE%" "%ROOT%\scratch\check_ws_ready.py" ws://127.0.0.1:8999 >nul 2>&1
            if not errorlevel 1 (
                set "WSL_READY=1"
                echo [+] WSL Consumer is ONLINE on 127.0.0.1:8999
            ) else (
                <nul set /p=.
                ping -n 2 127.0.0.1 >nul
            )
        )
    )
)
echo.

if "!WSL_READY!"=="0" (
    echo [WARNING] WSL Consumer took too long to start. Launching backend anyway...
)

echo [+] Launching Flask Dashboard Backend...
start "Backend (Relay)" /D "%ROOT%" cmd /k "echo [BACKEND] Initializing AI Relay... && .venv\Scripts\python.exe src\dashboard\app.py"

:: 4. Deploy Redis Validation
if "%USE_REDIS_QUEUE%"=="1" (
    echo [+] Validating Redis pipeline...
    "%PYTHON_EXE%" "%ROOT%\validate_redis_pipeline.py" >nul 2>&1
    if errorlevel 1 (
        echo [!] Redis pipeline validation failed. Check logs.
    ) else (
        echo [+] Redis pipeline validation passed.
    )
)
echo.

:: 5. Launch React Frontend
echo [+] Launching Sentinel Core Dashboard (React)...
start "Frontend (SOC)" /D "%UI_DIR%" cmd /k "echo [UI] Starting Dashboard... && npm run dev"

echo.
echo =================================================================
echo [SUCCESS] Sentinel Core is now ACTIVE.
echo =================================================================
echo.
if "%USE_REDIS_QUEUE%"=="1" (
    echo [PIPELINE] Redis Queue ^(Optimized^)
    echo - Expected latency: 10-50ms per event ^(5-10x faster^)
    echo - Expected throughput: 500-1000+ events/sec
    echo - Redis: redis://127.0.0.1:6379
) else (
    echo [PIPELINE] Legacy Polling ^(Compatibility Mode^)
    echo - Expected latency: 50-185ms per event
    echo - Expected throughput: 40-100 events/sec
)
echo.
echo [SERVICES]
echo - Dashboard:      http://localhost:3000
echo - WebSocket API:  ws://127.0.0.1:8999
echo - Flask Relay:    http://localhost:5000
echo - Core Logs:      tail -f data/logs/consumer.log
echo.
if "%USE_REDIS_QUEUE%"=="1" (
    echo [REDIS]
    echo - Monitor queue: wsl redis-cli LLEN sentinel_alerts_queue
    echo - View info:     wsl redis-cli INFO
)
echo.
echo Leave these windows open. Use stop.bat to terminate the system.
echo =================================================================
echo.
pause
