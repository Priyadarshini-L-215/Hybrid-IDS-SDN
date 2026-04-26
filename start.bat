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
set "MODELS_DIR=%ROOT%\models"
set "NEW_MODELS_DIR=%ROOT%\new"
set "RF_MODEL=%MODELS_DIR%\rf_model.pkl"
set "SCALER_MODEL=%MODELS_DIR%\scaler.pkl"
set "AE_MODEL=%MODELS_DIR%\autoencoder.pth"
set "RF_MODEL_FALLBACK=%NEW_MODELS_DIR%\sentinel_rf.pkl"
set "SCALER_MODEL_FALLBACK=%NEW_MODELS_DIR%\sentinel_scaler.pkl"
set "AE_MODEL_FALLBACK=%NEW_MODELS_DIR%\sentinel_autoencoder.pth"
set "FORCE_SETUP=0"
set "USE_REDIS_QUEUE=1"
set "WS_PORT=8765"
set "AUTOENCODER_THRESHOLD=0"
set "AUTOENCODER_THRESHOLD_PERCENTILE=95"
set "NO_PAUSE=0"

:parse_args
if "%~1"=="" goto :args_done
if /I "%~1"=="--force-setup" set "FORCE_SETUP=1"
if /I "%~1"=="--legacy" set "USE_REDIS_QUEUE=0"
if /I "%~1"=="--no-pause" set "NO_PAUSE=1"
shift
goto :parse_args
:args_done

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
echo [+] Preparing environment verification...

:: Check for Node.js (Required for Dashboard)
where node >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js not found. It is required for the React Dashboard.
    echo Please install Node.js (v20+) from https://nodejs.org/
    pause
    exit /b 1
)

:: Check for Python (Required for Backend)
where python >nul 2>&1
if errorlevel 1 (
    where py >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Python not found. Please install Python 3.12+ 
        pause
        exit /b 1
    )
)

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
    echo [!] Python virtual environment not found.
    echo [+] Running setup.bat to bootstrap Windows environment...
    call "%ROOT%\setup.bat" --no-pause
    if not exist "%PYTHON_EXE%" (
        echo [ERROR] Python virtual environment setup failed.
        pause
        exit /b 1
    )
)

if "%FORCE_SETUP%"=="1" (
    echo [!] Forced setup verification requested.
)

if exist "%SETUP_STAMP%" if not "%FORCE_SETUP%"=="1" (
    if exist "%PYTHON_EXE%" if exist "%UI_DIR%\node_modules" (
        echo [OK] Core dependencies verified.
        goto :model_sync
    )
    echo [!] Setup stamp exists but required dependencies are missing.
    echo [+] Falling back to full setup verification.
)

echo [+] Running full dependency audit...

:: Check for UI Dependencies
if not exist "%UI_DIR%\node_modules" (
    echo [!] UI dependencies not found in %UI_DIR%
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
        echo [!] Redis not running. Attempting auto-start...
        wsl -u root service redis-server start >nul 2>&1
        wsl -u root bash -c "redis-cli ping >/dev/null 2>&1"
        if errorlevel 1 (
            echo [WARNING] Redis could not be started. Falling back to legacy mode.
            set "USE_REDIS_QUEUE=0"
        ) else (
            echo [+] Redis started successfully.
        )
    ) else (
        echo [+] Redis is running.
    )
)

:model_sync
echo [+] Syncing ML artifacts for Tri-Layer pipeline...
if not exist "%MODELS_DIR%" mkdir "%MODELS_DIR%"

:: Always copy from 'new' if they exist, to pick up "recently updated" models
if exist "%RF_MODEL_FALLBACK%" (
    copy /Y "%RF_MODEL_FALLBACK%" "%RF_MODEL%" >nul
    echo [+] Using updated RF model from new\
)
if exist "%SCALER_MODEL_FALLBACK%" (
    copy /Y "%SCALER_MODEL_FALLBACK%" "%SCALER_MODEL%" >nul
    echo [+] Using updated scaler from new\
)
if exist "%AE_MODEL_FALLBACK%" (
    copy /Y "%AE_MODEL_FALLBACK%" "%AE_MODEL%" >nul
    echo [+] Using updated autoencoder from new\
)

if not exist "%RF_MODEL%" (
    echo [ERROR] Missing RF model: models\rf_model.pkl
    echo         Place rf_model.pkl in models\ or sentinel_rf.pkl in new\
    pause
    exit /b 1
)
if not exist "%SCALER_MODEL%" (
    echo [ERROR] Missing scaler: models\scaler.pkl
    echo         Place scaler.pkl in models\ or sentinel_scaler.pkl in new\
    pause
    exit /b 1
)
if not exist "%AE_MODEL%" (
    echo [ERROR] Missing autoencoder: models\autoencoder.pth
    echo         Place autoencoder.pth in models\ or sentinel_autoencoder.pth in new\
    pause
    exit /b 1
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
start "IDS Core (WSL)" wsl -u root bash -lc "export PROJECT_ROOT='%WSL_ROOT%' USE_REDIS_QUEUE=%USE_REDIS_QUEUE% AUTOENCODER_THRESHOLD=%AUTOENCODER_THRESHOLD% AUTOENCODER_THRESHOLD_PERCENTILE=%AUTOENCODER_THRESHOLD_PERCENTILE%; sed -i 's/\r$//' '%WSL_SCRIPT%' && bash '%WSL_SCRIPT%'"

:: 3. Launch Flask Backend
echo [+] Resolving WSL connectivity...
set "WSL_IP="
for /f "tokens=1" %%I in ('wsl hostname -I 2^>nul') do (
    if not defined WSL_IP set "WSL_IP=%%I"
)
if not defined WSL_IP set "WSL_IP=127.0.0.1"
echo [+] WSL IP resolved to: %WSL_IP%

:: 3b. Verify Model Alignment (77 Features)
echo [+] Verifying model feature alignment...
"%PYTHON_EXE%" -c "import joblib, json; s=joblib.load('models/scaler.pkl'); f=list(s.feature_names_in_); print(len(f))" > .tmp_feat_count 2>nul
set /p FEAT_COUNT=<.tmp_feat_count
del .tmp_feat_count
if "%FEAT_COUNT%"=="77" (
    echo [OK] Model feature count verified (77).
) else (
    echo [WARNING] Model uses %FEAT_COUNT% features. Ensure feature_extractor.py is synced.
)

echo [+] Waiting for WSL consumer to be ready...
set "WSL_READY=0"
set "WS_READY_MAX_ATTEMPTS=20"
for /L %%i in (1,1,!WS_READY_MAX_ATTEMPTS!) do (
    if "!WSL_READY!"=="0" (
        "%PYTHON_EXE%" "%ROOT%\scratch\check_ws_ready.py" ws://!WSL_IP!:!WS_PORT! 1 >nul 2>&1
        if not errorlevel 1 (
            set "WSL_READY=1"
            echo [+] WSL Consumer is ONLINE on !WSL_IP!:!WS_PORT!
        ) else (
            <nul set /p=.
            ping -n 2 127.0.0.1 >nul
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
    "%PYTHON_EXE%" "%ROOT%\tests\validate_redis_pipeline.py" >nul 2>&1
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
    echo - Expected latency: 10-50ms per event
    echo - Expected throughput: 500-1000+ events/sec
    echo - Redis: redis://127.0.0.1:6379
) else (
    echo [PIPELINE] Legacy Polling ^(Compatibility Mode^)
)
echo [ML]
echo - RF model:       models\rf_model.pkl ^(77 features^)
echo - Autoencoder:    models\autoencoder.pth
echo - AE threshold:   %AUTOENCODER_THRESHOLD% ^(percentile fallback %AUTOENCODER_THRESHOLD_PERCENTILE% pct^)
echo.
echo [SERVICES]
echo - Dashboard:      http://localhost:3000
echo - WebSocket API:  ws://%WSL_IP%:%WS_PORT%
echo - Flask Relay:    http://localhost:5000
echo - Core Logs:      tail -f data/logs/consumer.log
echo.
if "%USE_REDIS_QUEUE%"=="1" (
    echo [REDIS]
    echo - Monitor queue: wsl redis-cli LLEN sentinel_alerts_queue
)
echo.
echo [DIAGNOSTICS]
echo - Run Test:       .venv\Scripts\python.exe scratch\ml_test.py
echo =================================================================
echo.
if "%NO_PAUSE%"=="1" goto :eof
pause
