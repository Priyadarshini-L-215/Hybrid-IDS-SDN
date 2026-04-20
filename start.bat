@echo off
setlocal EnableExtensions
title Hybrid IDS Launcher

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "PYTHON_EXE=%ROOT%\.venv\Scripts\python.exe"
set "UI_DIR=%ROOT%\ui"
set "BACKEND_APP=%ROOT%\src\dashboard\app.py"
set "SURICATA_SH_WIN=%ROOT%\start_suricata.sh"
set "SURICATA_SH_WSL="

echo =================================================================
echo             HYBRID IDS MANAGEMENT SYSTEM
echo =================================================================
echo [+] Project root: %ROOT%
echo.

if not exist "%PYTHON_EXE%" (
	echo [ERROR] Python virtual environment not found:
	echo         %PYTHON_EXE%
	echo [HINT] Run these commands and retry:
	echo        python -m venv .venv
	echo        .venv\Scripts\pip install -r models\requirements.txt
	goto :finish
)

where npm >nul 2>&1
if errorlevel 1 (
	echo [ERROR] npm is not available in PATH. Install Node.js 18+ and retry.
	goto :finish
)

if not exist "%UI_DIR%\package.json" (
	echo [ERROR] Frontend project not found:
	echo         %UI_DIR%
	goto :finish
)

if not exist "%BACKEND_APP%" (
	echo [ERROR] Backend entrypoint not found:
	echo         %BACKEND_APP%
	goto :finish
)

:: 1. Launch WSL Suricata Sensor
echo [+] Launching Suricata Sensor in WSL...
where wsl >nul 2>&1
if errorlevel 1 (
	echo [WARN] WSL is not installed. Skipping Suricata launch.
) else (
	for /f "delims=" %%I in ('wsl wslpath "%SURICATA_SH_WIN%" 2^>nul') do set "SURICATA_SH_WSL=%%I"
)

if defined SURICATA_SH_WSL (
	start "Suricata Sensor" wsl bash -lc "sed -i 's/\r$//' '%SURICATA_SH_WSL%' && bash '%SURICATA_SH_WSL%'"
) else (
	if not errorlevel 1 (
		echo [WARN] Could not resolve WSL path for start_suricata.sh. Skipping Suricata launch.
	)
)

:: 2. Launch Flask Backend
echo [+] Launching Flask Dashboard Backend...
start "Backend" /D "%ROOT%" cmd /k "echo [INFO] Starting Flask backend... && .venv\Scripts\python.exe src\dashboard\app.py"

:: 3. Launch Vite Frontend
echo [+] Launching React Frontend...
start "Frontend" /D "%UI_DIR%" cmd /k "npm run dev"

echo.
echo =================================================================
echo [SUCCESS] Launch commands issued.
echo.
echo - Dashboard (UI): http://localhost:5173
echo - API Backend:    http://localhost:5000
echo.
echo INSTRUCTIONS:
echo 1. Keep all opened terminal windows running.
echo 2. Check the "Suricata Sensor" window for IDS logs.
echo 3. If WSL launch failed, start Suricata manually.
echo =================================================================
echo.

:finish
pause
endlocal
