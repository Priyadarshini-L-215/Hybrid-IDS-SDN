@echo off
title Sentinel Core - Windows Setup
echo =================================================================
echo             SENTINEL CORE - WINDOWS ENVIRONMENT SETUP
echo =================================================================

setlocal EnableExtensions EnableDelayedExpansion
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "PY_CMD="
where py >nul 2>&1
if not errorlevel 1 (
    set "PY_CMD=py -3"
) else (
    where python >nul 2>&1
    if not errorlevel 1 set "PY_CMD=python"
)

:: 1. Check Python
if not defined PY_CMD (
    echo [ERROR] Python is not installed or not in PATH.
    pause
    exit /b 1
)

:: 2. Create Virtual Environment
if not exist "!ROOT!\.venv" (
    echo [+] Creating Python virtual environment...
    %PY_CMD% -m venv "!ROOT!\.venv"
) else (
    echo [OK] Virtual environment already exists.
)

:: 3. Install Dependencies
echo [+] Installing backend dependencies...
"!ROOT!\.venv\Scripts\python.exe" -m pip --version >nul 2>&1
if errorlevel 1 (
    echo [!] pip is missing in virtual environment. Attempting to restore...
    "!ROOT!\.venv\Scripts\python.exe" -m ensurepip --default-pip
    if errorlevel 1 (
        echo [ERROR] Could not restore pip. Please ensure your base Python installation has pip.
        pause
        exit /b 1
    )
)
"!ROOT!\.venv\Scripts\python.exe" -m pip install --upgrade pip
"!ROOT!\.venv\Scripts\python.exe" -m pip install -r "!ROOT!\requirements_win.txt"
if errorlevel 1 (
    echo [ERROR] Python dependency installation failed.
    pause
    exit /b 1
)

:: 4. Setup UI
echo [+] Installing UI dependencies (Node.js required)...
where npm >nul 2>&1
if errorlevel 1 (
    echo [WARNING] npm not found. Please install Node.js to use the dashboard.
) else (
    pushd "!ROOT!\ui"
    if exist package-lock.json (
        call npm ci
    ) else (
        call npm install
    )
    if errorlevel 1 (
        echo [ERROR] UI dependency installation failed.
        popd
        pause
        exit /b 1
    )
    popd
)

echo =================================================================
echo [SUCCESS] Windows environment setup complete.
echo =================================================================
if "%1"=="--no-pause" goto :eof
pause
