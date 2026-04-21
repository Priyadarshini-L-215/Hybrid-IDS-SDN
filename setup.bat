@echo off
title Sentinel Core - Windows Setup
echo =================================================================
echo             SENTINEL CORE - WINDOWS ENVIRONMENT SETUP
echo =================================================================

:: 1. Check Python
where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    pause
    exit /b 1
)

:: 2. Create Virtual Environment
if not exist ".venv" (
    echo [+] Creating Python virtual environment...
    python -m venv .venv
) else (
    echo [OK] Virtual environment already exists.
)

:: 3. Install Dependencies
echo [+] Installing backend dependencies...
call .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt

:: 4. Setup UI
echo [+] Installing UI dependencies (Node.js required)...
where npm >nul 2>&1
if errorlevel 1 (
    echo [WARNING] npm not found. Please install Node.js to use the dashboard.
) else (
    cd ui
    npm install
    cd ..
)

echo =================================================================
echo [SUCCESS] Windows environment setup complete.
echo =================================================================
if "%1"=="--no-pause" goto :eof
pause
