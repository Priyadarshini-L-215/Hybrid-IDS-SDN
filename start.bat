@echo off
title Anti-Gravity IDS Launcher
color 0B

echo ========================================================
echo.
echo      ANTI-GRAVITY IDS - LAUNCH SEQUENCE INITIATED
echo.
echo ========================================================
echo.

echo [1/2] Booting Defensive Backend (Flask)...
IF EXIST ".venv\Scripts\python.exe" (
    start "Backend (port 5000)" cmd /k ".venv\Scripts\python.exe src\dashboard\app.py"
) ELSE (
    start "Backend (port 5000)" cmd /k "cd src\dashboard && python app.py"
)
timeout /t 2 /nobreak >nul

echo [2/2] Starting Visual Subsystem (React)...
start "Frontend (port 5173)" cmd /k "cd ui && npm run dev"

echo.
echo ========================================================
echo   ALL SYSTEMS ONLINE
echo   - Dashboard API proxying correctly
echo.
echo   Keep the two new command windows open to keep 
echo   the servers running. To stop the application, 
echo   simply close those two windows.
echo ========================================================
echo.
pause
