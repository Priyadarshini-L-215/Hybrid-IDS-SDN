@echo off
setlocal EnableDelayedExpansion
title Sentinel Core - Deep Pipeline Diagnostics
color 0B

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "PYTHON_EXE=%ROOT%\.venv\Scripts\python.exe"
set "CHECK_SCRIPT=%TEMP%\sentinel_check.py"
set /a PASS=0
set /a FAIL=0

echo.
echo  ================================================================
echo   SENTINEL CORE - DEEP PIPELINE DIAGNOSTICS
echo  ================================================================
echo.

:: -- 1. Python venv --
echo  [CHECK 1/8] Python virtual environment
if exist "%PYTHON_EXE%" (
    echo    [PASS] venv found: %PYTHON_EXE%
    set /a PASS+=1
) else (
    echo    [FAIL] .venv\Scripts\python.exe not found
    set /a FAIL+=1
)
echo.

:: -- 2. WSL available --
echo  [CHECK 2/8] WSL2 availability
where wsl >nul 2>&1
if errorlevel 1 (
    echo    [FAIL] WSL command not found in PATH
    set /a FAIL+=1
) else (
    echo    [PASS] WSL command found
    set /a PASS+=1
)
echo.

:: -- 3. WSL running --
echo  [CHECK 3/8] WSL instance running
wsl hostname -I >nul 2>&1
if not errorlevel 1 (
    echo    [PASS] WSL is running
    set /a PASS+=1
) else (
    echo    [FAIL] WSL is NOT running
    set /a FAIL+=1
)
echo.

:: -- 4. Redis inside WSL --
echo  [CHECK 4/8] Redis server  (redis-cli PING)
for /f %%R in ('wsl redis-cli ping 2^>nul') do set "REDIS_PONG=%%R"
if "!REDIS_PONG!"=="PONG" (
    echo    [PASS] Redis is responding with PONG
    set /a PASS+=1
) else (
    echo    [FAIL] Redis is NOT running inside WSL
    set /a FAIL+=1
)
echo.

:: -- 5. Consumer process --
echo  [CHECK 5/8] ML consumer process  (pgrep consumer.py)
for /f %%P in ('wsl pgrep -f consumer.py 2^>nul') do set "CONS_PID=%%P"
if defined CONS_PID (
    echo    [PASS] consumer.py is running  (PID: !CONS_PID!^)
    set /a PASS+=1
) else (
    echo    [FAIL] consumer.py is NOT running inside WSL
    set /a FAIL+=1
)
echo.

:: -- 6. WebSocket Deep Probe --
echo  [CHECK 6/8] WebSocket Handshake (Port 8765)
(
echo import asyncio
echo import websockets
echo import sys
echo async def check^(^):
echo     try:
echo         async with websockets.connect^('ws://127.0.0.1:8765', open_timeout=5^):
echo             print^('OK'^)
echo     except Exception as e:
echo         print^(f'FAIL: {e}'^)
echo asyncio.run^(check^(^)^)
) > "%CHECK_SCRIPT%"

"%PYTHON_EXE%" "%CHECK_SCRIPT%" 2>nul | find "OK" >nul
if not errorlevel 1 (
    echo    [PASS] Handshake successful on 127.0.0.1:8765
    set /a PASS+=1
) else (
    echo    [FAIL] Port 8765 WS handshake failed
    echo    [INFO] Error details:
    "%PYTHON_EXE%" "%CHECK_SCRIPT%"
    set /a FAIL+=1
)
del "%CHECK_SCRIPT%" >nul 2>&1
echo.

:: -- 7. Flask relay --
echo  [CHECK 7/8] Flask relay health  (http://127.0.0.1:5000/api/health)
(
echo import urllib.request, json, sys
echo try:
echo     r = urllib.request.urlopen^('http://127.0.0.1:5000/api/health', timeout=2^)
echo     d = json.loads^(r.read^(^)^)
echo     if d.get^('flask'^) == 'ok': print^('OK'^)
echo     else: print^('FAIL: Service reported status ' + str^(d.get^('flask'^)^)^)
echo except Exception as e:
echo     print^(f'FAIL: {e}'^)
) > "%CHECK_SCRIPT%"

"%PYTHON_EXE%" "%CHECK_SCRIPT%" 2>nul | find "OK" >nul
if not errorlevel 1 (
    echo    [PASS] Flask relay is responding at :5000
    set /a PASS+=1
) else (
    echo    [FAIL] Flask relay is NOT responding
    echo    [INFO] Error details:
    "%PYTHON_EXE%" "%CHECK_SCRIPT%"
    set /a FAIL+=1
)
del "%CHECK_SCRIPT%" >nul 2>&1
echo.

:: -- 8. Integration Test --
echo  [CHECK 8/8] Relay-to-Consumer Link status
(
echo import urllib.request, json, sys
echo try:
echo     r = urllib.request.urlopen^('http://127.0.0.1:5000/api/pipeline/status', timeout=2^)
echo     d = json.loads^(r.read^(^)^)
echo     state = d.get^('relay', {}^).get^('state'^)
echo     if state == 'connected': print^('OK'^)
echo     else: print^('FAIL: ' + str^(state^)^)
echo except Exception as e:
echo     print^(f'FAIL: {e}'^)
) > "%CHECK_SCRIPT%"

"%PYTHON_EXE%" "%CHECK_SCRIPT%" 2>nul | find "OK" >nul
if not errorlevel 1 (
    echo    [PASS] Windows Relay is CONNECTED to WSL Consumer
    set /a PASS+=1
) else (
    echo    [FAIL] Pipeline is DISCONNECTED
    echo    [INFO] Last Error:
    "%PYTHON_EXE%" -c "import urllib.request, json; d=json.loads^(urllib.request.urlopen^('http://127.0.0.1:5000/api/pipeline/status'^).read^(^)^); print^(f\"       ! {d['relay']['last_error']}\"^)" 2>nul
    set /a FAIL+=1
)
del "%CHECK_SCRIPT%" >nul 2>&1
echo.

:: -- Summary --
echo  ================================================================
echo   RESULT: !PASS!/8 checks passed
echo  ================================================================
if !FAIL! EQU 0 (
    echo   [SUCCESS] Integration verified. Dashboard should be live.
) else (
    echo   [ERROR] Found !FAIL! failures.
)
echo  ================================================================
echo.
pause
