#!/usr/bin/env powershell
# Sentinel Core - Windows-Side WebSocket Diagnostics
# Run from Windows: powershell -NoProfile .\diagnose_connection.ps1

$ErrorActionPreference = "SilentlyContinue"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Windows-Side Connection Diagnostics" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check if WSL is available
Write-Host "[1] WSL Status" -ForegroundColor Yellow
try {
    $wsl_version = & wsl --version 2>&1
    if ($?) {
        Write-Host "  ✓ WSL is available" -ForegroundColor Green
        Write-Host "    $wsl_version" -ForegroundColor Gray
    } else {
        Write-Host "  ✗ WSL not available" -ForegroundColor Red
    }
} catch {
    Write-Host "  ✗ WSL not available: $_" -ForegroundColor Red
}
Write-Host ""

# 2. Check if localhost:8999 is reachable
Write-Host "[2] WebSocket Port (127.0.0.1:8999) Connectivity" -ForegroundColor Yellow
$tcp_test = Test-NetConnection -ComputerName 127.0.0.1 -Port 8999 -WarningAction SilentlyContinue
if ($tcp_test.TcpTestSucceeded) {
    Write-Host "  ✓ Port 8999 is reachable from Windows" -ForegroundColor Green
} else {
    Write-Host "  ✗ Port 8999 is NOT reachable from Windows" -ForegroundColor Red
    Write-Host "    This means WSL consumer isn't listening yet" -ForegroundColor Gray
}
Write-Host ""

# 3. Check Flask process
Write-Host "[3] Flask Process Status" -ForegroundColor Yellow
try {
    $flask = Get-Process python | Where-Object { $_.CommandLine -match "flask|app.py" } | Select-Object -First 1
    if ($flask) {
        Write-Host "  ✓ Flask process is running (PID: $($flask.Id))" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Flask process NOT running" -ForegroundColor Red
    }
} catch {
    Write-Host "  ✗ Error checking processes" -ForegroundColor Red
}
Write-Host ""

# 4. Check WSL consumer from Windows
Write-Host "[4] WSL Consumer Status (from Windows)" -ForegroundColor Yellow
try {
    $consumer_pid = & wsl pgrep -f "consumer.py" 2>&1
    if ($? -and $consumer_pid) {
        Write-Host "  ✓ Consumer running in WSL (PID: $consumer_pid)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Consumer NOT running in WSL" -ForegroundColor Red
    }
} catch {
    Write-Host "  ✗ Error checking WSL" -ForegroundColor Red
}
Write-Host ""

# 5. Check WSL port listening
Write-Host "[5] WSL Port Listening Check" -ForegroundColor Yellow
try {
    $port_check = & wsl netstat -tlnp 2>&1 | Select-String "8999"
    if ($port_check) {
        Write-Host "  ✓ Port 8999 is listening in WSL" -ForegroundColor Green
        Write-Host "    $port_check" -ForegroundColor Gray
    } else {
        Write-Host "  ✗ Port 8999 NOT listening in WSL" -ForegroundColor Red
    }
} catch {
    Write-Host "  ✗ Error checking WSL ports" -ForegroundColor Red
}
Write-Host ""

# 6. Check WSL consumer logs
Write-Host "[6] WSL Consumer Logs (Last 10 Lines)" -ForegroundColor Yellow
try {
    $log_lines = & wsl tail -n 10 data/logs/consumer.log 2>&1
    if ($log_lines) {
        $log_lines | ForEach-Object {
            if ($_ -match "ERROR|Exception|Traceback") {
                Write-Host "  ! $_" -ForegroundColor Red
            } elseif ($_ -match "SUCCESS|Online|Ready") {
                Write-Host "  ✓ $_" -ForegroundColor Green
            } else {
                Write-Host "    $_" -ForegroundColor Gray
            }
        }
    }
} catch {
    Write-Host "  ✗ Cannot read logs" -ForegroundColor Red
}
Write-Host ""

# 7. Summary and recommendations
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Recommendations" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$all_good = $true

if (-not ($tcp_test.TcpTestSucceeded)) {
    Write-Host "[FIX] Port 8999 not reachable:" -ForegroundColor Yellow
    Write-Host "  1. Check if consumer is running in WSL:" -ForegroundColor White
    Write-Host "     wsl bash diagnose_websocket.sh" -ForegroundColor Cyan
    Write-Host "  2. If not running, start it:" -ForegroundColor White
    Write-Host "     wsl bash start_ids.sh" -ForegroundColor Cyan
    Write-Host ""
    $all_good = $false
}

try {
    $consumer_pid = & wsl pgrep -f "consumer.py" 2>&1
    if (-not ($? -and $consumer_pid)) {
        Write-Host "[FIX] Consumer not running in WSL:" -ForegroundColor Yellow
        Write-Host "  wsl bash start_ids.sh" -ForegroundColor Cyan
        Write-Host ""
        $all_good = $false
    }
} catch {
    $all_good = $false
}

$flask_process = Get-Process python | Where-Object { $_.CommandLine -match "flask|app.py" } | Select-Object -First 1
if (-not $flask_process) {
    Write-Host "[FIX] Flask not running on Windows:" -ForegroundColor Yellow
    Write-Host "  Make sure Flask backend terminal is open and running" -ForegroundColor Cyan
    Write-Host "  Or restart: .\start.bat" -ForegroundColor Cyan
    Write-Host ""
    $all_good = $false
}

if ($all_good) {
    Write-Host "✓ All systems appear healthy!" -ForegroundColor Green
    Write-Host ""
    Write-Host "If Flask relay still can't connect:" -ForegroundColor Yellow
    Write-Host "  1. Check Windows Firewall for port 8999" -ForegroundColor White
    Write-Host "  2. Try WSL IP instead of localhost:" -ForegroundColor White
    Write-Host "     wsl hostname -I" -ForegroundColor Cyan
    Write-Host "  3. Restart WSL: wsl --shutdown" -ForegroundColor Cyan
} else {
    Write-Host "[ACTION REQUIRED] Please fix the issues above" -ForegroundColor Red
}

Write-Host ""
Write-Host "For detailed help, see: WEBSOCKET_TROUBLESHOOTING.md" -ForegroundColor Gray
Write-Host ""
