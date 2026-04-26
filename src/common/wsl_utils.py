"""Helpers for resolving WSL network details."""

from __future__ import annotations

import subprocess
import threading
import time
from typing import Optional

_WSL_IP_CACHE_LOCK = threading.Lock()
_WSL_IP_CACHE_VALUE: Optional[str] = None
_WSL_IP_CACHE_TIME = 0.0
_WSL_IP_CACHE_TTL_SEC = 30.0


def get_wsl_ip(cache_ttl_sec: float = _WSL_IP_CACHE_TTL_SEC) -> Optional[str]:
    """Return the first WSL IP address and cache the result briefly."""
    global _WSL_IP_CACHE_VALUE, _WSL_IP_CACHE_TIME

    now = time.monotonic()
    with _WSL_IP_CACHE_LOCK:
        if _WSL_IP_CACHE_TIME and now - _WSL_IP_CACHE_TIME < cache_ttl_sec:
            return _WSL_IP_CACHE_VALUE

    ip = None
    try:
        import sys
        if sys.platform != "linux":
            result = subprocess.run(
                ["wsl", "hostname", "-I"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                if output:
                    ip = output.split()[0].strip()
        else:
            # On Linux (WSL), get local IP directly
            try:
                # Try hostname -I first
                res = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=1)
                if res.returncode == 0 and res.stdout.strip():
                    ip = res.stdout.split()[0].strip()
                else:
                    import socket
                    # Outbound IP trick
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    ip = s.getsockname()[0]
                    s.close()
            except:
                import socket
                ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        ip = None

    with _WSL_IP_CACHE_LOCK:
        _WSL_IP_CACHE_VALUE = ip
        _WSL_IP_CACHE_TIME = now

    return ip

def get_gateway_ip() -> Optional[str]:
    """Return the default gateway IP (usually the Windows host in WSL)."""
    try:
        # works on Linux/WSL
        result = subprocess.run(
            ["ip", "route"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "default via" in line:
                    return line.split()[2].strip()
    except Exception:
        pass
    return None