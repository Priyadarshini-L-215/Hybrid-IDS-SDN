"""Network utility helpers for native Linux."""

from __future__ import annotations

import subprocess
import socket
import threading
import time
from typing import Optional

# ── Local IP Cache ──
_LOCAL_IP_LOCK = threading.Lock()
_LOCAL_IP_VALUE: Optional[str] = None
_LOCAL_IP_TIME = 0.0
_CACHE_TTL = 30.0


def get_local_ip(cache_ttl: float = _CACHE_TTL) -> Optional[str]:
    """Return the primary local IP address, cached with a TTL."""
    global _LOCAL_IP_VALUE, _LOCAL_IP_TIME

    now = time.monotonic()
    with _LOCAL_IP_LOCK:
        if _LOCAL_IP_TIME and now - _LOCAL_IP_TIME < cache_ttl:
            return _LOCAL_IP_VALUE

    ip = None
    try:
        res = subprocess.run(
            ["hostname", "-I"], capture_output=True, text=True, timeout=2
        )
        if res.returncode == 0 and res.stdout.strip():
            ip = res.stdout.split()[0].strip()
    except Exception:
        pass

    if not ip:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

    with _LOCAL_IP_LOCK:
        _LOCAL_IP_VALUE = ip
        _LOCAL_IP_TIME = now

    return ip


# ── Gateway IP Cache ──
_GW_IP_LOCK = threading.Lock()
_GW_IP_VALUE: Optional[str] = None
_GW_IP_TIME = 0.0


def get_gateway_ip(cache_ttl: float = _CACHE_TTL) -> Optional[str]:
    """Return the default gateway IP, cached with a TTL."""
    global _GW_IP_VALUE, _GW_IP_TIME

    now = time.monotonic()
    with _GW_IP_LOCK:
        if _GW_IP_TIME and now - _GW_IP_TIME < cache_ttl:
            return _GW_IP_VALUE

    ip = None
    try:
        result = subprocess.run(
            ["ip", "route"], capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "default via" in line:
                    ip = line.split()[2].strip()
                    break
    except Exception:
        pass

    with _GW_IP_LOCK:
        _GW_IP_VALUE = ip
        _GW_IP_TIME = now

    return ip
