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
    except Exception:
        ip = None

    with _WSL_IP_CACHE_LOCK:
        _WSL_IP_CACHE_VALUE = ip
        _WSL_IP_CACHE_TIME = now

    return ip