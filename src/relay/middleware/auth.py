"""
API Key Authentication Middleware — Sentinel Core
==================================================
Provides a simple shared-key dependency for protecting mutating endpoints.

Configuration:
    Set the env var SENTINEL_API_KEY to a secure random string.
    If unset, authentication is disabled with a startup warning (dev mode).

Usage:
    from relay.middleware.auth import require_api_key
    
    @router.post("/some/endpoint", dependencies=[Depends(require_api_key)])
    async def protected_endpoint():
        ...
"""

import os
import logging
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader

logger = logging.getLogger(__name__)

_API_KEY = os.environ.get("SENTINEL_API_KEY", "")
_AUTH_ENABLED = bool(_API_KEY)

_api_key_header = APIKeyHeader(name="X-Sentinel-Key", auto_error=False)

if not _AUTH_ENABLED:
    logger.warning(
        "[AUTH] SENTINEL_API_KEY is not set. "
        "Mutating API endpoints are UNPROTECTED. "
        "Set this environment variable in production."
    )


async def require_api_key(api_key: str = Security(_api_key_header)):
    """
    FastAPI dependency that enforces the shared API key.
    
    - If SENTINEL_API_KEY env var is not set: auth is skipped (dev mode).
    - If set: requests must include the header X-Sentinel-Key with the correct value.
    """
    if not _AUTH_ENABLED:
        # Dev mode — no key configured, allow all requests
        return

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide the X-Sentinel-Key header.",
        )

    if api_key != _API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key.",
        )
