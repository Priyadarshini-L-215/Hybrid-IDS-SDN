"""
Developer-only Routes — Sentinel Core Relay
============================================
This router is conditionally mounted in app.py ONLY when DEV_MODE=True.
It must never be included in a production deployment.

Endpoints:
    POST /api/dev/reset — Wipes SQLite and Redis state for test resets.
"""

import asyncio
import sqlite3

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from relay.middleware.auth import require_api_key
from ml_engine import redis_client as rc

logger = structlog.get_logger("relay.routes.dev")

router = APIRouter(prefix="/api", tags=["Developer"])


class ResetConfirm(BaseModel):
    confirm: str = Field(..., description="Must be 'RESET' to confirm data wipe")


@router.post("/dev/reset", dependencies=[Depends(require_api_key)])
async def reset_system_state(req: ResetConfirm):
    """
    Developer convenience endpoint to reset SQLite and Redis state.

    Requirements:
    - Application must be started with DEV_MODE=true (enforced in app.py mount).
    - Request body must contain ``{"confirm": "RESET"}``.
    - Valid ``X-Sentinel-Key`` header must be provided.

    Returns:
        dict: Success flag and per-subsystem reset results.

    Raises:
        400: If confirmation string is wrong.
        500: If any reset operation fails.
    """
    if req.confirm != "RESET":
        raise HTTPException(
            status_code=400,
            detail='Confirmation required. Send {"confirm": "RESET"} to proceed.',
        )

    logger.warning("DEVELOPER RESET REQUESTED — wiping SQLite and Redis state")

    results: dict = {"sqlite": False, "redis": False, "errors": []}

    # --- Reset SQLite ---
    try:
        from common.config import DB_PATH

        if DB_PATH.exists():
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys = OFF;")
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            for (table_name,) in tables:
                if table_name != "sqlite_sequence":
                    cursor.execute(f"DELETE FROM {table_name};")  # noqa: S608 — intentional dev reset
            # Reset auto-increment counters
            try:
                cursor.execute("DELETE FROM sqlite_sequence;")
            except sqlite3.OperationalError:
                pass  # sqlite_sequence may not exist if no AUTOINCREMENT tables
            cursor.execute("PRAGMA foreign_keys = ON;")
            conn.commit()
            conn.close()
        results["sqlite"] = True
        logger.info("SQLite database cleared successfully")
    except Exception as e:
        logger.exception("Failed to reset SQLite")
        results["errors"].append(f"SQLite: {e}")

    # --- Reset Redis ---
    try:
        if rc.async_redis_client:
            await rc.async_redis_client.flushdb()  # flushdb only — safer than flushall
            results["redis"] = True
            logger.info("Redis DB flushed successfully")
        else:
            results["errors"].append("Redis: client not initialized")
    except Exception as e:
        logger.exception("Failed to reset Redis")
        results["errors"].append(f"Redis: {e}")

    return {"success": len(results["errors"]) == 0, "details": results}
