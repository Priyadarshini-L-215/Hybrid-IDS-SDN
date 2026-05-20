"""
Pytest fixtures for relay API tests.

Provides:
    - ``client``: An HTTPX async test client wired to the FastAPI app.
    - ``mock_redis``: AsyncMock that replaces the live Redis client.
    - ``mock_firewall``: Patches ActiveFirewall class methods.
    - ``mock_db``: Patches the async_database proxy functions.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure 'src' is in the path
src_root = str(Path(__file__).resolve().parents[2] / "src")
if src_root not in sys.path:
    sys.path.insert(0, src_root)

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport


@pytest.fixture(scope="session")
def event_loop_policy():
    """Use the default asyncio event loop policy."""
    import asyncio
    return asyncio.DefaultEventLoopPolicy()


@pytest_asyncio.fixture
async def client(mock_redis, mock_firewall):
    """HTTPX async client wired to the relay FastAPI app.

    Patches Redis and Firewall so tests run without live services.
    """
    # Patch Redis before importing the app so init does not fail
    with patch("ml_engine.redis_client.async_redis_client", mock_redis):
        from relay.app import app
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test"
        ) as ac:
            yield ac


@pytest.fixture
def mock_redis():
    """AsyncMock for the Redis client."""
    redis = AsyncMock()
    redis.ping = AsyncMock(return_value=True)
    redis.xlen = AsyncMock(return_value=0)
    # scan_iter returns an empty async generator by default
    async def _empty_scan(*args, **kwargs):
        return
        yield  # Make it an async generator

    redis.scan_iter = _empty_scan
    return redis


@pytest.fixture
def mock_firewall():
    """Patch ActiveFirewall class methods."""
    with patch("ml_engine.firewall.ActiveFirewall.block", new_callable=AsyncMock) as mock_block, \
         patch("ml_engine.firewall.ActiveFirewall.unblock", new_callable=AsyncMock) as mock_unblock, \
         patch("ml_engine.firewall.ActiveFirewall.get_status", new_callable=AsyncMock,
               return_value={"backend": "ipset", "blocked_count": 0}) as mock_status, \
         patch("ml_engine.firewall.ActiveFirewall.get_detailed_status", new_callable=AsyncMock,
               return_value={"permanent_ips": [], "reputation": {}}) as mock_detailed, \
         patch("ml_engine.firewall.ActiveFirewall.is_blocked", return_value=False):
        yield {
            "block": mock_block,
            "unblock": mock_unblock,
            "status": mock_status,
            "detailed": mock_detailed,
        }


@pytest.fixture
def mock_db():
    """Patch database functions in the route modules where they are imported."""
    # Note: intelligence_api imports these directly at top-level
    with patch("relay.routes.intelligence_api.get_recent_alerts", new_callable=AsyncMock,
               return_value=[]) as mock_alerts, \
         patch("relay.routes.intelligence_api.get_stats", new_callable=AsyncMock,
               return_value={"total_processed": 0, "attack_total": 0, "normal_total": 0}) as mock_stats, \
         patch("relay.routes.intelligence_api.get_alert_by_id", new_callable=AsyncMock,
               return_value=None) as mock_get_alert, \
         patch("common.database.db", new_callable=MagicMock) as mock_db_proxy, \
         patch("common.database.add_false_positive", new_callable=AsyncMock,
               return_value=True) as mock_fp, \
         patch("common.database.get_alert_signature", new_callable=AsyncMock,
               return_value="ET SCAN Nmap") as mock_sig:
        
        # mock_db_proxy is the db proxy used in routes
        mock_db_proxy.get_ip_forensics = AsyncMock(return_value=None)
        mock_db_proxy.find_similar_ips = AsyncMock(return_value=[])
        
        yield {
            "alerts": mock_alerts,
            "stats": mock_stats,
            "get_alert": mock_get_alert,
            "forensics": mock_db_proxy.get_ip_forensics,
            "similar": mock_db_proxy.find_similar_ips,
            "fp": mock_fp,
            "sig": mock_sig,
        }
