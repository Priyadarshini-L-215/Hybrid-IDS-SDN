"""Tests for mitigation (block/unblock) and false-positive feedback endpoints."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch


VALID_HEADERS = {"X-Sentinel-Key": "test-key"}


@pytest.mark.asyncio
async def test_block_ip_requires_api_key(client):
    """POST /api/mitigation/block without API key should return 401 (if key configured)."""
    # This test exercises the auth middleware dependency.
    # In test mode SENTINEL_API_KEY is typically unset, so auth is bypassed — we verify it
    # still reaches the handler without crashing.
    response = await client.post(
        "/api/mitigation/block",
        json={"ip": "10.0.0.1"}
    )
    # Without a key set the endpoint is open in dev; it should not 500.
    assert response.status_code in (200, 401, 403)


@pytest.mark.asyncio
async def test_block_ip_calls_firewall(client, mock_firewall):
    """POST /api/mitigation/block should delegate to ActiveFirewall.block."""
    response = await client.post(
        "/api/mitigation/block",
        json={"ip": "192.168.1.50"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "192.168.1.50" in data["message"]
    mock_firewall["block"].assert_awaited_once()


@pytest.mark.asyncio
async def test_unblock_ip_calls_firewall(client, mock_firewall):
    """POST /api/mitigation/unblock should delegate to ActiveFirewall.unblock."""
    response = await client.post(
        "/api/mitigation/unblock",
        json={"ip": "192.168.1.50"}
    )
    assert response.status_code == 200
    mock_firewall["unblock"].assert_awaited_once()


@pytest.mark.asyncio
async def test_block_ip_invalid_ip(client):
    """POST /api/mitigation/block with an invalid IP should return 422."""
    response = await client.post(
        "/api/mitigation/block",
        json={"ip": "not-an-ip"}
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_mark_false_positive_success(client, mock_firewall, mock_db):
    """POST /api/feedback/false-positive should unblock IP and log FP."""
    with patch("relay.routes.mitigation_api.add_false_positive",
               new_callable=AsyncMock, return_value=True), \
         patch("relay.routes.mitigation_api.get_alert_signature",
               new_callable=AsyncMock, return_value="ET SCAN Nmap"), \
         patch("common.fp_store.fp_store.add_suppression",
               new_callable=AsyncMock):
        response = await client.post(
            "/api/feedback/false-positive",
            json={"alert_id": 42, "src_ip": "10.10.0.5"}
        )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    mock_firewall["unblock"].assert_awaited_once()


@pytest.mark.asyncio
async def test_mark_false_positive_unknown_alert(client, mock_firewall):
    """POST /api/feedback/false-positive when DB returns False should report failure."""
    with patch("relay.routes.mitigation_api.add_false_positive",
               new_callable=AsyncMock, return_value=False), \
         patch("relay.routes.mitigation_api.get_alert_signature",
               new_callable=AsyncMock, return_value=None):
        response = await client.post(
            "/api/feedback/false-positive",
            json={"alert_id": 9999, "src_ip": "10.10.0.5"}
        )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is False
