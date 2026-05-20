"""Tests for alert list and alert detail endpoints."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch


SAMPLE_ALERT = {
    "id": 1,
    "event_id": "abc-123",
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.1",
    "src_port": 54321,
    "dst_port": 443,
    "protocol": "TCP",
    "prediction": "attack",
    "confidence": 0.97,
    "category": "Port Scan",
    "alert_sig": "ET SCAN Nmap",
    "final_score": 0.95,
    "timestamp": "2026-05-12T10:00:00Z",
    "raw_event": {},
    "shap_top3": [],
    "enrichment": {},
}


@pytest.mark.asyncio
async def test_get_alerts_empty(client, mock_db):
    """GET /api/alerts with no data should return empty list."""
    response = await client.get("/api/alerts")
    assert response.status_code == 200
    data = response.json()
    assert "alerts" in data
    assert isinstance(data["alerts"], list)
    assert data["displayed_total"] == 0


@pytest.mark.asyncio
async def test_get_alerts_with_data(client):
    """GET /api/alerts should return alert list from DB."""
    with patch("relay.routes.intelligence_api.get_recent_alerts",
               new_callable=AsyncMock, return_value=[SAMPLE_ALERT]), \
         patch("relay.routes.intelligence_api.get_stats",
               new_callable=AsyncMock,
               return_value={"total_processed": 1, "attack_total": 1, "normal_total": 0}):
        response = await client.get("/api/alerts")

    assert response.status_code == 200
    data = response.json()
    assert len(data["alerts"]) == 1
    assert data["alerts"][0]["prediction"] == "attack"
    assert data["total_processed"] == 1
    assert data["attack_total"] == 1


@pytest.mark.asyncio
async def test_get_alerts_limit_param(client):
    """GET /api/alerts?limit=5 should respect the limit parameter."""
    alerts = [SAMPLE_ALERT] * 3
    with patch("relay.routes.intelligence_api.get_recent_alerts",
               new_callable=AsyncMock, return_value=alerts) as mock_fn, \
         patch("relay.routes.intelligence_api.get_stats",
               new_callable=AsyncMock,
               return_value={"total_processed": 3, "attack_total": 3, "normal_total": 0}):
        response = await client.get("/api/alerts?limit=5")
        mock_fn.assert_awaited_once_with(5)

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_get_alert_detail_not_found(client, mock_db):
    """GET /api/alerts/{id} for nonexistent alert should return 404."""
    response = await client.get("/api/alerts/9999")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_get_alert_detail_by_numeric_id(client):
    """GET /api/alerts/{numeric_id} should return full alert."""
    with patch("relay.routes.intelligence_api.get_alert_by_id",
               new_callable=AsyncMock, return_value=SAMPLE_ALERT):
        response = await client.get("/api/alerts/1")

    assert response.status_code == 200
    data = response.json()
    assert data["event_id"] == "abc-123"
    assert data["prediction"] == "attack"


@pytest.mark.asyncio
async def test_get_alert_detail_by_event_id(client):
    """GET /api/alerts/{event_id} using string event_id should work."""
    with patch("relay.routes.intelligence_api.get_alert_by_id",
               new_callable=AsyncMock, return_value=SAMPLE_ALERT):
        response = await client.get("/api/alerts/abc-123")

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == 1
