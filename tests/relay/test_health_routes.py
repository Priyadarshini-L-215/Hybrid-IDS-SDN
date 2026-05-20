"""Tests for health, pipeline status, metrics, and baseline status endpoints."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.asyncio
async def test_health_ok(client):
    """GET /api/health should return 200 with status=ok."""
    response = await client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "timestamp" in data


@pytest.mark.asyncio
async def test_metrics_endpoint(client):
    """GET /api/metrics should return Prometheus text format."""
    response = await client.get("/api/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    # Should contain at least one metric from our custom registry
    assert b"sentinel" in response.content or b"# HELP" in response.content


@pytest.mark.asyncio
async def test_pipeline_status_ok(client, mock_db):
    """GET /api/pipeline/status should return 200 with status field."""
    with patch("relay.routes.health.get_stats",
               new_callable=AsyncMock,
               return_value={"total_processed": 42, "attack_total": 5, "normal_total": 37}):
        response = await client.get("/api/pipeline/status")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] in ("active", "degraded")
    assert "redis_ok" in data
    assert "checks" in data


@pytest.mark.asyncio
async def test_pipeline_status_degraded_when_redis_down(client, mock_db):
    """Pipeline status should be 'degraded' when Redis is unavailable."""
    with patch("ml_engine.redis_client.async_redis_client", None):
        response = await client.get("/api/pipeline/status")
    # Should still return 200 — never crash — but flag degraded
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "degraded"


@pytest.mark.asyncio
async def test_pipeline_status_slim(client):
    """GET /api/pipeline/status/slim should return compact summary."""
    response = await client.get("/api/pipeline/status/slim")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "ml_engine" in data
    assert "consumer" in data
    assert "ts" in data


@pytest.mark.asyncio
async def test_baseline_status(client):
    """GET /api/baseline/status should return model metadata."""
    with patch("ml_engine.baseline_updater.baseline_monitor") as mock_bm:
        mock_bm.baseline_mean = 0.5
        mock_bm.baseline_std = 0.1
        mock_bm.drift_detected = False
        mock_bm.last_refresh = 1715000000
        response = await client.get("/api/baseline/status")
    assert response.status_code == 200
    data = response.json()
    assert "is_calibrated" in data
    assert "accuracy_pct" in data
    assert "model_version" in data
