"""Tests for GET /api/config and POST /api/config endpoints."""

from __future__ import annotations

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
import yaml
import json

VALID_CONFIG = {
    "detection": {
        "autoencoder_threshold": 0.04,
        "anomaly_min_samples": 10,
        "correlation_window": 10.0,
        "dos_threshold": 100,
        "port_scan_threshold": 25,
        "ml": {"active_model": "rf_model.pkl", "active_scaler": "scaler.pkl"},
        "decision_engine": {
            "thresholds": {"attack": 0.9, "suspicious": 0.7, "anomaly": 0.6},
            "weights": {"signature": 1.0, "ml": 0.7, "anomaly": 0.3},
        }
    },
    "mitigation": {
        "block_ttl": 300,
        "rate_limit_per_sec": 5,
        "reputation_limit": 10.0,
        "reputation_temp_block": 25.0,
        "reputation_perm_block": 50.0,
    },
    "network": {"api_port": 3000, "redis_host": "127.0.0.1", "redis_port": 6379},
    "system": {"batch_flush_interval": 0.25, "batch_size": 20, "log_level": "INFO", "use_json_logging": False, "worker_count": 8},
    "forensics": {"pcap_enabled": True}
}

INVALID_CONFIG = {
    "mitigation": {
        "reputation_limit": 50.0,
        "reputation_temp_block": 10.0,   # Must be > limit
        "reputation_perm_block": 100.0,
        "block_ttl": 300,
        "rate_limit_per_sec": 5,
    }
}

class AsyncContextManagerMock(MagicMock):
    async def __aenter__(self):
        return self.return_value
    async def __aexit__(self, *args):
        pass

@pytest.mark.asyncio
async def test_get_config_returns_json(client):
    """GET /api/config should return valid JSON representation of the config file."""
    sample_yaml = yaml.dump(VALID_CONFIG)
    
    mock_file = AsyncMock()
    mock_file.read.return_value = sample_yaml
    
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_file
    
    with patch("relay.routes.config_api.CONFIG_PATH") as mock_path, \
         patch("aiofiles.open", return_value=mock_ctx):
        mock_path.exists.return_value = True
        mock_path.encode = MagicMock(return_value=b"path")
        
        response = await client.get("/api/config")

    assert response.status_code in (200, 304)
    if response.status_code == 200:
        data = response.json()
        assert isinstance(data, dict)
        assert "network" in data

@pytest.mark.asyncio
async def test_get_config_no_file(client):
    """GET /api/config when config file is absent should return empty dict."""
    with patch("relay.routes.config_api.CONFIG_PATH") as mock_path:
        mock_path.exists.return_value = False
        response = await client.get("/api/config")

    assert response.status_code == 200
    assert response.json() == {}

@pytest.mark.asyncio
async def test_update_config_valid(client):
    """POST /api/config with a valid payload should return success."""
    full_config = dict(VALID_CONFIG)
    
    with patch("asyncio.to_thread", new_callable=AsyncMock), \
         patch("common.config.refresh_config"):
        response = await client.post(
            "/api/config",
            json={"config": full_config}
        )

    assert response.status_code == 200
    assert response.json()["success"] is True

@pytest.mark.asyncio
async def test_update_config_invalid_schema(client):
    """POST /api/config with a schema-violating payload should return 422."""
    bad_config = dict(VALID_CONFIG)
    bad_config["mitigation"] = INVALID_CONFIG["mitigation"]
    
    response = await client.post(
        "/api/config",
        json={"config": bad_config}
    )
    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
    # detail should be the list of errors
    assert isinstance(data["detail"], list)

@pytest.mark.asyncio
async def test_update_config_unknown_key(client):
    """POST /api/config with an extra unknown key should return 200 (default ignore)."""
    bad_config = dict(VALID_CONFIG)
    bad_config["nonexistent_section"] = {"foo": "bar"}

    with patch("asyncio.to_thread", new_callable=AsyncMock), \
         patch("common.config.refresh_config"):
        response = await client.post(
            "/api/config",
            json={"config": bad_config}
        )
    assert response.status_code == 200
