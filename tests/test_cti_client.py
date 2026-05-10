import pytest
import time
import asyncio
from unittest.mock import patch
import requests_mock as rm
from src.ml_engine.cti_client import CTIClient, CACHE_TTL, MAX_CACHE_SIZE

@pytest.fixture
def cti_client():
    return CTIClient(api_key="valid_api_key")

@pytest.mark.asyncio
async def test_unconfigured_api_key():
    client = CTIClient(api_key="PASTE_YOUR_OTX_KEY_HERE")
    result = await client.get_ip_reputation("1.1.1.1")
    assert result == {"status": "unconfigured"}

    client2 = CTIClient(api_key="")
    result2 = await client2.get_ip_reputation("1.1.1.1")
    assert result2 == {"status": "unconfigured"}

@pytest.mark.asyncio
async def test_successful_reputation(cti_client, requests_mock):
    ip = "8.8.8.8"
    url = f"{cti_client.BASE_URL}/indicators/IPv4/{ip}/general"

    mock_data = {
        "pulse_info": {"count": 10},
        "tags": ["malware", "phishing"]
    }
    requests_mock.get(url, json=mock_data, status_code=200)

    result = await cti_client.get_ip_reputation(ip)

    assert result["status"] == "success"
    assert result["pulse_count"] == 10
    assert result["tags"] == ["malware", "phishing"]
    assert result["is_malicious"] is True
    assert 0.0 < result["reputation_score"] <= 1.0

    # Second call should be cached (no network request)
    assert ip in cti_client.cache
    assert requests_mock.call_count == 1

    result_cached = await cti_client.get_ip_reputation(ip)
    assert result_cached == result
    assert requests_mock.call_count == 1 # Still 1

@pytest.mark.asyncio
async def test_invalid_api_key(cti_client, requests_mock):
    ip = "8.8.8.8"
    url = f"{cti_client.BASE_URL}/indicators/IPv4/{ip}/general"
    requests_mock.get(url, status_code=403)

    result = await cti_client.get_ip_reputation(ip)

    assert result["status"] == "error"
    assert result["message"] == "Invalid API Key"

@pytest.mark.asyncio
async def test_network_failure(cti_client, requests_mock):
    ip = "8.8.8.8"
    url = f"{cti_client.BASE_URL}/indicators/IPv4/{ip}/general"
    requests_mock.get(url, exc=Exception("Connection error"))

    result = await cti_client.get_ip_reputation(ip)

    assert result["status"] == "error"
    assert result["message"] == "Network failure"

@pytest.mark.asyncio
async def test_cache_ttl(cti_client, requests_mock):
    ip = "1.2.3.4"
    url = f"{cti_client.BASE_URL}/indicators/IPv4/{ip}/general"
    mock_data = {"pulse_info": {"count": 1}}
    requests_mock.get(url, json=mock_data, status_code=200)

    # Initial call
    await cti_client.get_ip_reputation(ip)
    assert requests_mock.call_count == 1

    # Modify cache timestamp to be older than TTL
    data, timestamp = cti_client.cache[ip]
    cti_client.cache[ip] = (data, timestamp - CACHE_TTL - 1)

    # Second call should fetch again
    await cti_client.get_ip_reputation(ip)
    assert requests_mock.call_count == 2

@pytest.mark.asyncio
async def test_cache_size_limit(cti_client, requests_mock):
    import src.ml_engine.cti_client as cti_module
    original_max = cti_module.MAX_CACHE_SIZE
    cti_module.MAX_CACHE_SIZE = 2  # Lower size for testing

    try:
        requests_mock.get(rm.ANY, json={"pulse_info": {"count": 0}}, status_code=200)

        await cti_client.get_ip_reputation("1.1.1.1")
        await asyncio.sleep(0.01)
        await cti_client.get_ip_reputation("2.2.2.2")

        assert len(cti_client.cache) == 2
        assert "1.1.1.1" in cti_client.cache
        assert "2.2.2.2" in cti_client.cache

        # Adding a third should evict the oldest ("1.1.1.1")
        await cti_client.get_ip_reputation("3.3.3.3")

        assert len(cti_client.cache) == 2
        assert "1.1.1.1" not in cti_client.cache
        assert "2.2.2.2" in cti_client.cache
        assert "3.3.3.3" in cti_client.cache
    finally:
        cti_module.MAX_CACHE_SIZE = original_max

@pytest.mark.asyncio
async def test_calculate_score(cti_client):
    assert cti_client._calculate_score({"pulse_info": {"count": 0}}) == 0.0

    # 10 pulses -> log10(11) / 2 = 1.041 / 2 = ~0.52
    score_10 = cti_client._calculate_score({"pulse_info": {"count": 10}})
    assert 0.4 < score_10 < 0.6

    # 100 pulses -> log10(101) / 2 = 2.004 / 2 = ~1.0
    score_100 = cti_client._calculate_score({"pulse_info": {"count": 100}})
    assert score_100 == 1.0
