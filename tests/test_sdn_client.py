import pytest
import responses
import respx
import httpx
from ml_engine.sdn_client import SDNClient

@pytest.fixture
def sdn_client():
    return SDNClient(controller_url="http://test-controller:8080")

@responses.activate
def test_block_sync_success(sdn_client):
    responses.add(
        responses.POST,
        "http://test-controller:8080/sdn/block",
        json={"status": "success"},
        status=200,
    )
    result = sdn_client.block_sync("192.168.1.1", 60)
    assert result is True

@responses.activate
def test_block_sync_failure(sdn_client):
    responses.add(
        responses.POST,
        "http://test-controller:8080/sdn/block",
        json={"error": "failed"},
        status=500,
    )
    result = sdn_client.block_sync("192.168.1.1", 60)
    assert result is False

@responses.activate
def test_unblock_sync_success(sdn_client):
    responses.add(
        responses.POST,
        "http://test-controller:8080/sdn/unblock",
        json={"status": "success"},
        status=200,
    )
    result = sdn_client.unblock_sync("192.168.1.1")
    assert result is True

@responses.activate
def test_get_flows_sync_success(sdn_client):
    responses.add(
        responses.GET,
        "http://test-controller:8080/sdn/flows",
        json={"blocked_ips": ["192.168.1.1"], "status": "online"},
        status=200,
    )
    result = sdn_client.get_flows_sync()
    assert result == {"blocked_ips": ["192.168.1.1"], "status": "online"}

@pytest.mark.asyncio
@respx.mock
async def test_block_async_success(sdn_client):
    respx.post("http://test-controller:8080/sdn/block").mock(return_value=httpx.Response(200, json={"status": "success"}))
    result = await sdn_client.block("192.168.1.1", 60)
    assert result is True

@pytest.mark.asyncio
@respx.mock
async def test_block_async_failure(sdn_client):
    respx.post("http://test-controller:8080/sdn/block").mock(return_value=httpx.Response(400, text="Bad Request"))
    result = await sdn_client.block("192.168.1.1", 60)
    assert result is False

@pytest.mark.asyncio
@respx.mock
async def test_unblock_async_success(sdn_client):
    respx.post("http://test-controller:8080/sdn/unblock").mock(return_value=httpx.Response(200, json={"status": "success"}))
    result = await sdn_client.unblock("192.168.1.1")
    assert result is True

@pytest.mark.asyncio
@respx.mock
async def test_get_flows_async_success(sdn_client):
    respx.get("http://test-controller:8080/sdn/flows").mock(
        return_value=httpx.Response(200, json={"blocked_ips": ["192.168.1.1"], "status": "online"})
    )
    result = await sdn_client.get_flows()
    assert result == {"blocked_ips": ["192.168.1.1"], "status": "online"}

@pytest.mark.asyncio
@respx.mock
async def test_get_flows_async_failure(sdn_client):
    respx.get("http://test-controller:8080/sdn/flows").mock(return_value=httpx.Response(500))
    result = await sdn_client.get_flows()
    assert result == {"blocked_ips": [], "status": "offline"}

@pytest.mark.asyncio
async def test_async_context_manager():
    async with SDNClient("http://test-controller:8080") as client:
        assert client.base_url == "http://test-controller:8080"
        assert client._async_client is not None
    assert client._async_client is None
