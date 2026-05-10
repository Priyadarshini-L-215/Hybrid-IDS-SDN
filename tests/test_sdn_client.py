import pytest
import responses
import asyncio
from unittest.mock import patch, MagicMock

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
def test_block_sync_exception(sdn_client):
    # Do not add any responses so it raises ConnectionError
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
def test_unblock_sync_failure(sdn_client):
    responses.add(
        responses.POST,
        "http://test-controller:8080/sdn/unblock",
        json={"error": "failed"},
        status=500,
    )
    result = sdn_client.unblock_sync("192.168.1.1")
    assert result is False

@responses.activate
def test_unblock_sync_exception(sdn_client):
    result = sdn_client.unblock_sync("192.168.1.1")
    assert result is False

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

@responses.activate
def test_get_flows_sync_failure(sdn_client):
    responses.add(
        responses.GET,
        "http://test-controller:8080/sdn/flows",
        json={"error": "failed"},
        status=500,
    )
    result = sdn_client.get_flows_sync()
    assert result == {"blocked_ips": [], "status": "offline"}

@responses.activate
def test_get_flows_sync_exception(sdn_client):
    result = sdn_client.get_flows_sync()
    assert result == {"blocked_ips": [], "status": "offline"}

@pytest.mark.asyncio
@responses.activate
async def test_block_async_success(sdn_client):
    responses.add(
        responses.POST,
        "http://test-controller:8080/sdn/block",
        json={"status": "success"},
        status=200,
    )
    result = await sdn_client.block("192.168.1.1", 60)
    assert result is True

@pytest.mark.asyncio
@responses.activate
async def test_block_async_failure(sdn_client):
    responses.add(
        responses.POST,
        "http://test-controller:8080/sdn/block",
        body="Bad Request",
        status=400,
    )
    result = await sdn_client.block("192.168.1.1", 60)
    assert result is False

@pytest.mark.asyncio
async def test_block_async_fetch_none(sdn_client):
    with patch("asyncio.get_running_loop") as mock_loop:
        future = asyncio.Future()
        future.set_result(None)
        mock_loop.return_value.run_in_executor.return_value = future
        result = await sdn_client.block("192.168.1.1", 60)
        assert result is False

@pytest.mark.asyncio
async def test_block_async_fetch_not_200(sdn_client):
    with patch("asyncio.get_running_loop") as mock_loop:
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "Bad Request"
        mock_resp.__bool__.return_value = True

        future = asyncio.Future()
        future.set_result(mock_resp)
        mock_loop.return_value.run_in_executor.return_value = future

        result = await sdn_client.block("192.168.1.1", 60)
        assert result is False

@pytest.mark.asyncio
async def test_block_async_fetch_exception(sdn_client):
    with patch("requests.post", side_effect=Exception("Timeout")):
        result = await sdn_client.block("192.168.1.1", 60)
        assert result is False

@pytest.mark.asyncio
async def test_block_async_executor_exception(sdn_client):
    with patch("asyncio.get_running_loop") as mock_loop:
        mock_loop.return_value.run_in_executor.side_effect = Exception("Loop failed")
        result = await sdn_client.block("192.168.1.1", 60)
        assert result is False

@pytest.mark.asyncio
@responses.activate
async def test_unblock_async_success(sdn_client):
    responses.add(
        responses.POST,
        "http://test-controller:8080/sdn/unblock",
        json={"status": "success"},
        status=200,
    )
    result = await sdn_client.unblock("192.168.1.1")
    assert result is True

@pytest.mark.asyncio
@responses.activate
async def test_unblock_async_failure(sdn_client):
    responses.add(
        responses.POST,
        "http://test-controller:8080/sdn/unblock",
        body="Bad Request",
        status=400,
    )
    result = await sdn_client.unblock("192.168.1.1")
    assert result is False

@pytest.mark.asyncio
async def test_unblock_async_fetch_none(sdn_client):
    with patch("asyncio.get_running_loop") as mock_loop:
        future = asyncio.Future()
        future.set_result(None)
        mock_loop.return_value.run_in_executor.return_value = future
        result = await sdn_client.unblock("192.168.1.1")
        assert result is False

@pytest.mark.asyncio
async def test_unblock_async_fetch_not_200(sdn_client):
    with patch("asyncio.get_running_loop") as mock_loop:
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "Bad Request"
        mock_resp.__bool__.return_value = True

        future = asyncio.Future()
        future.set_result(mock_resp)
        mock_loop.return_value.run_in_executor.return_value = future

        result = await sdn_client.unblock("192.168.1.1")
        assert result is False

@pytest.mark.asyncio
async def test_unblock_async_fetch_exception(sdn_client):
    with patch("requests.post", side_effect=Exception("Timeout")):
        result = await sdn_client.unblock("192.168.1.1")
        assert result is False

@pytest.mark.asyncio
async def test_unblock_async_executor_exception(sdn_client):
    with patch("asyncio.get_running_loop") as mock_loop:
        mock_loop.return_value.run_in_executor.side_effect = Exception("Loop failed")
        result = await sdn_client.unblock("192.168.1.1")
        assert result is False

@pytest.mark.asyncio
@responses.activate
async def test_get_flows_async_success(sdn_client):
    responses.add(
        responses.GET,
        "http://test-controller:8080/sdn/flows",
        json={"blocked_ips": ["192.168.1.1"], "status": "online"},
        status=200,
    )
    result = await sdn_client.get_flows()
    assert result == {"blocked_ips": ["192.168.1.1"], "status": "online"}

@pytest.mark.asyncio
@responses.activate
async def test_get_flows_async_failure(sdn_client):
    responses.add(
        responses.GET,
        "http://test-controller:8080/sdn/flows",
        json={"error": "failed"},
        status=500,
    )
    result = await sdn_client.get_flows()
    assert result == {"blocked_ips": [], "status": "offline"}

@pytest.mark.asyncio
async def test_get_flows_async_fetch_exception(sdn_client):
    with patch("requests.get", side_effect=Exception("Timeout")):
        result = await sdn_client.get_flows()
        assert result == {"blocked_ips": [], "status": "offline"}

@pytest.mark.asyncio
async def test_get_flows_async_executor_exception(sdn_client):
    with patch("asyncio.get_running_loop") as mock_loop:
        mock_loop.return_value.run_in_executor.side_effect = Exception("Loop failed")
        result = await sdn_client.get_flows()
        assert result == {"blocked_ips": [], "status": "offline"}

@pytest.mark.asyncio
async def test_async_context_manager():
    async with SDNClient("http://test-controller:8080") as client:
        assert client.base_url == "http://test-controller:8080"

def test_init_default_url():
    with patch("common.config.SDN_CONTROLLER_HOST", "127.0.0.1"), \
         patch("common.config.SDN_CONTROLLER_PORT", 8080):
        client = SDNClient()
        assert client.base_url == "http://127.0.0.1:8080"

@pytest.mark.asyncio
async def test_block_fetch_inner_exception():
    client = SDNClient(controller_url="http://test-controller:8080")
    with patch("requests.post", side_effect=Exception("inner")):
        # Call fetch directly to cover lines 32-33
        # In async context, we mock requests.post to throw, and the inner fetch function catches it.
        # So we can just call client.block to let it run `fetch()` via executor.
        result = await client.block("192.168.1.1")
        assert result is False

@pytest.mark.asyncio
async def test_unblock_fetch_inner_exception():
    client = SDNClient(controller_url="http://test-controller:8080")
    with patch("requests.post", side_effect=Exception("inner")):
        result = await client.unblock("192.168.1.1")
        assert result is False

@pytest.mark.asyncio
async def test_get_flows_fetch_inner_exception():
    client = SDNClient(controller_url="http://test-controller:8080")
    with patch("requests.get", side_effect=Exception("inner")):
        result = await client.get_flows()
        assert result == {"blocked_ips": [], "status": "offline"}

@responses.activate
def test_block_sync_exception_catch(sdn_client):
    with patch("requests.post", side_effect=Exception("inner")):
        result = sdn_client.block_sync("192.168.1.1")
        assert result is False

@responses.activate
def test_unblock_sync_exception_catch(sdn_client):
    with patch("requests.post", side_effect=Exception("inner")):
        result = sdn_client.unblock_sync("192.168.1.1")
        assert result is False

@responses.activate
def test_get_flows_sync_exception_catch(sdn_client):
    with patch("requests.get", side_effect=Exception("inner")):
        result = sdn_client.get_flows_sync()
        assert result == {"blocked_ips": [], "status": "offline"}
