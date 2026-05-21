import pytest
import asyncio
import subprocess
from unittest.mock import MagicMock, patch, AsyncMock
from ml_engine.firewall import ActiveFirewall

@pytest.fixture(autouse=True)
async def reset_firewall():
    """Reset ActiveFirewall class-level state before and after each test."""
    ActiveFirewall._initialized = False
    ActiveFirewall._backend = "legacy"
    ActiveFirewall._redis_client = None
    ActiveFirewall._sdn_client = None
    ActiveFirewall._decay_task = None
    ActiveFirewall._kernel_sets_initialized = True
    yield
    await ActiveFirewall.close()

@pytest.mark.asyncio
async def test_is_blocked_true(mocker):
    """Test that is_blocked returns True when ipset test returns 0."""
    # Mock _initialize to avoid actually creating sets / connecting to Redis
    mocker.patch.object(ActiveFirewall, "_initialize", AsyncMock())
    
    mock_run = mocker.patch("subprocess.run")
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    # Ensure it's marked initialized
    ActiveFirewall._initialized = True
    
    blocked = await ActiveFirewall.is_blocked("1.2.3.4")
    assert blocked is True
    
    # Verify the mocked subprocess was called correctly inside run_in_executor
    mock_run.assert_called_once()
    called_args = mock_run.call_args
    assert called_args[0][0] == ["sudo", "ipset", "test", "sentinel_blocks", "1.2.3.4"]
    assert called_args[1].get("capture_output") is True
    assert called_args[1].get("check") is False

@pytest.mark.asyncio
async def test_is_blocked_false(mocker):
    """Test that is_blocked returns False when ipset test returns 1."""
    mocker.patch.object(ActiveFirewall, "_initialize", AsyncMock())
    
    mock_run = mocker.patch("subprocess.run")
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_run.return_value = mock_result

    ActiveFirewall._initialized = True
    
    blocked = await ActiveFirewall.is_blocked("1.2.3.4")
    assert blocked is False
    
    mock_run.assert_called_once()

@pytest.mark.asyncio
async def test_legacy_block(mocker):
    """Test that _legacy_block calls ipset add with the correct arguments."""
    mocker.patch.object(ActiveFirewall, "_initialize", AsyncMock())
    
    mock_run = mocker.patch("subprocess.run")
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    ActiveFirewall._initialized = True
    
    await ActiveFirewall._legacy_block("1.2.3.4", ttl=3600)
    
    mock_run.assert_called_once()
    called_args = mock_run.call_args
    assert called_args[0][0] == ["sudo", "ipset", "add", "sentinel_blocks", "1.2.3.4", "timeout", "3600", "-!"]
    assert called_args[1].get("check") is True

@pytest.mark.asyncio
async def test_rate_limit(mocker):
    """Test that rate_limit calls ipset add on the correct set."""
    mocker.patch.object(ActiveFirewall, "_initialize", AsyncMock())
    
    mock_run = mocker.patch("subprocess.run")
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    ActiveFirewall._initialized = True
    
    await ActiveFirewall.rate_limit("1.2.3.4")
    
    mock_run.assert_called_once()
    called_args = mock_run.call_args
    assert called_args[0][0] == ["sudo", "ipset", "add", "sentinel_limited", "1.2.3.4", "-!"]
    assert called_args[1].get("check") is True

@pytest.mark.asyncio
async def test_unblock(mocker):
    """Test that unblock calls ipset del on both sets."""
    mocker.patch.object(ActiveFirewall, "_initialize", AsyncMock())
    
    mock_run = mocker.patch("subprocess.run")
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    ActiveFirewall._initialized = True
    
    await ActiveFirewall.unblock("1.2.3.4")
    
    # It should call subprocess.run twice: once for sentinel_blocks, once for sentinel_limited
    assert mock_run.call_count == 2
    
    first_call_args = mock_run.call_args_list[0]
    assert first_call_args[0][0] == ["sudo", "ipset", "del", "sentinel_blocks", "1.2.3.4", "-!"]
    assert first_call_args[1].get("check") is False
    
    second_call_args = mock_run.call_args_list[1]
    assert second_call_args[0][0] == ["sudo", "ipset", "del", "sentinel_limited", "1.2.3.4", "-!"]
    assert second_call_args[1].get("check") is False

@pytest.mark.asyncio
async def test_is_blocked_ipv6(mocker):
    """Test that is_blocked checks the correct v6 ipset for an IPv6 address."""
    mocker.patch.object(ActiveFirewall, "_initialize", AsyncMock())
    
    mock_run = mocker.patch("subprocess.run")
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    ActiveFirewall._initialized = True
    
    blocked = await ActiveFirewall.is_blocked("fe80::1")
    assert blocked is True
    
    mock_run.assert_called_once()
    called_args = mock_run.call_args
    assert called_args[0][0] == ["sudo", "ipset", "test", "sentinel_blocks_v6", "fe80::1"]
    assert called_args[1].get("capture_output") is True
    assert called_args[1].get("check") is False

@pytest.mark.asyncio
async def test_legacy_block_ipv6(mocker):
    """Test that _legacy_block targets sentinel_blocks_v6 for an IPv6 address."""
    mocker.patch.object(ActiveFirewall, "_initialize", AsyncMock())
    
    mock_run = mocker.patch("subprocess.run")
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    ActiveFirewall._initialized = True
    
    await ActiveFirewall._legacy_block("fe80::1", ttl=3600)
    
    mock_run.assert_called_once()
    called_args = mock_run.call_args
    assert called_args[0][0] == ["sudo", "ipset", "add", "sentinel_blocks_v6", "fe80::1", "timeout", "3600", "-!"]
    assert called_args[1].get("check") is True

@pytest.mark.asyncio
async def test_rate_limit_ipv6(mocker):
    """Test that rate_limit targets sentinel_limited_v6 for an IPv6 address."""
    mocker.patch.object(ActiveFirewall, "_initialize", AsyncMock())
    
    mock_run = mocker.patch("subprocess.run")
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    ActiveFirewall._initialized = True
    
    await ActiveFirewall.rate_limit("fe80::1")
    
    mock_run.assert_called_once()
    called_args = mock_run.call_args
    assert called_args[0][0] == ["sudo", "ipset", "add", "sentinel_limited_v6", "fe80::1", "-!"]
    assert called_args[1].get("check") is True

@pytest.mark.asyncio
async def test_unblock_ipv6(mocker):
    """Test that unblock clears both v6 ipsets for an IPv6 address."""
    mocker.patch.object(ActiveFirewall, "_initialize", AsyncMock())
    
    mock_run = mocker.patch("subprocess.run")
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    ActiveFirewall._initialized = True
    
    await ActiveFirewall.unblock("fe80::1")
    
    assert mock_run.call_count == 2
    
    first_call_args = mock_run.call_args_list[0]
    assert first_call_args[0][0] == ["sudo", "ipset", "del", "sentinel_blocks_v6", "fe80::1", "-!"]
    assert first_call_args[1].get("check") is False
    
    second_call_args = mock_run.call_args_list[1]
    assert second_call_args[0][0] == ["sudo", "ipset", "del", "sentinel_limited_v6", "fe80::1", "-!"]
    assert second_call_args[1].get("check") is False

