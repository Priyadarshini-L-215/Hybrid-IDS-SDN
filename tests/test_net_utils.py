import pytest
from unittest.mock import MagicMock
import subprocess
import socket
import time
import threading

import common.net_utils as net_utils

@pytest.fixture(autouse=True)
def reset_caches():
    """Reset the caches before each test."""
    with net_utils._LOCAL_IP_LOCK:
        net_utils._LOCAL_IP_VALUE = None
        net_utils._LOCAL_IP_TIME = 0.0
    with net_utils._GW_IP_LOCK:
        net_utils._GW_IP_VALUE = None
        net_utils._GW_IP_TIME = 0.0
    yield


def test_get_local_ip_subprocess_success(mocker):
    """Test getting local IP successfully via subprocess (hostname -I)."""
    mock_run = mocker.patch("subprocess.run")
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "192.168.1.100 10.0.0.1 \n"
    mock_run.return_value = mock_result

    ip = net_utils.get_local_ip()

    assert ip == "192.168.1.100"
    mock_run.assert_called_once_with(["hostname", "-I"], capture_output=True, text=True, timeout=2)


def test_get_local_ip_subprocess_fails_socket_success(mocker):
    """Test getting local IP when subprocess fails but socket fallback succeeds."""
    mock_run = mocker.patch("subprocess.run", side_effect=Exception("hostname failed"))

    mock_socket = mocker.patch("socket.socket")
    mock_socket_instance = MagicMock()
    mock_socket.return_value = mock_socket_instance
    mock_socket_instance.getsockname.return_value = ("10.0.0.50", 12345)

    ip = net_utils.get_local_ip()

    assert ip == "10.0.0.50"
    mock_run.assert_called_once()
    mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
    mock_socket_instance.connect.assert_called_once_with(("8.8.8.8", 80))
    mock_socket_instance.getsockname.assert_called_once()
    mock_socket_instance.close.assert_called_once()


def test_get_local_ip_all_fail(mocker):
    """Test getting local IP when both subprocess and socket fallback fail."""
    mock_run = mocker.patch("subprocess.run", side_effect=Exception("hostname failed"))
    mock_socket = mocker.patch("socket.socket", side_effect=Exception("socket failed"))

    ip = net_utils.get_local_ip()

    assert ip is None
    mock_run.assert_called_once()
    mock_socket.assert_called_once()


def test_get_local_ip_caching(mocker):
    """Test that local IP results are cached properly."""
    mock_run = mocker.patch("subprocess.run")
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "192.168.1.100\n"
    mock_run.return_value = mock_result

    mock_time = mocker.patch("time.monotonic")
    mock_time.return_value = 100.0

    # First call, should call subprocess and cache
    ip1 = net_utils.get_local_ip(cache_ttl=30.0)
    assert ip1 == "192.168.1.100"
    mock_run.assert_called_once()

    # Second call, before TTL expires, should return cached
    mock_time.return_value = 110.0
    mock_run.reset_mock()
    ip2 = net_utils.get_local_ip(cache_ttl=30.0)
    assert ip2 == "192.168.1.100"
    mock_run.assert_not_called()

    # Third call, after TTL expires, should call subprocess again
    mock_time.return_value = 140.0
    mock_result.stdout = "192.168.1.101\n"
    ip3 = net_utils.get_local_ip(cache_ttl=30.0)
    assert ip3 == "192.168.1.101"
    mock_run.assert_called_once()


def test_get_gateway_ip_success(mocker):
    """Test getting gateway IP successfully via subprocess (ip route)."""
    mock_run = mocker.patch("subprocess.run")
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100 metric 100\n"
    mock_run.return_value = mock_result

    ip = net_utils.get_gateway_ip()

    assert ip == "192.168.1.1"
    mock_run.assert_called_once_with(["ip", "route"], capture_output=True, text=True, timeout=2)


def test_get_gateway_ip_fails(mocker):
    """Test getting gateway IP when subprocess fails."""
    mock_run = mocker.patch("subprocess.run", side_effect=Exception("ip route failed"))

    ip = net_utils.get_gateway_ip()

    assert ip is None
    mock_run.assert_called_once()


def test_get_gateway_ip_caching(mocker):
    """Test that gateway IP results are cached properly."""
    mock_run = mocker.patch("subprocess.run")
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "default via 192.168.1.1 dev eth0\n"
    mock_run.return_value = mock_result

    mock_time = mocker.patch("time.monotonic")
    mock_time.return_value = 100.0

    # First call, should call subprocess and cache
    ip1 = net_utils.get_gateway_ip(cache_ttl=30.0)
    assert ip1 == "192.168.1.1"
    mock_run.assert_called_once()

    # Second call, before TTL expires, should return cached
    mock_time.return_value = 110.0
    mock_run.reset_mock()
    ip2 = net_utils.get_gateway_ip(cache_ttl=30.0)
    assert ip2 == "192.168.1.1"
    mock_run.assert_not_called()

    # Third call, after TTL expires, should call subprocess again
    mock_time.return_value = 140.0
    mock_result.stdout = "default via 192.168.1.254 dev eth0\n"
    ip3 = net_utils.get_gateway_ip(cache_ttl=30.0)
    assert ip3 == "192.168.1.254"
    mock_run.assert_called_once()
