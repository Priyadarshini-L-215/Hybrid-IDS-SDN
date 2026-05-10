import pytest
from unittest.mock import patch, MagicMock

from common.net_utils import get_local_ip, get_gateway_ip

def test_get_local_ip_subprocess_success():
    """Test get_local_ip when subprocess succeeds."""
    with patch("common.net_utils.subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "192.168.1.100 \n"
        mock_run.return_value = mock_result

        # We need to clear the cache first
        import common.net_utils as net_utils
        net_utils._LOCAL_IP_TIME = 0.0

        ip = get_local_ip()
        assert ip == "192.168.1.100"
        mock_run.assert_called_once()

def test_get_local_ip_fallback_socket_success():
    """Test get_local_ip fallback when subprocess fails but socket succeeds."""
    with patch("common.net_utils.subprocess.run") as mock_run, \
         patch("common.net_utils.socket.socket") as mock_socket:

        # Subprocess fails
        mock_run.side_effect = Exception("Subprocess failed")

        # Socket succeeds
        mock_sock_instance = MagicMock()
        mock_sock_instance.getsockname.return_value = ("10.0.0.5", 12345)
        mock_socket.return_value = mock_sock_instance

        # Clear cache
        import common.net_utils as net_utils
        net_utils._LOCAL_IP_TIME = 0.0

        ip = get_local_ip()
        assert ip == "10.0.0.5"
        mock_run.assert_called_once()
        mock_socket.assert_called_once()
        mock_sock_instance.connect.assert_called_once_with(("8.8.8.8", 80))

def test_get_local_ip_all_fail():
    """Test get_local_ip when both subprocess and socket fail."""
    with patch("common.net_utils.subprocess.run") as mock_run, \
         patch("common.net_utils.socket.socket") as mock_socket:

        # Subprocess fails
        mock_run.side_effect = Exception("Subprocess failed")

        # Socket fails
        mock_socket.side_effect = Exception("Socket failed")

        # Clear cache
        import common.net_utils as net_utils
        net_utils._LOCAL_IP_TIME = 0.0

        ip = get_local_ip()
        assert ip is None
        mock_run.assert_called_once()
        mock_socket.assert_called_once()

def test_get_gateway_ip_success():
    """Test get_gateway_ip when subprocess succeeds."""
    with patch("common.net_utils.subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "default via 192.168.1.1 dev eth0 \n192.168.1.0/24 dev eth0 \n"
        mock_run.return_value = mock_result

        # Clear cache
        import common.net_utils as net_utils
        net_utils._GW_IP_TIME = 0.0

        ip = get_gateway_ip()
        assert ip == "192.168.1.1"
        mock_run.assert_called_once()

def test_get_gateway_ip_fail():
    """Test get_gateway_ip when subprocess fails."""
    with patch("common.net_utils.subprocess.run") as mock_run:
        mock_run.side_effect = Exception("Subprocess failed")

        # Clear cache
        import common.net_utils as net_utils
        net_utils._GW_IP_TIME = 0.0

        ip = get_gateway_ip()
        assert ip is None
        mock_run.assert_called_once()

def test_get_local_ip_cache():
    """Test get_local_ip uses cache when TTL has not expired."""
    with patch("common.net_utils.time.monotonic") as mock_time, \
         patch("common.net_utils.subprocess.run") as mock_run:

        import common.net_utils as net_utils

        # First call, fetches IP
        mock_time.return_value = 100.0
        net_utils._LOCAL_IP_TIME = 0.0 # Force fetch

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "192.168.1.100 \n"
        mock_run.return_value = mock_result

        ip1 = get_local_ip(cache_ttl=30.0)
        assert ip1 == "192.168.1.100"
        assert mock_run.call_count == 1

        # Second call, within TTL
        mock_time.return_value = 110.0 # Only 10 seconds later

        ip2 = get_local_ip(cache_ttl=30.0)
        assert ip2 == "192.168.1.100"
        assert mock_run.call_count == 1 # Subprocess shouldn't be called again

def test_get_gateway_ip_cache():
    """Test get_gateway_ip uses cache when TTL has not expired."""
    with patch("common.net_utils.time.monotonic") as mock_time, \
         patch("common.net_utils.subprocess.run") as mock_run:

        import common.net_utils as net_utils

        # First call, fetches IP
        mock_time.return_value = 100.0
        net_utils._GW_IP_TIME = 0.0 # Force fetch

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "default via 192.168.1.1 dev eth0 \n"
        mock_run.return_value = mock_result

        ip1 = get_gateway_ip(cache_ttl=30.0)
        assert ip1 == "192.168.1.1"
        assert mock_run.call_count == 1

        # Second call, within TTL
        mock_time.return_value = 110.0 # Only 10 seconds later

        ip2 = get_gateway_ip(cache_ttl=30.0)
        assert ip2 == "192.168.1.1"
        assert mock_run.call_count == 1 # Subprocess shouldn't be called again
