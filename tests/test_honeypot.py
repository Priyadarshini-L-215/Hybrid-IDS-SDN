import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from sdn.honeypot import HoneypotServer, BANNERS, LOG_FILE

class MockStreamReader:
    def __init__(self, data=b""):
        self._data = data

    async def read(self, n=1024):
        await asyncio.sleep(0)  # Yield to event loop
        return self._data

class MockStreamWriter:
    def __init__(self, peername=('192.168.1.100', 12345), sockname=('0.0.0.0', 80)):
        self.peername = peername
        self.sockname = sockname
        self.written_data = b""
        self.is_closed = False

    def get_extra_info(self, name):
        if name == 'peername':
            return self.peername
        elif name == 'sockname':
            return self.sockname
        return None

    def write(self, data):
        self.written_data += data

    async def drain(self):
        await asyncio.sleep(0)

    def close(self):
        self.is_closed = True

    async def wait_closed(self):
        await asyncio.sleep(0)

@pytest.fixture
def honeypot_server():
    # Use a temporary directory for logs to avoid polluting test environment
    with patch('sdn.honeypot.LOG_FILE', 'data/logs/test_honeypot.jsonl'):
        server = HoneypotServer()
        yield server

@pytest.mark.asyncio
@patch('sdn.honeypot.HoneypotServer.write_log')
async def test_handle_connection_with_banner(mock_write_log, honeypot_server):
    # Port 80 has a banner
    reader = MockStreamReader(data=b"GET / HTTP/1.1\r\n\r\n")
    writer = MockStreamWriter(sockname=('0.0.0.0', 80))

    await honeypot_server.handle_connection(reader, writer)

    assert writer.written_data == BANNERS[80]
    assert honeypot_server.stats["total_connections"] == 1
    assert "192.168.1.100" in honeypot_server.stats["unique_ips"]
    assert writer.is_closed

    # Verify log entry
    mock_write_log.assert_called_once()
    log_entry = mock_write_log.call_args[0][0]
    assert log_entry["event"] == "connection"
    assert log_entry["src_ip"] == "192.168.1.100"
    assert log_entry["src_port"] == 12345
    assert log_entry["dst_port"] == 80
    assert log_entry["payload_text"] == "GET / HTTP/1.1\r\n\r\n"

@pytest.mark.asyncio
@patch('sdn.honeypot.HoneypotServer.write_log')
async def test_handle_connection_without_banner(mock_write_log, honeypot_server):
    # Port 443 does not have a banner in BANNERS
    reader = MockStreamReader(data=b"\x16\x03\x01\x00\x00")
    writer = MockStreamWriter(sockname=('0.0.0.0', 443))

    await honeypot_server.handle_connection(reader, writer)

    assert writer.written_data == b""
    assert honeypot_server.stats["total_connections"] == 1
    assert writer.is_closed

    # Verify log entry
    mock_write_log.assert_called_once()
    log_entry = mock_write_log.call_args[0][0]
    assert log_entry["dst_port"] == 443
    assert log_entry["payload_hex"] == "1603010000"

@pytest.mark.asyncio
@patch('sdn.honeypot.HoneypotServer.write_log')
async def test_handle_connection_timeout(mock_write_log, honeypot_server):
    # Mock reader to raise TimeoutError directly
    class TimeoutMockStreamReader:
        async def read(self, n=1024):
            raise asyncio.TimeoutError()

    reader = TimeoutMockStreamReader()
    writer = MockStreamWriter(sockname=('0.0.0.0', 8080))

    # wait_for takes a coroutine and raises TimeoutError if it takes too long.
    # By making the read() coroutine itself raise TimeoutError, we simulate the
    # same exception path cleanly without unawaited coroutine warnings.
    await honeypot_server.handle_connection(reader, writer)

    assert honeypot_server.stats["total_connections"] == 1
    assert writer.is_closed

    # Verify log entry
    mock_write_log.assert_called_once()
    log_entry = mock_write_log.call_args[0][0]
    assert log_entry["dst_port"] == 8080
    assert "payload_hex" not in log_entry # Should not have payload

@pytest.mark.asyncio
@patch('sdn.honeypot.HoneypotServer.write_log')
async def test_handle_connection_exception(mock_write_log, honeypot_server):
    class ErrorMockStreamReader:
        async def read(self, n=1024):
            raise ConnectionResetError("Connection reset by peer")

    reader = ErrorMockStreamReader()
    writer = MockStreamWriter(sockname=('0.0.0.0', 8080))

    await honeypot_server.handle_connection(reader, writer)

    assert writer.is_closed

    # Verify log entry
    mock_write_log.assert_called_once()
    log_entry = mock_write_log.call_args[0][0]
    assert log_entry["dst_port"] == 8080
    assert "Connection reset by peer" in log_entry["error"]
