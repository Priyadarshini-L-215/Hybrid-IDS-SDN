import pytest
import orjson
from unittest.mock import AsyncMock, patch, MagicMock
from src.ml_engine.ingestion import handle_suricata_stream
from src.ml_engine.worker_pool import WorkerPool

class MockStreamReader:
    def __init__(self, lines):
        self.lines = lines

    async def __aiter__(self):
        for line in self.lines:
            yield line

@pytest.fixture
def mock_redis():
    mock = AsyncMock()
    mock.setex = AsyncMock()
    mock.get = AsyncMock()
    return mock

@pytest.mark.asyncio
async def test_ingestion_caches_protocols(mock_redis):
    lines = [
        # DNS Answer
        orjson.dumps({
            "event_type": "dns",
            "dns": {
                "type": "answer",
                "rrname": "malicious-c2.com",
                "rdata": "192.168.2.10",
                "answers": [{"rdata": "192.168.2.11"}]
            }
        }),
        # HTTP Log
        orjson.dumps({
            "event_type": "http",
            "src_ip": "10.0.0.5",
            "dest_ip": "10.0.0.10",
            "dest_port": 80,
            "http": {
                "hostname": "c2-server.net",
                "url": "/login.php",
                "http_user_agent": "evil-agent",
                "http_method": "POST"
            }
        }),
        # TLS Log
        orjson.dumps({
            "event_type": "tls",
            "src_ip": "10.0.0.5",
            "dest_ip": "10.0.0.20",
            "dest_port": 443,
            "tls": {
                "subject": "CN=malicious",
                "issuerdn": "CN=fake-ca",
                "serial": "12345",
                "fingerprint": "aabbcc",
                "ja3": {"hash": "abc123hash", "string": "abc123string"}
            }
        })
    ]
    
    reader = MockStreamReader(lines)
    
    writer = AsyncMock()
    # Mock close and wait_closed as async mocks
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    writer.get_extra_info.return_value = ("127.0.0.1", 12345)
    
    with patch("src.ml_engine.ingestion.rc") as mock_rc, \
         patch("src.ml_engine.ingestion.push_to_redis") as mock_push:
        mock_rc.async_redis_client = mock_redis
        
        try:
            await handle_suricata_stream(reader, writer)
        except Exception:
            pass
            
        # Verify setex was called for DNS resolves
        mock_redis.setex.assert_any_call("sentinel_dns_resolve:192.168.2.10", 300, "malicious-c2.com")
        mock_redis.setex.assert_any_call("sentinel_dns_resolve:192.168.2.11", 300, "malicious-c2.com")
        
        # Verify setex was called for HTTP Cache
        mock_redis.setex.assert_any_call(
            "sentinel_http_cache:10.0.0.5:10.0.0.10:80",
            120,
            orjson.dumps({
                "hostname": "c2-server.net",
                "url": "/login.php",
                "user_agent": "evil-agent",
                "method": "POST"
            })
        )
        
        # Verify setex was called for TLS Cache
        mock_redis.setex.assert_any_call(
            "sentinel_tls_cache:10.0.0.5:10.0.0.20:443",
            120,
            orjson.dumps({
                "subject": "CN=malicious",
                "issuer": "CN=fake-ca",
                "serial": "12345",
                "fingerprint": "aabbcc",
                "ja3_hash": "abc123hash",
                "ja3_string": "abc123string"
            })
        )

@pytest.mark.asyncio
async def test_worker_pool_enrichment_correlation(mock_redis):
    pool = WorkerPool(worker_count=1)
    
    alert = {
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.10",
        "dst_port": 80,
        "protocol": "TCP",
        "prediction": "attack",
        "confidence": 90.0,
        "enrichment": {}
    }
    
    async def mock_get(key):
        if key == "sentinel_dns_resolve:10.0.0.10":
            return b"resolved-domain.com"
        elif key == "sentinel_http_cache:10.0.0.5:10.0.0.10:80":
            return orjson.dumps({
                "hostname": "resolved-domain.com",
                "url": "/malware.exe",
                "user_agent": "wget",
                "method": "GET"
            })
        elif key == "sentinel_tls_cache:10.0.0.5:10.0.0.10:80":
            return orjson.dumps({
                "subject": "CN=cert",
                "issuer": "CN=issuer",
                "ja3_hash": "mockedja3hash",
                "ja3_string": "mockedja3string"
            })
        return None
        
    mock_redis.get.side_effect = mock_get
    
    with patch("src.ml_engine.worker_pool.rc") as mock_rc, \
         patch("src.ml_engine.worker_pool.get_cti_client") as mock_cti:
         
        mock_rc.async_redis_client = mock_redis
        
        cti_client = AsyncMock()
        cti_client.get_ip_reputation.return_value = {"reputation_score": 0}
        mock_cti.return_value = cti_client
        
        await pool._enrich_event(alert)
        
        assert alert["enrichment"]["resolved_domain"] == "resolved-domain.com"
        assert alert["enrichment"]["http_details"]["url"] == "/malware.exe"
        assert alert["enrichment"]["tls_details"]["subject"] == "CN=cert"
        assert alert["ja3_hash"] == "mockedja3hash"
