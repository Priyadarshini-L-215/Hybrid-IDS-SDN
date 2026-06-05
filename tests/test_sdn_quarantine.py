# test_sdn_quarantine.py - Unit tests for Ryu SDN VLAN Quarantine steering
import pytest
from unittest.mock import MagicMock, patch
import json
import httpx
import respx

from sdn.sentinel_controller import SentinelController, SentinelRestController
from ml_engine.sdn_client import SDNClient

class DummyRequest:
    def __init__(self, body):
        self.body = body

def test_rest_controller_quarantine_endpoint():
    mock_app = MagicMock()
    req = DummyRequest(json.dumps({"ip": "10.0.0.5", "vlan_id": 99, "ttl": 120}).encode())
    controller = SentinelRestController(req, link=None, data={'sentinel_api_app': mock_app})
    
    resp = controller.quarantine_ip(req)
    assert resp.status == 200
    mock_app.add_quarantine_flow.assert_called_with("10.0.0.5", 99, 120)

def test_controller_quarantine_flow_mapping():
    mock_wsgi = MagicMock()
    app = SentinelController(wsgi=mock_wsgi)
    
    assert len(app.quarantine_list) == 0
    
    # Mock Switch Datapath
    mock_datapath = MagicMock()
    mock_datapath.ofproto = MagicMock()
    mock_datapath.ofproto_parser = MagicMock()
    app.datapaths = {1: mock_datapath}
    
    app.add_quarantine_flow("10.0.0.5", 100, ttl=300)
    
    assert app.quarantine_list["10.0.0.5"] == 100
    assert mock_datapath.send_msg.called
    
    # Remove block/quarantine flow
    app.remove_block_flow("10.0.0.5")
    assert "10.0.0.5" not in app.quarantine_list

@pytest.mark.asyncio
@respx.mock
async def test_sdn_client_quarantine_success():
    client = SDNClient(controller_url="http://localhost:8080")
    respx.post("http://localhost:8080/sdn/quarantine").mock(
        return_value=httpx.Response(200, json={"status": "success"})
    )
    res = await client.quarantine_host("10.0.0.5", vlan_id=100)
    assert res is True

@pytest.mark.asyncio
@respx.mock
async def test_sdn_client_quarantine_default_vlan():
    client = SDNClient(controller_url="http://localhost:8080")
    respx.post("http://localhost:8080/sdn/quarantine").mock(
        return_value=httpx.Response(200, json={"status": "success"})
    )
    res = await client.quarantine_host("10.0.0.5")
    assert res is True
