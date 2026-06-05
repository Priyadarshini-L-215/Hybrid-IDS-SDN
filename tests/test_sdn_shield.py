import sys
import os
from unittest.mock import MagicMock, patch

# Create dummy mock modules for ryu before importing sentinel_controller
class DummyModule:
    pass

ryu = DummyModule()
ryu.base = DummyModule()
ryu.base.app_manager = DummyModule()
class MockRyuApp:
    def __init__(self, *args, **kwargs):
        self.logger = MagicMock()

ryu.base.app_manager.RyuApp = MockRyuApp

ryu.controller = DummyModule()
ryu.controller.ofp_event = DummyModule()
ryu.controller.ofp_event.EventOFPSwitchFeatures = MagicMock
ryu.controller.ofp_event.EventOFPFlowRemoved = MagicMock
ryu.controller.ofp_event.EventOFPPacketIn = MagicMock

ryu.controller.handler = DummyModule()
ryu.controller.handler.CONFIG_DISPATCHER = 1
ryu.controller.handler.MAIN_DISPATCHER = 2
ryu.controller.handler.set_ev_cls = lambda *args, **kwargs: lambda f: f

ryu.ofproto = DummyModule()
ryu.ofproto.ofproto_v1_3 = DummyModule()
ryu.ofproto.ofproto_v1_3.OFP_VERSION = 0x04

ryu.lib = DummyModule()
ryu.lib.packet = DummyModule()
ryu.lib.packet.packet = DummyModule()
ryu.lib.packet.packet.Packet = MagicMock()
ryu.lib.packet.ipv4 = DummyModule()
ryu.lib.packet.ipv4.ipv4 = MagicMock()
ryu.lib.packet.ethernet = DummyModule()
ryu.lib.packet.ethernet.ethernet = MagicMock()
ryu.lib.packet.ether_types = DummyModule()
ryu.lib.packet.ether_types.ETH_TYPE_LLDP = 0x88cc
ryu.lib.packet.ether_types.ETH_TYPE_IP = 0x0800

ryu.app = DummyModule()
ryu.app.wsgi = DummyModule()
ryu.app.wsgi.WSGIApplication = MagicMock()
ryu.app.wsgi.ControllerBase = MagicMock
ryu.app.wsgi.route = lambda *args, **kwargs: lambda f: f

sys.modules['ryu'] = ryu
sys.modules['ryu.base'] = ryu.base
sys.modules['ryu.base.app_manager'] = ryu.base.app_manager
sys.modules['ryu.controller'] = ryu.controller
sys.modules['ryu.controller.ofp_event'] = ryu.controller.ofp_event
sys.modules['ryu.controller.handler'] = ryu.controller.handler
sys.modules['ryu.ofproto'] = ryu.ofproto
sys.modules['ryu.ofproto.ofproto_v1_3'] = ryu.ofproto.ofproto_v1_3
sys.modules['ryu.lib'] = ryu.lib
sys.modules['ryu.lib.packet'] = ryu.lib.packet
sys.modules['ryu.lib.packet.packet'] = ryu.lib.packet.packet
sys.modules['ryu.lib.packet.ipv4'] = ryu.lib.packet.ipv4
sys.modules['ryu.lib.packet.ethernet'] = ryu.lib.packet.ethernet
sys.modules['ryu.lib.packet.ether_types'] = ryu.lib.packet.ether_types
sys.modules['ryu.app'] = ryu.app
sys.modules['ryu.app.wsgi'] = ryu.app.wsgi

# Add src to PYTHONPATH
sys.path.insert(0, os.path.abspath("src"))

import pytest
import sdn.sentinel_controller
from sdn.sentinel_controller import SentinelController

# Overwrite fallback packet, ethernet and ether_types if they were set to Dummy values due to previous import caching
sdn.sentinel_controller.packet = ryu.lib.packet.packet
sdn.sentinel_controller.ethernet = ryu.lib.packet.ethernet
sdn.sentinel_controller.ether_types = ryu.lib.packet.ether_types

class MockDatapath:
    def __init__(self):
        self.id = 1
        self.ofproto = MagicMock()
        self.ofproto.OFP_NO_BUFFER = -1
        self.ofproto.OFPP_FLOOD = 0xfffffffc
        self.ofproto.OFPP_CONTROLLER = 0xfffffffd
        self.ofproto.OFPCML_NO_BUFFER = 0xffff
        self.ofproto_parser = MagicMock()
        self.send_msg = MagicMock()

class MockMessage:
    def __init__(self, in_port=1, data=b"dummy"):
        self.datapath = MockDatapath()
        self.match = {'in_port': in_port}
        self.data = data
        self.buffer_id = -1

class MockEvent:
    def __init__(self, in_port=1):
        self.msg = MockMessage(in_port=in_port)

@pytest.fixture
def controller():
    mock_wsgi = MagicMock()
    app = SentinelController(wsgi=mock_wsgi)
    
    # Register a mock datapath manually to simulate a connected switch
    dp = MockDatapath()
    app.datapaths[dp.id] = dp
    yield app

def test_sentinel_controller_init(controller):
    assert hasattr(controller, 'packet_in_rates')
    assert controller.RATE_THRESHOLD == 100
    assert len(controller.packet_in_rates) == 0

@patch('requests.post')
def test_rate_limiting_triggers_drop_flow(mock_post, controller):
    # Setup mock response for requests
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_post.return_value = mock_response

    # Prepare packets
    ev = MockEvent(in_port=3)
    datapath = ev.msg.datapath
    parser = datapath.ofproto_parser

    # Send 100 Packet-Ins (this is exactly at or below threshold, shouldn't trigger block)
    with patch('ryu.lib.packet.packet.Packet') as mock_packet_class:
        mock_eth = MagicMock()
        mock_eth.ethertype = 0x0800 # Not LLDP
        mock_eth.dst = '00:11:22:33:44:55'
        mock_eth.src = 'aa:bb:cc:dd:ee:ff'
        mock_packet_class.return_value.get_protocols.return_value = [mock_eth]
        mock_packet_class.return_value.get_protocol.return_value = None
        
        for _ in range(100):
            controller._packet_in_handler(ev)

    # Verify that no drop flows have been sent yet and request.post hasn't been called
    assert not mock_post.called
    assert not parser.OFPFlowMod.called

    # Send the 101st Packet-In (triggers the rate limit threshold)
    with patch('ryu.lib.packet.packet.Packet') as mock_packet_class:
        mock_eth = MagicMock()
        mock_eth.ethertype = 0x0800
        mock_eth.dst = '00:11:22:33:44:55'
        mock_eth.src = 'aa:bb:cc:dd:ee:ff'
        mock_packet_class.return_value.get_protocols.return_value = [mock_eth]
        mock_packet_class.return_value.get_protocol.return_value = None
        
        controller._packet_in_handler(ev)

    # 1. Verify drop flow was injected with priority 300 and empty actions
    assert parser.OFPFlowMod.called
    flow_mod_args = parser.OFPFlowMod.call_args[1]
    assert flow_mod_args['priority'] == 300
    assert flow_mod_args['instructions'] != []
    assert flow_mod_args['hard_timeout'] == 60

    # 2. Verify notify HTTP client called POST to correct endpoint with sentinel key
    mock_post.assert_called_once()
    post_url = mock_post.call_args[0][0]
    post_headers = mock_post.call_args[1]['headers']
    post_json = mock_post.call_args[1]['json']
    
    assert "/api/forensics/alert/external" in post_url
    assert "X-Sentinel-Key" in post_headers
    assert post_json['alert_sig'] == "SDN Control Plane Saturation Flood"
    assert post_json['prediction'] == "attack"
    assert post_json['severity'] == 3
    assert post_json['is_mitigated'] == 1
