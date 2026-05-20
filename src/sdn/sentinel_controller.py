# sentinel_controller.py - Ryu SDN Controller for Sentinel Hybrid IDS/IPS
# Implements L2 Learning Switch + REST API for Flow Mitigation

import json

try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
    from ryu.controller.handler import set_ev_cls
    from ryu.ofproto import ofproto_v1_3
    from ryu.lib.packet import packet
    from ryu.lib.packet import ethernet
    from ryu.lib.packet import ether_types
    from ryu.app.wsgi import WSGIApplication, ControllerBase, route
    from webob import Response
    RYU_AVAILABLE = True
except ImportError:
    # Dummy fallbacks for imports so the module can be imported without Ryu/Webob installed
    class DummyRyuApp:
        pass
    class DummyControllerBase:
        def __init__(self, *args, **kwargs):
            pass
    class DummyResponse:
        def __init__(self, *args, **kwargs):
            pass
    app_manager = type('dummy', (), {'RyuApp': DummyRyuApp})
    ControllerBase = DummyControllerBase
    Response = DummyResponse
    ofp_event = type('dummy', (), {'EventOFPSwitchFeatures': None, 'EventOFPFlowRemoved': None, 'EventOFPPacketIn': None})
    CONFIG_DISPATCHER = None
    MAIN_DISPATCHER = None
    set_ev_cls = lambda *args, **kwargs: lambda f: f
    ofproto_v1_3 = type('dummy', (), {'OFP_VERSION': 0})
    packet = type('dummy', (), {'Packet': None})
    ethernet = type('dummy', (), {'ethernet': None})
    ether_types = type('dummy', (), {'ETH_TYPE_LLDP': 0, 'ETH_TYPE_IP': 0})
    WSGIApplication = None
    route = lambda *args, **kwargs: lambda f: f
    RYU_AVAILABLE = False

# --- REST API CONTROLLER ---

sentinel_instance_name = 'sentinel_api_app'
url = '/sdn'

class SentinelRestController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(SentinelRestController, self).__init__(req, link, data, **config)
        self.sentinel_app = data[sentinel_instance_name]

    @route('sentinel', url + '/block', methods=['POST'])
    def block_ip(self, req, **kwargs):
        try:
            data = json.loads(req.body)
            ip = data.get('ip')
            ttl = data.get('ttl', 0)
            if not ip:
                return Response(status=400, body='Missing IP')
            
            self.sentinel_app.add_block_flow(ip, ttl)
            return Response(status=200, body=f'Blocked {ip}')
        except Exception as e:
            return Response(status=500, body=str(e))

    @route('sentinel', url + '/unblock', methods=['POST'])
    def unblock_ip(self, req, **kwargs):
        try:
            data = json.loads(req.body)
            ip = data.get('ip')
            if not ip:
                return Response(status=400, body='Missing IP')
            
            self.sentinel_app.remove_block_flow(ip)
            return Response(status=200, body=f'Unblocked {ip}')
        except Exception as e:
            return Response(status=500, body=str(e))

    @route('sentinel', url + '/flows', methods=['GET'])
    def list_flows(self, req, **kwargs):
        flows = self.sentinel_app.get_flow_stats()
        return Response(content_type='application/json', body=json.dumps(flows))

# --- RYU APPLICATION ---

class SentinelController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SentinelController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.block_list = set()
        self.datapaths = {} # dpid -> datapath object
        
        # Register REST API
        wsgi = kwargs['wsgi']
        wsgi.register(SentinelRestController, {sentinel_instance_name: self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"Sentinel Controller: Switch {datapath.id} connected and registered.")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        
        # Set SEND_FLOW_REM flag to get notified when flow expires
        flags = ofproto.OFPFF_SEND_FLOW_REM if hard_timeout > 0 or idle_timeout > 0 else 0
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout, flags=flags)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout, flags=flags)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        
        if msg.reason == ofp.OFPRR_HARD_TIMEOUT or msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            # Check if this was a block flow (priority 200)
            if msg.priority == 200 and 'ipv4_src' in msg.match:
                ip = msg.match['ipv4_src']
                self.logger.info(f"Sentinel Controller: Block flow for {ip} expired. Removing from block_list.")
                if ip in self.block_list:
                    self.block_list.remove(ip)

    def add_block_flow(self, ip, ttl=0):
        """Installs a DROP flow for the specified source IP on all connected switches."""
        self.logger.info(f"Sentinel Controller: Pushing DROP flow for {ip} (TTL: {ttl})")
        self.block_list.add(ip)
        
        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            # Match IPv4 source IP (eth_type 0x0800 for IP)
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            # actions=[] means DROP
            # Priority 200 to override normal forwarding flows (priority 1)
            self.add_flow(datapath, 200, match, [], hard_timeout=ttl)
            self.logger.info(f" -> Flow installed on dpid {dpid}")

    def remove_block_flow(self, ip):
        """Removes a DROP flow for the specified source IP from all switches."""
        self.logger.info(f"Sentinel Controller: Removing DROP flow for {ip}")
        if ip in self.block_list:
            self.block_list.remove(ip)
            
        for dpid, datapath in self.datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match
            )
            datapath.send_msg(mod)
            self.logger.info(f" -> Flow deleted from dpid {dpid}")

    def get_flow_stats(self):
        """Returns a list of currently blocked IPs and basic stats."""
        return {
            "blocked_ips": list(self.block_list),
            "status": "active"
        }

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # 1. Check Block List (Source IP)
        from ryu.lib.packet import ipv4
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            src_ip = pkt_ipv4.src
            if src_ip in self.block_list:
                self.logger.info(f"Packet from blocked IP {src_ip} dropped.")
                # Install a hard drop flow to avoid future PacketIn for this IP
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)
                self.add_flow(datapath, 100, match, [], hard_timeout=300)
                return

        # 2. Standard L2 Learning
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # 3. Install flow to avoid PacketIn next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoids sending both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
