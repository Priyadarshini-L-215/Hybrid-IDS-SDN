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
        def __init__(self, *args, **kwargs):
            import logging
            self.logger = logging.getLogger("DummyRyuApp")
    class DummyControllerBase:
        def __init__(self, *args, **kwargs):
            pass
    class DummyResponse:
        def __init__(self, *args, **kwargs):
            self.status = kwargs.get('status', 200)
            self.body = kwargs.get('body', '')
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

    @route('sentinel', url + '/block_shape', methods=['POST'])
    def block_shape(self, req, **kwargs):
        try:
            data = json.loads(req.body)
            ip = data.get('ip')
            protocol = data.get('protocol', 'TCP')
            dport = data.get('dport')
            ttl = data.get('ttl', 300)
            if not ip or not dport:
                return Response(status=400, body='Missing ip or dport parameter')
            
            self.sentinel_app.add_block_shape_flow(ip, protocol, int(dport), ttl)
            return Response(status=200, body=f'Blocked shape: {ip} - {protocol} - {dport}')
        except Exception as e:
            return Response(status=500, body=str(e))

    @route('sentinel', url + '/redirect', methods=['POST'])
    def redirect_ip(self, req, **kwargs):
        try:
            data = json.loads(req.body)
            ip = data.get('ip')
            honeypot_ip = data.get('honeypot_ip')
            ttl = data.get('ttl', 300)
            if not ip or not honeypot_ip:
                return Response(status=400, body='Missing ip or honeypot_ip parameter')
            
            self.sentinel_app.add_redirect_flow(ip, honeypot_ip, ttl)
            return Response(status=200, body=f'Redirected {ip} to honeypot {honeypot_ip}')
        except Exception as e:
            return Response(status=500, body=str(e))

    @route('sentinel', url + '/quarantine', methods=['POST'])
    def quarantine_ip(self, req, **kwargs):
        try:
            data = json.loads(req.body)
            ip = data.get('ip')
            vlan_id = data.get('vlan_id')
            ttl = data.get('ttl', 300)
            if not ip or vlan_id is None:
                return Response(status=400, body='Missing ip or vlan_id parameter')
            
            self.sentinel_app.add_quarantine_flow(ip, int(vlan_id), ttl)
            return Response(status=200, body=f'Quarantined {ip} into VLAN {vlan_id}')
        except Exception as e:
            return Response(status=500, body=str(e))

# --- RYU APPLICATION ---

class SentinelController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SentinelController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.block_list = set()
        self.quarantine_list = {} # ip -> vlan_id
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
                if ip in self.quarantine_list:
                    self.logger.info(f"Sentinel Controller: Quarantine flow for {ip} expired. Removing from quarantine_list.")
                    self.quarantine_list.pop(ip, None)

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
        """Removes a DROP or QUARANTINE flow for the specified source IP from all switches."""
        self.logger.info(f"Sentinel Controller: Removing block/quarantine flows for {ip}")
        if ip in self.block_list:
            self.block_list.remove(ip)
        if ip in self.quarantine_list:
            self.quarantine_list.pop(ip, None)
            
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
            "quarantined_ips": list(self.quarantine_list.keys()),
            "status": "active"
        }

    def add_quarantine_flow(self, ip, vlan_id, ttl=300):
        """Installs a flow that pushes a VLAN tag to isolate packets matching source IP."""
        self.logger.info(f"Sentinel Controller: Pushing QUARANTINE flow for {ip} (VLAN: {vlan_id}, TTL: {ttl})")
        self.quarantine_list[ip] = vlan_id

        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto

            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)

            # OpenFlow 1.3 actions to push VLAN tag
            # 0x8100 is ETH_TYPE_8021Q
            actions = [
                parser.OFPActionPushVlan(0x8100),
                # Set VLAN ID (vlan_id) with the OFPVID_PRESENT bit (0x1000 / 4096)
                parser.OFPActionSetField(vlan_vid=vlan_id | 0x1000),
                parser.OFPActionOutput(ofproto.OFPP_FLOOD)
            ]

            # Priority 200 to override normal forwarding flows
            self.add_flow(datapath, 200, match, actions, hard_timeout=ttl)
            self.logger.info(f" -> Quarantine VLAN flow installed on dpid {dpid}")

    def add_block_shape_flow(self, ip, protocol, dport, ttl=300):
        """Installs a DROP flow rule for a specific protocol shape (src IP, protocol, dst port)."""
        self.logger.info(f"Sentinel Controller: Pushing DROP shape flow for {ip} - {protocol} - {dport} (TTL: {ttl})")
        
        proto_num = 6 if protocol.upper() == 'TCP' else (17 if protocol.upper() == 'UDP' else 6)
        
        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            if proto_num == 6:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip, ip_proto=proto_num, tcp_dst=dport)
            else:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip, ip_proto=proto_num, udp_dst=dport)
            # actions=[] means DROP
            self.add_flow(datapath, 200, match, [], hard_timeout=ttl)
            self.logger.info(f" -> Flow shape installed on dpid {dpid}")

    def add_redirect_flow(self, ip, honeypot_ip, ttl=300):
        """Installs a DNAT redirection flow rule to redirect traffic matching source IP to the honeypot."""
        self.logger.info(f"Sentinel Controller: Pushing REDIRECT flow for {ip} to {honeypot_ip} (TTL: {ttl})")
        
        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            actions = [
                parser.OFPActionSetField(ipv4_dst=honeypot_ip),
                parser.OFPActionOutput(ofproto.OFPP_FLOOD)
            ]
            self.add_flow(datapath, 200, match, actions, hard_timeout=ttl)
            self.logger.info(f" -> Redirect flow installed on dpid {dpid}")

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

            if src_ip in self.quarantine_list:
                vlan_id = self.quarantine_list[src_ip]
                self.logger.info(f"Packet from quarantined IP {src_ip} tagged with VLAN {vlan_id}.")
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)
                actions = [
                    parser.OFPActionPushVlan(0x8100),
                    parser.OFPActionSetField(vlan_vid=vlan_id | 0x1000),
                    parser.OFPActionOutput(ofproto.OFPP_FLOOD)
                ]
                self.add_flow(datapath, 100, match, actions, hard_timeout=300)
                
                # Send packet out
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
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
