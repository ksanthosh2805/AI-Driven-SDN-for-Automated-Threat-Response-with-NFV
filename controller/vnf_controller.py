from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp

class VNFController(app_manager.RyuApp):
    """
    Advanced SDN Controller that steers traffic through VNFs
    Network Ports:- Port 1: Regular hosts (h1, h2)- Port 2: Regular hosts (h3, h4)  - Port 3: pfSense Firewall- Port 4: Suricata IDPS
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(VNFController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # VNF Port Definitions
        self.vnf_ports = {
            'firewall': 3,
            'ids': 4,
            'normal_hosts': [1, 2]
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Default rule: send unknown to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        self.logger.info("VNF Controller ready on switch %s", datapath.id)
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Add a flow rule to the switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                           actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                  priority=priority, match=match,
                                  instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                  match=match, instructions=inst)
        
        datapath.send_msg(mod)
        self.logger.debug("Flow added: priority=%d", priority)
    
    def steer_to_vnf(self, datapath, in_port, dst_mac, vnf_type):
        """Steer traffic to a specific VNF"""
        parser = datapath.ofproto_parser
        
        if vnf_type not in self.vnf_ports:
            self.logger.error("Unknown VNF type: %s", vnf_type)
            return
        
        out_port = self.vnf_ports[vnf_type]
        
        # Create match rule for this traffic
        match = parser.OFPMatch(
            in_port=in_port,
            eth_dst=dst_mac
        )
        
        # Action: send to VNF
        actions = [parser.OFPActionOutput(out_port)]
        
        # High priority so it's checked first
        self.add_flow(datapath, 100, match, actions)
        
        self.logger.info("Traffic steered to %s VNF (port %d)",
                        vnf_type, out_port)
    
    def detect_suspicious_traffic(self, pkt):
        """
        Simple heuristic detection
        Returns True if traffic looks suspicious
        (This will be replaced by AI model in Phase 3)
        """
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        
        if not ipv4_pkt:
            return False
        
        # Example suspicious patterns:
        
        # 1. Port scanning (connections to many uncommon ports)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            suspicious_ports = [23, 135, 139, 445, 1433, 3389]
            if tcp_pkt.dst_port in suspicious_ports:
                self.logger.warning("Suspicious: Port %d access detected",
                                  tcp_pkt.dst_port)
                return True
        
        # 2. You could add more detection rules here
        
        return False
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        # Learn MAC address location
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        
        self.logger.info("Packet: %s -> %s (in_port=%d)", src, dst, in_port)
        
        # IMPORTANT: Check if traffic is suspicious
        if self.detect_suspicious_traffic(pkt):
            # Route through IDS for inspection
            self.steer_to_vnf(datapath, in_port, dst, 'ids')
            return
        
        # Normal routing logic
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)