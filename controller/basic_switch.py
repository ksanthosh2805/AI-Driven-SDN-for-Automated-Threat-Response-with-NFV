from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types

class BasicSwitch(app_manager.RyuApp):
    """
    A simple learning switch controller
    
    This controller learns MAC addresses and forwards frames accordingly
    It's the "brain" that tells switches where to send packets
    """
    
    # Support OpenFlow 1.3
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(BasicSwitch, self).__init__(*args, **kwargs)
        # Dictionary to store MAC addresses and their ports
        # Format: {switch_id: {mac_address: port_number}}
        self.mac_to_port = {}
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        This runs when a switch connects to the controller
        It installs a default rule: send unknown packets to controller
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Create a rule that matches everything
        match = parser.OFPMatch()
        
        # Action: send packets to controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        
        # Install the rule
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch %s connected", datapath.id)
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """
        Install a flow rule in the switch
        Priority: Higher number = more important
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Create instruction: apply these actions
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                           actions)]
        
        # Create the flow modification message
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                  priority=priority, match=match,
                                  instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                  match=match, instructions=inst)
        
        # Send to switch
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        This runs when the switch sends a packet to the controller
        The controller decides what to do with it
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Extract information from the incoming message
        in_port = msg.match['in_port']
        
        # Parse the packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # Ignore LLDP packets (network discovery)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        # Extract source and destination MAC addresses
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        # Remember which port the source MAC came from
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        
        self.logger.info("Packet from %s to %s (learned %s on port %s)",
                        src, dst, src, in_port)
        
        # Decide output port
        if dst in self.mac_to_port[dpid]:
            # We know where this MAC is - send there
            out_port = self.mac_to_port[dpid][dst]
        else:
            # We don't know - flood to all ports except incoming
            out_port = ofproto.OFPP_FLOOD
        
        # Create action
        actions = [parser.OFPActionOutput(out_port)]
        
        # If we know the destination, install a flow rule for future packets
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)
        
        # Send this packet out now
        data = None if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                 in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)