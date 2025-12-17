#!/usr/bin/env python3
"""
Micro-Segmentation Controller with VLAN Isolation
Dynamically assigns hosts to security zones based on AI threat assessment
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, vlan, ipv4
from ryu.lib import hub
import requests
from collections import defaultdict
import time
import json
import os


class MicroSegmentationController(app_manager.RyuApp):
    """
    Advanced SDN controller with dynamic VLAN-based micro-segmentation.

    Security Zones (VLANs):
      - VLAN 100: Trusted Zone (benign hosts, full access)
      - VLAN 200: Monitored Zone (suspicious, limited access)
      - VLAN 999: Quarantine Zone (malicious, isolated)
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MicroSegmentationController, self).__init__(*args, **kwargs)

        # MAC to port learning
        self.mac_to_port = {}

        # Host security zones (default: trusted)
        self.host_zones = defaultdict(lambda: 'trusted')

        # VLAN definitions
        self.vlans = {
            'trusted': 100,
            'monitored': 200,
            'quarantine': 999
        }

        # Host IP <-> MAC mapping
        self.ip_to_mac = {}
        self.mac_to_ip = {}

        # Flow statistics
        self.flow_stats = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'start_time': time.time(),
            'last_check': 0
        })

        # AI API endpoint
        self.ai_api_url = 'http://localhost:5000/predict'

        # Monitoring thread
        self.monitor_thread = hub.spawn(self._monitor_and_segregate)

        self.logger.info("=" * 70)
        self.logger.info("MICRO-SEGMENTATION CONTROLLER INITIALIZED")
        self.logger.info("Security Zones:")
        for zone, vlan_id in self.vlans.items():
            self.logger.info("  - %s: VLAN %d", zone.upper(), vlan_id)
        self.logger.info("=" * 70)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Initialize switch with default flows"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Default table-miss flow
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Install inter-VLAN blocking rules (prevent cross-VLAN traffic)
        self.install_vlan_isolation_rules(datapath)

        self.logger.info("Switch %s: VLAN isolation rules installed", datapath.id)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None,
                 idle_timeout=0, hard_timeout=0):
        """Add flow to switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout
            )

        datapath.send_msg(mod)

    def install_vlan_isolation_rules(self, datapath):
        """Install rules to isolate VLANs from each other"""
        parser = datapath.ofproto_parser

        # Rule 1: Drop traffic from quarantine VLAN to any other VLAN
        match = parser.OFPMatch(vlan_vid=self.vlans['quarantine'])
        actions = []  # Empty actions = DROP
        self.add_flow(datapath, 100, match, actions)

        self.logger.info("Quarantine VLAN isolated")
        # Rules for trusted/monitored are implemented via VLAN assignment.

    def assign_host_to_vlan(self, datapath, mac_addr, vlan_id, out_port):
        """Assign specific host to VLAN by installing tagging rule"""
        parser = datapath.ofproto_parser

        # Match on MAC, add VLAN tag, output to port
        match = parser.OFPMatch(eth_src=mac_addr)

        # Actions: Push VLAN tag, set VLAN ID, output
        actions = [
            parser.OFPActionPushVlan(0x8100),  # Push VLAN tag
            parser.OFPActionSetField(vlan_vid=vlan_id | 0x1000),  # Set VLAN ID
            parser.OFPActionOutput(out_port)
        ]

        self.add_flow(datapath, 10, match, actions)

        self.logger.info("Host %s assigned to VLAN %d", mac_addr, vlan_id)

    def move_host_to_quarantine(self, datapath, ip_addr, mac_addr):
        """Move host to quarantine VLAN"""
        if ip_addr in self.host_zones:
            old_zone = self.host_zones[ip_addr]
            self.host_zones[ip_addr] = 'quarantine'
            self.logger.warning("QUARANTINE: %s moved from %s to quarantine",
                                ip_addr, old_zone)
        else:
            self.host_zones[ip_addr] = 'quarantine'
            self.logger.warning("QUARANTINE: %s (new host)", ip_addr)

        # Install blocking rule for this host
        self.block_host_traffic(datapath, ip_addr, mac_addr)

    def block_host_traffic(self, datapath, ip_addr, mac_addr):
        """Install flow rules to block all traffic from host"""
        parser = datapath.ofproto_parser

        # Block by source MAC
        match = parser.OFPMatch(eth_src=mac_addr)
        actions = []  # DROP
        self.add_flow(datapath, 200, match, actions)  # High priority

        # Block by source IP
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_addr)
        actions = []  # DROP
        self.add_flow(datapath, 200, match, actions)

        self.logger.info("All traffic from %s blocked", ip_addr)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle incoming packets with VLAN awareness"""
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

        # Learn MAC to port mapping
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Extract IP addresses
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self.ip_to_mac[ip_pkt.src] = src
            self.mac_to_ip[src] = ip_pkt.src

            # Track flow stats
            flow_key = f"{ip_pkt.src}_{ip_pkt.dst}"
            self.flow_stats[flow_key]['packets'] += 1
            self.flow_stats[flow_key]['bytes'] += len(msg.data)

        # Check if host is in quarantine
        if src in self.mac_to_ip:
            src_ip = self.mac_to_ip[src]
            if self.host_zones.get(src_ip) == 'quarantine':
                self.logger.debug("Dropped packet from quarantined host %s",
                                  src_ip)
                return  # Drop packet

        # Normal forwarding
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions, idle_timeout=30)

        # Send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    def _save_stats_snapshot(self):
        """Write a JSON snapshot for the dashboard"""
        data = {
            "host_zones": dict(self.host_zones),
            "flow_stats_count": len(self.flow_stats),
        }
        try:
            os.makedirs("/tmp/ai_sdn", exist_ok=True)
            with open("/tmp/ai_sdn/controller_stats.json", "w") as f:
                json.dump(data, f)
        except Exception as e:
            self.logger.debug("Failed to write stats file: %s", e)

    def _monitor_and_segregate(self):
        """Background thread: monitor flows and apply segregation"""
        self.logger.info("Micro-segmentation monitor started")

        while True:
            hub.sleep(15)  # Check every 15 seconds

            current_time = time.time()

            for flow_key, stats in list(self.flow_stats.items()):
                # Skip if checked recently
                if current_time - stats['last_check'] < 30:
                    continue

                # Parse flow key
                parts = flow_key.split('_')
                if len(parts) != 2:
                    continue

                src_ip, dst_ip = parts

                # Check with AI
                duration = current_time - stats['start_time']

                flow_data = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': 0,
                    'dst_port': 0,
                    'duration_sec': duration,
                    'packets_total': stats['packets'],
                    'bytes_total': stats['bytes'],
                    'packets_per_sec': stats['packets'] / max(duration, 1),
                    'bytes_per_sec': stats['bytes'] / max(duration, 1),
                    'avg_packet_size': stats['bytes'] / max(
                        stats['packets'], 1
                    )
                }

                prediction = self.check_with_ai(flow_data)

                # Heuristic override for very heavy flows
                if (flow_data['packets_total'] > 1000 or
                        flow_data['packets_per_sec'] > 500):
                    self.logger.warning(
                        "Heuristic triggered ATTACK for %s -> %s "
                        "(packets=%d, pps=%.1f)",
                        src_ip, dst_ip,
                        flow_data['packets_total'],
                        flow_data['packets_per_sec']
                    )
                    prediction = 'ATTACK'

                if prediction == 'ATTACK':
                    self.logger.warning("Threat detected: %s -> %s",
                                        src_ip, dst_ip)

                    # Get datapath (assuming single switch for simplicity)
                    if self.mac_to_port:
                        dpid = list(self.mac_to_port.keys())[0]
                        datapath = self.get_datapath(dpid)

                        if datapath and src_ip in self.ip_to_mac:
                            mac = self.ip_to_mac[src_ip]
                            self.move_host_to_quarantine(datapath, src_ip, mac)

                stats['last_check'] = current_time

            # Update snapshot for dashboard each cycle
            self._save_stats_snapshot()

    def check_with_ai(self, flow_data):
        """Query AI API for threat assessment"""
        try:
            response = requests.post(
                self.ai_api_url,
                json=flow_data,
                timeout=2
            )

            if response.status_code == 200:
                result = response.json()
                return result.get('prediction', 'BENIGN')
        except Exception as e:
            self.logger.debug("AI API error: %s", e)

        return 'BENIGN'

    def get_datapath(self, dpid):
        """Get datapath object by ID"""
        # Simplified – in production you would track actual datapath objects
        for dp in self.get_datapaths():
            if getattr(dp, 'id', None) == dpid:
                return dp
        return None

    def get_datapaths(self):
        """Get all connected datapaths (placeholder)"""
        # Ryu normally manages datapath list internally; for this example
        # we treat keys of mac_to_port as existing datapaths.
        return []

    def get_security_status(self):
        """Get current security zone status"""
        status = {
            'trusted': [],
            'monitored': [],
            'quarantine': []
        }

        for ip, zone in self.host_zones.items():
            status[zone].append(ip)

        return status


def main():
    from ryu.cmd import manager
    import sys

    sys.argv.append('--ofp-tcp-listen-port')
    sys.argv.append('6633')
    sys.argv.append(__file__)

    manager.main()


if __name__ == '__main__':
    main()
