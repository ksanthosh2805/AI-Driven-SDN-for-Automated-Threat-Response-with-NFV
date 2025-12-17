#!/usr/bin/env python3
"""
AI-Integrated SDN Controller
Combines Ryu SDN controller with AI-based threat detection.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
from ryu.lib import hub

import requests
import time
from collections import defaultdict
from datetime import datetime


class AISDNController(app_manager.RyuApp):
    """
    Advanced SDN Controller with AI-driven threat detection.

    Features:
    - Real-time flow monitoring
    - AI-based anomaly detection via REST API
    - Automated threat response (blocking / quarantine)
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AISDNController, self).__init__(*args, **kwargs)

        # MAC learning table: {dpid: {mac: port}}
        self.mac_to_port = {}

        # Flow statistics: keyed by "srcip_dstip_dstport"
        self.flow_stats = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'first_seen': time.time(),
            'last_seen': time.time(),
            'duration': 0
        })

        # Blocked hosts (by src_ip)
        self.blocked_hosts = set()

        # AI API configuration (HTTP only, local)
        self.ai_api_url = 'http://127.0.0.1:5000/predict'
        self.ai_check_interval = 10  # seconds

        # VNF port mapping (if you later want to steer flows)
        self.vnf_ports = {
            'firewall': 3,
            'ids': 4
        }

        # Micro-segmentation VLANs (not used yet, but kept for report)
        self.vlans = {
            'trusted': 100,
            'untrusted': 200,
            'quarantine': 999
        }

        # Threat log
        self.threat_log = []

        # Start background monitoring thread
        self.monitor_thread = hub.spawn(self._monitor_flows)

        self.logger.info("=" * 70)
        self.logger.info("AI-SDN CONTROLLER INITIALIZED")
        self.logger.info("AI API URL: %s", self.ai_api_url)
        self.logger.info("=" * 70)

    # ------------------------------------------------------------------
    # Switch setup and basic learning switch behaviour
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install table-miss flow when switch connects."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.logger.info("Switch %s connected", datapath.id)

    def add_flow(self, datapath, priority, match, actions,
                 buffer_id=None, idle_timeout=0, hard_timeout=0):
        """Install flow rule in switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    buffer_id=buffer_id,
                                    priority=priority,
                                    match=match,
                                    instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority,
                                    match=match,
                                    instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def delete_flow(self, datapath, match):
        """Remove flow rule from switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle incoming packets (learning switch + stats update)."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP packets used by topology discovery
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # MAC learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Extract flow info for AI
        flow_info = self.extract_flow_info(pkt, in_port)

        if flow_info:
            flow_key = f"{flow_info['src_ip']}_{flow_info['dst_ip']}_{flow_info['dst_port']}"
            self.update_flow_stats(flow_key)

            # If source is already blocked, drop silently
            if flow_info['src_ip'] in self.blocked_hosts:
                self.logger.warning("Dropping packet from blocked host %s",
                                    flow_info['src_ip'])
                return

        # Normal learning-switch forwarding
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow to reduce future PacketIn
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions,
                          msg.buffer_id, idle_timeout=30)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                return

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    # ------------------------------------------------------------------
    # Flow statistics and AI integration
    # ------------------------------------------------------------------

    def extract_flow_info(self, pkt, in_port):
        """Extract L3/L4 info from a packet for stats and AI."""
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return None

        flow_info = {
            'src_ip': ip_pkt.src,
            'dst_ip': ip_pkt.dst,
            'protocol': ip_pkt.proto,
            'src_port': 0,
            'dst_port': 0,
            'in_port': in_port
        }

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if tcp_pkt:
            flow_info['src_port'] = tcp_pkt.src_port
            flow_info['dst_port'] = tcp_pkt.dst_port
            flow_info['protocol_name'] = 'TCP'
        elif udp_pkt:
            flow_info['src_port'] = udp_pkt.src_port
            flow_info['dst_port'] = udp_pkt.dst_port
            flow_info['protocol_name'] = 'UDP'
        else:
            flow_info['protocol_name'] = 'OTHER'

        return flow_info

    def update_flow_stats(self, flow_key):
        """Increment simple statistics for a flow."""
        stats = self.flow_stats[flow_key]
        stats['packets'] += 1
        stats['bytes'] += 1500  # approximate
        now = time.time()
        stats['last_seen'] = now
        stats['duration'] = now - stats['first_seen']

    def _monitor_flows(self):
        """Background thread: periodically send flows to AI API."""
        self.logger.info("Flow monitoring thread started")

        while True:
            hub.sleep(self.ai_check_interval)

            flows_to_check = []

            for flow_key, stats in list(self.flow_stats.items()):
                parts = flow_key.split('_')
                if len(parts) < 3:
                    continue

                src_ip, dst_ip, dst_port = parts[0], parts[1], parts[2]

                # Use safe values and compute engineered features
                duration = max(stats['duration'], 1.0)
                packets = max(stats['packets'], 1)
                bytes_ = stats['bytes']

                flow_data = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': 0,  # not stored in key
                    'dst_port': int(dst_port) if dst_port.isdigit() else 0,
                    'duration_sec': duration,
                    'packets_total': packets,
                    'bytes_total': bytes_,
                    'packets_per_sec': packets / duration,
                    'bytes_per_sec': bytes_ / duration,
                    'avg_packet_size': bytes_ / packets,
                    'bytes_per_packet': bytes_ / packets,
                    'traffic_intensity': (packets * bytes_) / duration,
                    'is_common_port': 1 if int(dst_port) in
                                      [80, 443, 22, 21, 25, 53] else 0
                }

                flows_to_check.append((flow_key, flow_data))

            # Log stats and send to AI
            for flow_key, flow_data in flows_to_check:
                stats = self.flow_stats.get(flow_key, {})
                self.logger.info(
                    "DEBUG flow %s stats: packets=%d bytes=%d duration=%.2f",
                    flow_key,
                    stats.get('packets', 0),
                    stats.get('bytes', 0),
                    stats.get('duration', 0.0)
                )
                self.check_flow_with_ai(flow_key, flow_data)

            # Cleanup old flows (> 5 minutes inactive)
            now = time.time()
            old_keys = [k for k, v in self.flow_stats.items()
                        if now - v['last_seen'] > 300]
            for k in old_keys:
                del self.flow_stats[k]

    def check_flow_with_ai(self, flow_key, flow_data):
        """Call the external AI REST API to classify a flow."""
        try:
            # Simple heuristic: if packets_per_sec or bytes_per_sec very high,
            # treat it as an obvious DoS attack
            if (flow_data['packets_per_sec'] > 50 or
                    flow_data['bytes_per_sec'] > 50_000):
                self.logger.warning("Heuristic DoS detection on flow %s",
                                    flow_key)
                self.handle_threat(flow_data, confidence=1.0)
                return

            resp = requests.post(self.ai_api_url, json=flow_data, timeout=2)
            if resp.status_code != 200:
                self.logger.debug("AI API returned status %s",
                                  resp.status_code)
                return

            result = resp.json()
            if result.get('prediction') == 'ATTACK':
                confidence = float(result.get('confidence', 0.0))
                self.logger.warning("THREAT DETECTED on flow %s", flow_key)
                self.logger.warning(" Source: %s, Confidence: %.2f",
                                    flow_data['src_ip'], confidence)
                self.handle_threat(flow_data, confidence)

        except Exception as e:
            # Keep controller alive even if AI API fails
            self.logger.debug("AI API error: %s", e)

    def handle_threat(self, flow_data, confidence):
        """Block malicious source and record the event."""
        src_ip = flow_data['src_ip']

        record = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': flow_data['dst_ip'],
            'confidence': confidence,
            'action': 'blocked'
        }
        self.threat_log.append(record)

        self.blocked_hosts.add(src_ip)
        self.logger.warning("AUTOMATED RESPONSE: blocked %s", src_ip)

    def get_threat_stats(self):
        """Return simple stats used in report/monitoring."""
        return {
            'total_threats': len(self.threat_log),
            'blocked_hosts': list(self.blocked_hosts),
            'recent_threats': self.threat_log[-10:]
        }
