"""
Ryu SDN Controller IDS/IPS Module
Makine Ogrenmesi Tabanli Gercek Zamanli Saldiri Tespit ve Onleme Sistemi

Bu modul, Ryu SDN controller uzerinde calisarak:
1. Ag trafikini analiz eder
2. ML servisine sorgu gondererek saldiri tespiti yapar
3. Zararli trafigi engeller veya karantinaya alir
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from ryu.lib.packet import ether_types
from ryu.lib import hub
from ryu.app.ofctl.api import get_datapath

import requests
import json
import time
import logging
from collections import defaultdict
from datetime import datetime

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.feature_extractor import FeatureExtractor

# Configuration
ML_SERVICE_URL = "http://127.0.0.1:5000"
STATS_INTERVAL = 5  # seconds
FLOW_TIMEOUT_IDLE = 30
FLOW_TIMEOUT_HARD = 300
CONFIDENCE_THRESHOLD = 0.85
QUARANTINE_THRESHOLD = 0.70

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('SDN_IDS')


class SDNIntrusionDetectionSystem(app_manager.RyuApp):
    """
    SDN-based Intrusion Detection and Prevention System

    Integrates with ML service to detect and mitigate DDoS attacks
    in real-time using OpenFlow protocol.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNIntrusionDetectionSystem, self).__init__(*args, **kwargs)

        # MAC address table for learning switch functionality
        self.mac_to_port = {}

        # Datapath management
        self.datapaths = {}

        # Feature extractor for ML
        self.feature_extractor = FeatureExtractor()

        # Statistics tracking
        self.flow_stats = defaultdict(dict)
        self.port_stats = defaultdict(dict)

        # Detection statistics
        self.detection_stats = {
            'total_packets': 0,
            'benign_packets': 0,
            'attack_packets': 0,
            'blocked_flows': 0,
            'quarantined_flows': 0
        }

        # Blocked and quarantined IPs
        self.blocked_ips = set()
        self.quarantined_ips = {}  # IP -> expiry_time

        # ML service status
        self.ml_service_available = False

        # Start background threads
        self.monitor_thread = hub.spawn(self._monitor_loop)
        self.cleanup_thread = hub.spawn(self._cleanup_loop)
        self.stats_thread = hub.spawn(self._stats_request_loop)

        logger.info("SDN IDS Module initialized")

    def _check_ml_service(self):
        """Check if ML service is available"""
        try:
            response = requests.get(f"{ML_SERVICE_URL}/health", timeout=2)
            self.ml_service_available = response.status_code == 200
            return self.ml_service_available
        except:
            self.ml_service_available = False
            return False

    def _query_ml_service(self, features, flow_id, src_ip, dst_ip):
        """
        Query ML service for traffic classification

        Returns: (action, attack_type, confidence)
        """
        if not self.ml_service_available:
            if not self._check_ml_service():
                logger.warning("ML service unavailable, allowing traffic")
                return 'ALLOW', 'UNKNOWN', 0.0

        try:
            payload = {
                'features': features,
                'flow_id': flow_id,
                'src_ip': src_ip,
                'dst_ip': dst_ip
            }

            response = requests.post(
                f"{ML_SERVICE_URL}/predict",
                json=payload,
                timeout=1
            )

            if response.status_code == 200:
                result = response.json()
                return (
                    result.get('action', 'ALLOW'),
                    result.get('attack_type', 'UNKNOWN'),
                    result.get('confidence', 0.0)
                )
            else:
                logger.error(f"ML service error: {response.status_code}")
                return 'ALLOW', 'ERROR', 0.0

        except requests.exceptions.Timeout:
            logger.warning("ML service timeout")
            return 'ALLOW', 'TIMEOUT', 0.0
        except Exception as e:
            logger.error(f"ML query error: {e}")
            return 'ALLOW', 'ERROR', 0.0

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """Handle switch connection state changes"""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                logger.info(f"Switch {datapath.id} connected")
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                logger.info(f"Switch {datapath.id} disconnected")
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch feature negotiation"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        logger.info(f"Configuring switch {datapath.id}")

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)

    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0, buffer_id=None):
        """Add a flow entry to the switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                     priority=priority, match=match,
                                     idle_timeout=idle_timeout,
                                     hard_timeout=hard_timeout,
                                     instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                     match=match,
                                     idle_timeout=idle_timeout,
                                     hard_timeout=hard_timeout,
                                     instructions=inst)
        datapath.send_msg(mod)

    def _delete_flow(self, datapath, match):
        """Delete a flow entry from the switch"""
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

    def _block_ip(self, datapath, src_ip, duration=3600):
        """Block traffic from a specific IP address"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Add high-priority drop rule
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)
        actions = []  # Empty actions = drop

        self._add_flow(datapath, priority=1000, match=match, actions=actions,
                       hard_timeout=duration)

        self.blocked_ips.add(src_ip)
        self.detection_stats['blocked_flows'] += 1

        logger.warning(f"BLOCKED IP: {src_ip} for {duration} seconds")

    def _quarantine_ip(self, datapath, src_ip, duration=300):
        """Quarantine traffic from a specific IP (rate limiting)"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Add meter for rate limiting (if supported)
        # For simplicity, we'll use a lower priority drop with timeout
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)

        # Send to controller for monitoring
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self._add_flow(datapath, priority=500, match=match, actions=actions,
                       hard_timeout=duration)

        self.quarantined_ips[src_ip] = time.time() + duration
        self.detection_stats['quarantined_flows'] += 1

        logger.warning(f"QUARANTINED IP: {src_ip} for {duration} seconds")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle Packet-In events - main IDS logic"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # Ignore LLDP packets

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Check if this is an IP packet
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            protocol = ip_pkt.proto

            # Check if IP is already blocked
            if src_ip in self.blocked_ips:
                logger.debug(f"Dropping packet from blocked IP: {src_ip}")
                return

            # Get transport layer info
            src_port = 0
            dst_port = 0
            tcp_flags = {}
            window_size = 0

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)

            if tcp_pkt:
                src_port = tcp_pkt.src_port
                dst_port = tcp_pkt.dst_port
                window_size = tcp_pkt.window_size
                tcp_flags = {
                    'syn': 1 if tcp_pkt.bits & tcp.TCP_SYN else 0,
                    'ack': 1 if tcp_pkt.bits & tcp.TCP_ACK else 0,
                    'rst': 1 if tcp_pkt.bits & tcp.TCP_RST else 0,
                    'psh': 1 if tcp_pkt.bits & tcp.TCP_PSH else 0,
                    'fin': 1 if tcp_pkt.bits & tcp.TCP_FIN else 0,
                    'urg': 1 if tcp_pkt.bits & tcp.TCP_URG else 0,
                }
            elif udp_pkt:
                src_port = udp_pkt.src_port
                dst_port = udp_pkt.dst_port

            # Update feature extractor
            packet_length = len(msg.data)
            flow_id = self.feature_extractor.update_flow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_length=packet_length,
                tcp_flags=tcp_flags,
                window_size=window_size,
                header_length=ip_pkt.header_length * 4
            )

            # Extract features and query ML service periodically
            self.detection_stats['total_packets'] += 1

            # Query ML service for classification
            features = self.feature_extractor.extract_features(flow_id)

            if features:
                action, attack_type, confidence = self._query_ml_service(
                    features, flow_id, src_ip, dst_ip
                )

                if action == 'DROP':
                    self._block_ip(datapath, src_ip)
                    self.detection_stats['attack_packets'] += 1
                    logger.warning(
                        f"ATTACK DETECTED: {attack_type} from {src_ip} "
                        f"(confidence: {confidence:.2%})"
                    )
                    return
                elif action == 'QUARANTINE':
                    self._quarantine_ip(datapath, src_ip)
                    self.detection_stats['attack_packets'] += 1
                    logger.warning(
                        f"SUSPICIOUS TRAFFIC: {attack_type} from {src_ip} "
                        f"(confidence: {confidence:.2%}) - QUARANTINED"
                    )
                else:
                    self.detection_stats['benign_packets'] += 1

        # Normal forwarding logic (learning switch)
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow rule for known destinations
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self._add_flow(datapath, 1, match, actions,
                              idle_timeout=FLOW_TIMEOUT_IDLE,
                              buffer_id=msg.buffer_id)
                return
            else:
                self._add_flow(datapath, 1, match, actions,
                              idle_timeout=FLOW_TIMEOUT_IDLE)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Handle flow statistics reply"""
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        for stat in body:
            key = (stat.match.get('ipv4_src'), stat.match.get('ipv4_dst'),
                   stat.match.get('tcp_src'), stat.match.get('tcp_dst'))

            self.flow_stats[dpid][key] = {
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count,
                'duration_sec': stat.duration_sec
            }

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """Handle port statistics reply"""
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        for stat in body:
            self.port_stats[dpid][stat.port_no] = {
                'rx_packets': stat.rx_packets,
                'tx_packets': stat.tx_packets,
                'rx_bytes': stat.rx_bytes,
                'tx_bytes': stat.tx_bytes,
                'rx_errors': stat.rx_errors,
                'tx_errors': stat.tx_errors
            }

    def _request_stats(self, datapath):
        """Request flow and port statistics from switch"""
        parser = datapath.ofproto_parser

        # Request flow stats
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        # Request port stats
        req = parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def _stats_request_loop(self):
        """Periodically request statistics from all switches"""
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(STATS_INTERVAL)

    def _monitor_loop(self):
        """Main monitoring loop"""
        while True:
            # Log statistics periodically
            if self.detection_stats['total_packets'] > 0:
                logger.info(
                    f"IDS Stats - Total: {self.detection_stats['total_packets']}, "
                    f"Benign: {self.detection_stats['benign_packets']}, "
                    f"Attacks: {self.detection_stats['attack_packets']}, "
                    f"Blocked: {self.detection_stats['blocked_flows']}, "
                    f"Quarantined: {self.detection_stats['quarantined_flows']}"
                )

            # Check ML service status
            self._check_ml_service()

            hub.sleep(30)

    def _cleanup_loop(self):
        """Clean up expired quarantine entries and old flows"""
        while True:
            current_time = time.time()

            # Remove expired quarantine entries
            expired = [ip for ip, expiry in self.quarantined_ips.items()
                      if current_time > expiry]
            for ip in expired:
                del self.quarantined_ips[ip]
                logger.info(f"Quarantine expired for IP: {ip}")

            # Clean up feature extractor
            self.feature_extractor.cleanup_old_flows()

            hub.sleep(60)

    def get_ids_statistics(self):
        """Get current IDS statistics"""
        return {
            'detection_stats': self.detection_stats,
            'blocked_ips': list(self.blocked_ips),
            'quarantined_ips': list(self.quarantined_ips.keys()),
            'ml_service_status': self.ml_service_available,
            'active_flows': len(self.feature_extractor.flows),
            'connected_switches': len(self.datapaths)
        }
