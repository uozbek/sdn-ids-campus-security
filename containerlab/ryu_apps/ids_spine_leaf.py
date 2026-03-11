"""
IDS-Enabled Spine-Leaf SDN Controller Application

Bu uygulama, HHO-BDT makine öğrenmesi modelini Spine-Leaf
SDN mimarisine entegre eder.

Author: PhD Research - SDN Security
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from ryu.lib.packet import ether_types
from ryu.app.ofctl.api import get_datapath
from ryu.lib import hub

import requests
import time
import logging
from collections import defaultdict
from datetime import datetime

# ============================================
# Configuration
# ============================================
ML_SERVICE_URL = "http://172.10.10.100:5000"
CONFIDENCE_THRESHOLD = 0.85
QUARANTINE_THRESHOLD = 0.70
BLOCK_DURATION = 300  # 5 minutes
FLOW_TIMEOUT = 30

# Network Topology
TABLE0 = 0
MIN_PRIORITY = 0
MID_PRIORITY = 500
HIGH_PRIORITY = 1000
BLOCK_PRIORITY = 65000

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('IDS_SpineLeaf')


class NetworkTopology:
    """Spine-Leaf Network Definition"""
    spines = [11, 12]  # Spine switch IDs (0x0B, 0x0C)
    leaves = [21, 22, 23]  # Leaf switch IDs (0x15, 0x16, 0x17)

    links = {
        (11, 21): {'port': 1}, (11, 22): {'port': 2}, (11, 23): {'port': 3},
        (12, 21): {'port': 1}, (12, 22): {'port': 2}, (12, 23): {'port': 3},
        (21, 11): {'port': 1}, (21, 12): {'port': 2},
        (22, 11): {'port': 1}, (22, 12): {'port': 2},
        (23, 11): {'port': 1}, (23, 12): {'port': 2}
    }


net = NetworkTopology()


class FlowStatistics:
    """Per-flow statistics for feature extraction"""

    def __init__(self):
        self.start_time = time.time()
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.fwd_pkt_lengths = []
        self.bwd_pkt_lengths = []
        self.fwd_iats = []
        self.bwd_iats = []
        self.last_fwd_time = None
        self.last_bwd_time = None
        self.tcp_flags = defaultdict(int)
        self.init_win_fwd = 0
        self.init_win_bwd = 0

    def update_forward(self, pkt_len, tcp_pkt=None):
        current_time = time.time()
        self.fwd_packets += 1
        self.fwd_bytes += pkt_len
        self.fwd_pkt_lengths.append(pkt_len)

        if self.last_fwd_time:
            self.fwd_iats.append(current_time - self.last_fwd_time)
        self.last_fwd_time = current_time

        if tcp_pkt:
            self._update_tcp_flags(tcp_pkt)
            if self.fwd_packets == 1:
                self.init_win_fwd = tcp_pkt.window_size

    def update_backward(self, pkt_len, tcp_pkt=None):
        current_time = time.time()
        self.bwd_packets += 1
        self.bwd_bytes += pkt_len
        self.bwd_pkt_lengths.append(pkt_len)

        if self.last_bwd_time:
            self.bwd_iats.append(current_time - self.last_bwd_time)
        self.last_bwd_time = current_time

        if tcp_pkt:
            self._update_tcp_flags(tcp_pkt)
            if self.bwd_packets == 1:
                self.init_win_bwd = tcp_pkt.window_size

    def _update_tcp_flags(self, tcp_pkt):
        if tcp_pkt.has_flags(tcp.TCP_SYN):
            self.tcp_flags['SYN'] += 1
        if tcp_pkt.has_flags(tcp.TCP_FIN):
            self.tcp_flags['FIN'] += 1
        if tcp_pkt.has_flags(tcp.TCP_RST):
            self.tcp_flags['RST'] += 1
        if tcp_pkt.has_flags(tcp.TCP_PSH):
            self.tcp_flags['PSH'] += 1
        if tcp_pkt.has_flags(tcp.TCP_ACK):
            self.tcp_flags['ACK'] += 1
        if tcp_pkt.has_flags(tcp.TCP_URG):
            self.tcp_flags['URG'] += 1

    def extract_features(self):
        """Extract 45 HHO-selected features"""
        duration = max(time.time() - self.start_time, 0.001)
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes

        all_pkt_lengths = self.fwd_pkt_lengths + self.bwd_pkt_lengths
        all_iats = self.fwd_iats + self.bwd_iats

        features = {
            # Flow statistics
            'Flow Duration': duration * 1e6,
            'Total Fwd Packets': self.fwd_packets,
            'Total Backward Packets': self.bwd_packets,
            'Total Length of Fwd Packets': self.fwd_bytes,
            'Total Length of Bwd Packets': self.bwd_bytes,

            # Packet lengths
            'Fwd Packet Length Max': max(self.fwd_pkt_lengths) if self.fwd_pkt_lengths else 0,
            'Fwd Packet Length Min': min(self.fwd_pkt_lengths) if self.fwd_pkt_lengths else 0,
            'Fwd Packet Length Mean': sum(self.fwd_pkt_lengths) / len(self.fwd_pkt_lengths) if self.fwd_pkt_lengths else 0,
            'Bwd Packet Length Max': max(self.bwd_pkt_lengths) if self.bwd_pkt_lengths else 0,
            'Bwd Packet Length Min': min(self.bwd_pkt_lengths) if self.bwd_pkt_lengths else 0,
            'Bwd Packet Length Mean': sum(self.bwd_pkt_lengths) / len(self.bwd_pkt_lengths) if self.bwd_pkt_lengths else 0,
            'Packet Length Max': max(all_pkt_lengths) if all_pkt_lengths else 0,
            'Packet Length Min': min(all_pkt_lengths) if all_pkt_lengths else 0,
            'Packet Length Mean': sum(all_pkt_lengths) / len(all_pkt_lengths) if all_pkt_lengths else 0,
            'Packet Length Variance': self._variance(all_pkt_lengths),

            # Flow rates
            'Flow Bytes/s': total_bytes / duration,
            'Flow Packets/s': total_packets / duration,

            # IAT features
            'Flow IAT Mean': sum(all_iats) / len(all_iats) if all_iats else 0,
            'Flow IAT Max': max(all_iats) if all_iats else 0,
            'Flow IAT Min': min(all_iats) if all_iats else 0,
            'Fwd IAT Total': sum(self.fwd_iats),
            'Fwd IAT Mean': sum(self.fwd_iats) / len(self.fwd_iats) if self.fwd_iats else 0,
            'Fwd IAT Max': max(self.fwd_iats) if self.fwd_iats else 0,
            'Bwd IAT Total': sum(self.bwd_iats),
            'Bwd IAT Mean': sum(self.bwd_iats) / len(self.bwd_iats) if self.bwd_iats else 0,

            # TCP Flags
            'PSH Flag Count': self.tcp_flags['PSH'],
            'ACK Flag Count': self.tcp_flags['ACK'],
            'URG Flag Count': self.tcp_flags['URG'],
            'SYN Flag Count': self.tcp_flags['SYN'],
            'RST Flag Count': self.tcp_flags['RST'],
            'FIN Flag Count': self.tcp_flags['FIN'],

            # Subflow
            'Subflow Fwd Packets': self.fwd_packets,
            'Subflow Fwd Bytes': self.fwd_bytes,
            'Subflow Bwd Packets': self.bwd_packets,
            'Subflow Bwd Bytes': self.bwd_bytes,

            # Window sizes
            'Init_Win_bytes_forward': self.init_win_fwd,
            'Init_Win_bytes_backward': self.init_win_bwd,

            # Additional metrics
            'min_seg_size_forward': min(self.fwd_pkt_lengths) if self.fwd_pkt_lengths else 0,
            'Average Packet Size': total_bytes / total_packets if total_packets > 0 else 0,
            'Avg Fwd Segment Size': self.fwd_bytes / self.fwd_packets if self.fwd_packets > 0 else 0,
            'Avg Bwd Segment Size': self.bwd_bytes / self.bwd_packets if self.bwd_packets > 0 else 0,

            # Idle/Active
            'Idle Mean': max(all_iats) if all_iats else 0,
            'Idle Max': max(all_iats) if all_iats else 0,
            'Idle Min': min(all_iats) if all_iats else 0,
            'Active Mean': sum(all_iats) / len(all_iats) if all_iats else 0,
        }

        return features

    def _variance(self, values):
        if not values:
            return 0
        mean = sum(values) / len(values)
        return sum((x - mean) ** 2 for x in values) / len(values)


class IDSSpineLeaf(app_manager.RyuApp):
    """
    IDS-Enabled Spine-Leaf SDN Controller

    Integrates HHO-BDT ML model for real-time DDoS detection
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_table = {}
        self.flow_stats = {}  # {flow_key: FlowStatistics}
        self.blocked_ips = {}  # {ip: unblock_time}
        self.quarantined_ips = {}  # {ip: unblock_time}
        self.detection_stats = {
            'total_flows': 0,
            'blocked': 0,
            'quarantined': 0,
            'allowed': 0
        }
        self.ignore = [ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6]

        # Start background threads
        self.monitor_thread = hub.spawn(self._monitor_flows)
        self.cleanup_thread = hub.spawn(self._cleanup_blocked_ips)

        logger.info("=" * 60)
        logger.info("IDS Spine-Leaf Controller Started")
        logger.info(f"ML Service: {ML_SERVICE_URL}")
        logger.info(f"Confidence Threshold: {CONFIDENCE_THRESHOLD}")
        logger.info("=" * 60)

    def _get_flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """Generate unique flow identifier"""
        return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}"

    def _monitor_flows(self):
        """Background thread to analyze accumulated flows"""
        while True:
            hub.sleep(5)  # Analyze every 5 seconds

            flows_to_analyze = []
            current_time = time.time()

            for flow_key, stats in list(self.flow_stats.items()):
                # Analyze flows with sufficient data
                if stats.fwd_packets + stats.bwd_packets >= 10:
                    flows_to_analyze.append((flow_key, stats))
                # Remove old flows
                elif current_time - stats.start_time > 60:
                    del self.flow_stats[flow_key]

            for flow_key, stats in flows_to_analyze:
                try:
                    features = stats.extract_features()
                    result = self._query_ml_service(features)

                    if result and result.get('prediction') == 1:
                        # Malicious flow detected
                        src_ip = flow_key.split('->')[0].split(':')[0]
                        action = result.get('action', 'QUARANTINE')
                        confidence = result.get('confidence', 0)

                        logger.warning(f"[ALERT] Malicious flow detected: {flow_key}")
                        logger.warning(f"[ALERT] Confidence: {confidence:.2%}, Action: {action}")

                        if action == 'DROP':
                            self._block_ip_global(src_ip)
                        else:
                            self._quarantine_ip_global(src_ip)

                except Exception as e:
                    logger.error(f"Error analyzing flow {flow_key}: {e}")
                finally:
                    # Reset flow statistics
                    del self.flow_stats[flow_key]

    def _cleanup_blocked_ips(self):
        """Periodically clean up expired blocks"""
        while True:
            hub.sleep(30)
            current_time = time.time()

            for ip in list(self.blocked_ips.keys()):
                if current_time > self.blocked_ips[ip]:
                    del self.blocked_ips[ip]
                    logger.info(f"[UNBLOCK] IP {ip} unblocked (expired)")

            for ip in list(self.quarantined_ips.keys()):
                if current_time > self.quarantined_ips[ip]:
                    del self.quarantined_ips[ip]
                    logger.info(f"[UNQUARANTINE] IP {ip} removed from quarantine")

    def _query_ml_service(self, features):
        """Query ML inference service"""
        try:
            response = requests.post(
                f"{ML_SERVICE_URL}/predict",
                json={'features': features},
                timeout=2
            )
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.debug(f"ML service query failed: {e}")
        return None

    def _block_ip_global(self, ip):
        """Block IP across all switches"""
        if ip in self.blocked_ips:
            return

        self.blocked_ips[ip] = time.time() + BLOCK_DURATION
        self.detection_stats['blocked'] += 1

        logger.warning(f"[BLOCK] Blocking IP {ip} for {BLOCK_DURATION}s")

        # Install drop rules on all leaf switches
        for leaf_id in net.leaves:
            datapath = get_datapath(self, leaf_id)
            if datapath:
                self._install_drop_rule(datapath, ip)

    def _quarantine_ip_global(self, ip):
        """Quarantine IP (rate limit) across all switches"""
        if ip in self.quarantined_ips:
            return

        self.quarantined_ips[ip] = time.time() + BLOCK_DURATION
        self.detection_stats['quarantined'] += 1

        logger.warning(f"[QUARANTINE] Rate limiting IP {ip} for {BLOCK_DURATION}s")

        # Install rate-limit meter on all leaf switches
        for leaf_id in net.leaves:
            datapath = get_datapath(self, leaf_id)
            if datapath:
                self._install_quarantine_rule(datapath, ip)

    def _install_drop_rule(self, datapath, ip):
        """Install flow rule to drop packets from IP"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        inst = []  # Empty instruction = drop

        msg = parser.OFPFlowMod(
            datapath=datapath,
            priority=BLOCK_PRIORITY,
            match=match,
            instructions=inst,
            hard_timeout=BLOCK_DURATION
        )
        datapath.send_msg(msg)

    def _install_quarantine_rule(self, datapath, ip):
        """Install flow rule to rate limit packets from IP"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Create meter for rate limiting (100 packets/sec)
        meter_id = hash(ip) % 65535
        bands = [parser.OFPMeterBandDrop(rate=100, burst_size=10)]

        meter_mod = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_PKTPS,
            meter_id=meter_id,
            bands=bands
        )
        datapath.send_msg(meter_mod)

        # Apply meter to traffic from IP
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        inst = [parser.OFPInstructionMeter(meter_id)]

        msg = parser.OFPFlowMod(
            datapath=datapath,
            priority=HIGH_PRIORITY,
            match=match,
            instructions=inst,
            hard_timeout=BLOCK_DURATION
        )
        datapath.send_msg(msg)

    # ============================================
    # OpenFlow Event Handlers
    # ============================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):
        """Handle switch connection"""
        datapath = event.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Delete all existing flows
        self._del_all_flows(datapath)

        if datapath.id in net.leaves:
            # Leaf switch: send packets to controller
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )]
            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions
            )]
            self._add_flow(datapath, TABLE0, MIN_PRIORITY, match, inst)
            logger.info(f"[SWITCH] Leaf switch {datapath.id} connected")
        else:
            # Spine switch: default drop
            match = parser.OFPMatch()
            inst = []
            self._add_flow(datapath, TABLE0, MIN_PRIORITY, match, inst)
            logger.info(f"[SWITCH] Spine switch {datapath.id} connected")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        """Handle incoming packets"""
        datapath = event.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = event.msg.match['in_port']

        # Parse packet
        pkt = packet.Packet(event.msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype in self.ignore:
            return

        # Get IP information if available
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        src = eth.src
        dst = eth.dst

        # Check if source IP is blocked
        if ip_pkt and ip_pkt.src in self.blocked_ips:
            logger.debug(f"[DROP] Packet from blocked IP {ip_pkt.src}")
            return

        # Update flow statistics
        if ip_pkt:
            self._update_flow_stats(ip_pkt, tcp_pkt, udp_pkt, len(event.msg.data))

        # Learn MAC address
        src_host = self.mac_table.get(src, {})
        src_host['port'] = in_port
        src_host['dpid'] = datapath.id
        self.mac_table[src] = src_host

        # Determine output port
        dst_host = self.mac_table.get(dst)
        out_port = dst_host['port'] if dst_host else ofproto.OFPP_ALL

        if out_port == ofproto.OFPP_ALL:
            # Flood to all leaf switches
            for leaf in net.leaves:
                dpath = get_datapath(self, leaf)
                if dpath:
                    actual_in_port = in_port if datapath.id == leaf else ofproto.OFPP_CONTROLLER
                    self._forward_packet(dpath, event.msg.data, actual_in_port, out_port)
        else:
            if dst_host['dpid'] == datapath.id:
                # Same leaf switch
                self._make_dual_connections(datapath, src, dst, in_port, out_port)
                self._forward_packet(datapath, event.msg.data, in_port, out_port)
            else:
                # Different leaf switches - use spine
                self._route_through_spine(
                    datapath, src, dst, in_port,
                    src_host, dst_host, event.msg.data
                )

    def _update_flow_stats(self, ip_pkt, tcp_pkt, udp_pkt, pkt_len):
        """Update flow statistics for ML analysis"""
        src_port = dst_port = 0
        protocol = ip_pkt.proto

        if tcp_pkt:
            src_port = tcp_pkt.src_port
            dst_port = tcp_pkt.dst_port
        elif udp_pkt:
            src_port = udp_pkt.src_port
            dst_port = udp_pkt.dst_port

        # Forward flow key
        fwd_key = self._get_flow_key(
            ip_pkt.src, ip_pkt.dst, src_port, dst_port, protocol
        )
        # Backward flow key
        bwd_key = self._get_flow_key(
            ip_pkt.dst, ip_pkt.src, dst_port, src_port, protocol
        )

        if fwd_key in self.flow_stats:
            self.flow_stats[fwd_key].update_forward(pkt_len, tcp_pkt)
        elif bwd_key in self.flow_stats:
            self.flow_stats[bwd_key].update_backward(pkt_len, tcp_pkt)
        else:
            # New flow
            self.flow_stats[fwd_key] = FlowStatistics()
            self.flow_stats[fwd_key].update_forward(pkt_len, tcp_pkt)
            self.detection_stats['total_flows'] += 1

    def _route_through_spine(self, datapath, src, dst, in_port, src_host, dst_host, data):
        """Route traffic through spine switch"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Select spine based on hash
        spine_idx = hash(src_host['dpid'] + dst_host['dpid']) % len(net.spines)
        selected_spine = net.spines[spine_idx]

        # Source leaf -> Spine
        upstream_port = net.links[datapath.id, selected_spine]['port']
        self._make_dual_connections(datapath, src, dst, in_port, upstream_port)

        # Spine switch flows
        spine_dp = get_datapath(self, selected_spine)
        dst_dp = get_datapath(self, dst_host['dpid'])

        if spine_dp and dst_dp:
            spine_in = net.links[selected_spine, datapath.id]['port']
            spine_out = net.links[selected_spine, dst_dp.id]['port']
            self._make_dual_connections(spine_dp, src, dst, spine_in, spine_out)

            # Destination leaf flows
            down_port = net.links[dst_dp.id, selected_spine]['port']
            remote_port = dst_host['port']
            self._make_dual_connections(dst_dp, src, dst, down_port, remote_port)

            # Forward packet to destination
            self._forward_packet(dst_dp, data, ofproto.OFPP_CONTROLLER, remote_port)

    def _make_dual_connections(self, datapath, src, dst, in_port, out_port):
        """Create bidirectional flow rules"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Forward direction
        match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self._add_flow(datapath, TABLE0, MID_PRIORITY, match, inst, idle=FLOW_TIMEOUT)

        # Reverse direction
        match = parser.OFPMatch(in_port=out_port, eth_src=dst, eth_dst=src)
        actions = [parser.OFPActionOutput(in_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self._add_flow(datapath, TABLE0, MID_PRIORITY, match, inst, idle=FLOW_TIMEOUT)

    def _forward_packet(self, datapath, data, in_port, out_port):
        """Send packet out"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        actions = [parser.OFPActionOutput(out_port)]
        msg = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(msg)

    def _add_flow(self, datapath, table, priority, match, inst, idle=0):
        """Add flow rule"""
        parser = datapath.ofproto_parser
        msg = parser.OFPFlowMod(
            datapath=datapath,
            table_id=table,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle
        )
        datapath.send_msg(msg)

    def _del_all_flows(self, datapath):
        """Delete all flows"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        msg = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch()
        )
        datapath.send_msg(msg)
