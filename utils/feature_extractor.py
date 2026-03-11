"""
Real-time Feature Extractor for SDN Traffic
Ag paketlerinden CIC-DDoS2019 formatinda ozellik cikarimi

Bu modul, SDN controller'dan gelen paket ve akis istatistiklerini
ML modeli icin uygun formata donusturur.
"""

import time
import numpy as np
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger('FeatureExtractor')


@dataclass
class FlowStatistics:
    """Store statistics for a single flow"""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0

    # Timing
    start_time: float = 0.0
    last_time: float = 0.0

    # Packet counts
    total_fwd_packets: int = 0
    total_bwd_packets: int = 0

    # Byte counts
    total_fwd_bytes: int = 0
    total_bwd_bytes: int = 0

    # Packet lengths (forward)
    fwd_packet_lengths: List[int] = field(default_factory=list)
    # Packet lengths (backward)
    bwd_packet_lengths: List[int] = field(default_factory=list)

    # Inter-arrival times
    fwd_iat: List[float] = field(default_factory=list)
    bwd_iat: List[float] = field(default_factory=list)
    flow_iat: List[float] = field(default_factory=list)

    # Flags
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    fin_count: int = 0
    urg_count: int = 0
    cwe_count: int = 0
    ece_count: int = 0

    # Window sizes
    init_fwd_win_bytes: int = 0
    init_bwd_win_bytes: int = 0

    # Header lengths
    fwd_header_length: int = 0
    bwd_header_length: int = 0

    # Active/Idle times
    active_times: List[float] = field(default_factory=list)
    idle_times: List[float] = field(default_factory=list)

    # Segment sizes
    fwd_seg_size_min: int = 0

    # Data packets
    fwd_act_data_packets: int = 0


class FeatureExtractor:
    """
    Extract features from network flows for ML-based IDS
    Implements CIC-DDoS2019 feature extraction methodology
    """

    def __init__(self, feature_window: float = 10.0):
        """
        Initialize feature extractor

        Args:
            feature_window: Time window for flow aggregation (seconds)
        """
        self.feature_window = feature_window
        self.flows: Dict[str, FlowStatistics] = {}
        self.last_cleanup = time.time()

    def _get_flow_id(self, src_ip: str, dst_ip: str,
                      src_port: int, dst_port: int, protocol: int) -> str:
        """Generate unique flow identifier"""
        return f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}"

    def _get_reverse_flow_id(self, src_ip: str, dst_ip: str,
                              src_port: int, dst_port: int, protocol: int) -> str:
        """Generate reverse flow identifier"""
        return f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{protocol}"

    def update_flow(self, src_ip: str, dst_ip: str, src_port: int,
                    dst_port: int, protocol: int, packet_length: int,
                    tcp_flags: Optional[Dict] = None,
                    window_size: int = 0, header_length: int = 0,
                    timestamp: Optional[float] = None) -> str:
        """
        Update flow statistics with new packet information

        Returns: flow_id
        """
        current_time = timestamp or time.time()

        # Determine flow direction
        flow_id = self._get_flow_id(src_ip, dst_ip, src_port, dst_port, protocol)
        reverse_flow_id = self._get_reverse_flow_id(src_ip, dst_ip, src_port, dst_port, protocol)

        # Check if this is forward or backward direction
        is_forward = True
        if reverse_flow_id in self.flows:
            flow_id = reverse_flow_id
            is_forward = False

        # Initialize flow if new
        if flow_id not in self.flows:
            self.flows[flow_id] = FlowStatistics(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                start_time=current_time,
                last_time=current_time,
                init_fwd_win_bytes=window_size,
                fwd_seg_size_min=packet_length
            )

        flow = self.flows[flow_id]

        # Calculate IAT
        if flow.last_time > 0:
            iat = current_time - flow.last_time
            flow.flow_iat.append(iat)

            if is_forward:
                flow.fwd_iat.append(iat)
            else:
                flow.bwd_iat.append(iat)

        flow.last_time = current_time

        # Update packet counts and lengths
        if is_forward:
            flow.total_fwd_packets += 1
            flow.total_fwd_bytes += packet_length
            flow.fwd_packet_lengths.append(packet_length)
            flow.fwd_header_length += header_length

            if packet_length > 0:
                flow.fwd_act_data_packets += 1

            if packet_length < flow.fwd_seg_size_min or flow.fwd_seg_size_min == 0:
                flow.fwd_seg_size_min = packet_length
        else:
            flow.total_bwd_packets += 1
            flow.total_bwd_bytes += packet_length
            flow.bwd_packet_lengths.append(packet_length)
            flow.bwd_header_length += header_length

            if flow.init_bwd_win_bytes == 0:
                flow.init_bwd_win_bytes = window_size

        # Update TCP flags
        if tcp_flags:
            flow.syn_count += tcp_flags.get('syn', 0)
            flow.ack_count += tcp_flags.get('ack', 0)
            flow.rst_count += tcp_flags.get('rst', 0)
            flow.psh_count += tcp_flags.get('psh', 0)
            flow.fin_count += tcp_flags.get('fin', 0)
            flow.urg_count += tcp_flags.get('urg', 0)
            flow.cwe_count += tcp_flags.get('cwe', 0)
            flow.ece_count += tcp_flags.get('ece', 0)

        return flow_id

    def _safe_mean(self, values: List) -> float:
        """Calculate mean safely"""
        return float(np.mean(values)) if values else 0.0

    def _safe_std(self, values: List) -> float:
        """Calculate standard deviation safely"""
        return float(np.std(values)) if len(values) > 1 else 0.0

    def _safe_max(self, values: List) -> float:
        """Calculate max safely"""
        return float(max(values)) if values else 0.0

    def _safe_min(self, values: List) -> float:
        """Calculate min safely"""
        return float(min(values)) if values else 0.0

    def _safe_variance(self, values: List) -> float:
        """Calculate variance safely"""
        return float(np.var(values)) if values else 0.0

    def extract_features(self, flow_id: str) -> Optional[List[float]]:
        """
        Extract 45 HHO-selected features for a flow

        Returns: List of 45 feature values in the correct order
        """
        if flow_id not in self.flows:
            logger.warning(f"Flow {flow_id} not found")
            return None

        flow = self.flows[flow_id]

        # Calculate derived statistics
        flow_duration = (flow.last_time - flow.start_time) * 1000000  # microseconds
        if flow_duration <= 0:
            flow_duration = 1  # Avoid division by zero

        all_packet_lengths = flow.fwd_packet_lengths + flow.bwd_packet_lengths

        # Calculate features in HHO-selected order
        features = [
            # 1. Subflow Bwd Packets
            float(flow.total_bwd_packets),
            # 2. Fwd Packet Length Max
            self._safe_max(flow.fwd_packet_lengths),
            # 3. Idle Mean
            self._safe_mean(flow.idle_times),
            # 4. Packet Length Max
            self._safe_max(all_packet_lengths),
            # 5. Flow Bytes/s
            (flow.total_fwd_bytes + flow.total_bwd_bytes) / (flow_duration / 1000000) if flow_duration > 0 else 0,
            # 6. Packet Length Min
            self._safe_min(all_packet_lengths) if all_packet_lengths else 0,
            # 7. ACK Flag Count
            float(flow.ack_count),
            # 8. Fwd Seg Size Min
            float(flow.fwd_seg_size_min),
            # 9. RST Flag Count
            float(flow.rst_count),
            # 10. Init Fwd Win Bytes
            float(flow.init_fwd_win_bytes),
            # 11. CWE Flag Count
            float(flow.cwe_count),
            # 12. Init Bwd Win Bytes
            float(flow.init_bwd_win_bytes),
            # 13. Fwd Header Length
            float(flow.fwd_header_length),
            # 14. Bwd IAT Max
            self._safe_max(flow.bwd_iat) * 1000000,  # Convert to microseconds
            # 15. Avg Bwd Segment Size
            self._safe_mean(flow.bwd_packet_lengths),
            # 16. Bwd Packet Length Mean
            self._safe_mean(flow.bwd_packet_lengths),
            # 17. Subflow Fwd Packets
            float(flow.total_fwd_packets),
            # 18. Active Max
            self._safe_max(flow.active_times),
            # 19. Fwd Packet Length Std
            self._safe_std(flow.fwd_packet_lengths),
            # 20. Packet Length Variance
            self._safe_variance(all_packet_lengths),
            # 21. Flow Duration
            flow_duration,
            # 22. Total Fwd Packets
            float(flow.total_fwd_packets),
            # 23. Total Backward Packets
            float(flow.total_bwd_packets),
            # 24. Fwd Packets Length Total
            float(flow.total_fwd_bytes),
            # 25. Fwd Packet Length Min
            self._safe_min(flow.fwd_packet_lengths) if flow.fwd_packet_lengths else 0,
            # 26. Bwd Packet Length Max
            self._safe_max(flow.bwd_packet_lengths),
            # 27. Flow IAT Mean
            self._safe_mean(flow.flow_iat) * 1000000,
            # 28. Flow IAT Max
            self._safe_max(flow.flow_iat) * 1000000,
            # 29. Fwd IAT Total
            sum(flow.fwd_iat) * 1000000 if flow.fwd_iat else 0,
            # 30. Fwd IAT Std
            self._safe_std(flow.fwd_iat) * 1000000,
            # 31. Fwd IAT Min
            self._safe_min(flow.fwd_iat) * 1000000 if flow.fwd_iat else 0,
            # 32. Bwd IAT Mean
            self._safe_mean(flow.bwd_iat) * 1000000,
            # 33. Bwd IAT Std
            self._safe_std(flow.bwd_iat) * 1000000,
            # 34. Idle Max
            self._safe_max(flow.idle_times),
            # 35. Subflow Fwd Bytes
            float(flow.total_fwd_bytes),
            # 36. Fwd Act Data Packets
            float(flow.fwd_act_data_packets),
            # 37. Packet Length Mean
            self._safe_mean(all_packet_lengths),
            # 38. Active Min
            self._safe_min(flow.active_times) if flow.active_times else 0,
            # 39. Protocol
            float(flow.protocol),
            # 40. Bwd Packets Length Total
            float(flow.total_bwd_bytes),
            # 41. Bwd Packet Length Min
            self._safe_min(flow.bwd_packet_lengths) if flow.bwd_packet_lengths else 0,
            # 42. Fwd IAT Mean
            self._safe_mean(flow.fwd_iat) * 1000000,
            # 43. Down/Up Ratio
            flow.total_bwd_bytes / flow.total_fwd_bytes if flow.total_fwd_bytes > 0 else 0,
            # 44. Avg Fwd Segment Size
            self._safe_mean(flow.fwd_packet_lengths),
            # 45. Active Mean
            self._safe_mean(flow.active_times)
        ]

        return features

    def cleanup_old_flows(self, max_age: float = 120.0):
        """Remove flows older than max_age seconds"""
        current_time = time.time()

        if current_time - self.last_cleanup < 30:  # Cleanup every 30 seconds
            return

        expired_flows = [
            fid for fid, flow in self.flows.items()
            if current_time - flow.last_time > max_age
        ]

        for fid in expired_flows:
            del self.flows[fid]

        if expired_flows:
            logger.info(f"Cleaned up {len(expired_flows)} expired flows")

        self.last_cleanup = current_time

    def get_all_flow_features(self) -> Dict[str, List[float]]:
        """Extract features for all active flows"""
        results = {}
        for flow_id in self.flows:
            features = self.extract_features(flow_id)
            if features:
                results[flow_id] = features
        return results
