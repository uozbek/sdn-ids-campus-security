"""
Test module for Feature Extractor
"""

import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.feature_extractor import FeatureExtractor, FlowStatistics
from config.config import HHO_SELECTED_FEATURES


class TestFeatureExtractor:
    """Test feature extraction functionality"""

    @pytest.fixture
    def extractor(self):
        """Create feature extractor instance"""
        return FeatureExtractor()

    def test_flow_creation(self, extractor):
        """Test flow creation"""
        flow_id = extractor.update_flow(
            src_ip='192.168.1.1',
            dst_ip='192.168.1.2',
            src_port=12345,
            dst_port=80,
            protocol=6,
            packet_length=1500
        )

        assert flow_id is not None
        assert flow_id in extractor.flows

    def test_flow_update(self, extractor):
        """Test flow statistics update"""
        # First packet
        flow_id = extractor.update_flow(
            src_ip='192.168.1.1',
            dst_ip='192.168.1.2',
            src_port=12345,
            dst_port=80,
            protocol=6,
            packet_length=1500
        )

        # Second packet
        extractor.update_flow(
            src_ip='192.168.1.1',
            dst_ip='192.168.1.2',
            src_port=12345,
            dst_port=80,
            protocol=6,
            packet_length=500
        )

        flow = extractor.flows[flow_id]
        assert flow.total_fwd_packets == 2
        assert flow.total_fwd_bytes == 2000

    def test_feature_extraction(self, extractor):
        """Test feature extraction produces correct number of features"""
        flow_id = extractor.update_flow(
            src_ip='192.168.1.1',
            dst_ip='192.168.1.2',
            src_port=12345,
            dst_port=80,
            protocol=6,
            packet_length=1500,
            tcp_flags={'syn': 1, 'ack': 0}
        )

        features = extractor.extract_features(flow_id)

        assert features is not None
        assert len(features) == len(HHO_SELECTED_FEATURES)
        assert len(features) == 45

    def test_bidirectional_flow(self, extractor):
        """Test bidirectional flow handling"""
        # Forward packet
        flow_id = extractor.update_flow(
            src_ip='192.168.1.1',
            dst_ip='192.168.1.2',
            src_port=12345,
            dst_port=80,
            protocol=6,
            packet_length=1500
        )

        # Backward packet
        extractor.update_flow(
            src_ip='192.168.1.2',
            dst_ip='192.168.1.1',
            src_port=80,
            dst_port=12345,
            protocol=6,
            packet_length=500
        )

        flow = extractor.flows[flow_id]
        assert flow.total_fwd_packets == 1
        assert flow.total_bwd_packets == 1

    def test_tcp_flags(self, extractor):
        """Test TCP flag counting"""
        flow_id = extractor.update_flow(
            src_ip='192.168.1.1',
            dst_ip='192.168.1.2',
            src_port=12345,
            dst_port=80,
            protocol=6,
            packet_length=64,
            tcp_flags={'syn': 1, 'ack': 1, 'psh': 1}
        )

        flow = extractor.flows[flow_id]
        assert flow.syn_count == 1
        assert flow.ack_count == 1
        assert flow.psh_count == 1

    def test_flow_cleanup(self, extractor):
        """Test old flow cleanup"""
        flow_id = extractor.update_flow(
            src_ip='192.168.1.1',
            dst_ip='192.168.1.2',
            src_port=12345,
            dst_port=80,
            protocol=6,
            packet_length=1500,
            timestamp=1.0  # Old timestamp
        )

        # Force cleanup with very short max_age
        extractor.last_cleanup = 0
        extractor.cleanup_old_flows(max_age=0.001)

        assert flow_id not in extractor.flows


class TestFlowStatistics:
    """Test FlowStatistics dataclass"""

    def test_default_values(self):
        """Test default values"""
        flow = FlowStatistics()
        assert flow.total_fwd_packets == 0
        assert flow.total_bwd_packets == 0
        assert len(flow.fwd_packet_lengths) == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
