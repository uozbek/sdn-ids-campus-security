"""
Test module for ML Inference Service
"""

import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml_service.inference_server import app, predict_traffic
from config.config import HHO_SELECTED_FEATURES


@pytest.fixture
def client():
    """Create test client"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestHealthEndpoint:
    """Test health check endpoint"""

    def test_health_check(self, client):
        """Test health endpoint returns 200"""
        response = client.get('/health')
        assert response.status_code == 200
        data = response.get_json()
        assert 'status' in data
        assert data['status'] == 'healthy'


class TestPredictEndpoint:
    """Test prediction endpoint"""

    def test_predict_missing_features(self, client):
        """Test error handling for missing features"""
        response = client.post('/predict', json={})
        assert response.status_code == 400

    def test_predict_wrong_feature_count(self, client):
        """Test error handling for wrong feature count"""
        response = client.post('/predict', json={'features': [1, 2, 3]})
        assert response.status_code == 400

    def test_predict_valid_request(self, client):
        """Test prediction with valid features"""
        # Create dummy features (45 features)
        features = [0.0] * len(HHO_SELECTED_FEATURES)
        features[4] = 1000  # Flow Bytes/s - low value (benign)

        response = client.post('/predict', json={
            'features': features,
            'flow_id': 'test_flow',
            'src_ip': '192.168.1.1',
            'dst_ip': '192.168.1.2'
        })

        assert response.status_code == 200
        data = response.get_json()
        assert 'prediction' in data
        assert 'confidence' in data
        assert 'action' in data

    def test_predict_high_traffic_volume(self, client):
        """Test prediction with high traffic (potential attack)"""
        features = [0.0] * len(HHO_SELECTED_FEATURES)
        features[4] = 10000000  # Very high Flow Bytes/s

        response = client.post('/predict', json={
            'features': features,
            'flow_id': 'attack_flow',
            'src_ip': '10.0.0.1',
            'dst_ip': '192.168.1.1'
        })

        assert response.status_code == 200
        data = response.get_json()
        assert 'action' in data


class TestModelInfo:
    """Test model information endpoint"""

    def test_model_info(self, client):
        """Test model info endpoint"""
        response = client.get('/model/info')
        assert response.status_code == 200
        data = response.get_json()
        assert 'feature_count' in data
        assert data['feature_count'] == len(HHO_SELECTED_FEATURES)


class TestBatchPredict:
    """Test batch prediction endpoint"""

    def test_batch_predict(self, client):
        """Test batch prediction"""
        features = [0.0] * len(HHO_SELECTED_FEATURES)

        response = client.post('/predict/batch', json={
            'flows': [
                {'features': features, 'flow_id': 'flow1'},
                {'features': features, 'flow_id': 'flow2'}
            ]
        })

        assert response.status_code == 200
        data = response.get_json()
        assert 'results' in data
        assert 'total_processed' in data
        assert data['total_processed'] == 2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
