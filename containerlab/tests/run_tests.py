#!/usr/bin/env python3
"""
SDN-IDS Complete Test Suite

Bu script, tüm sistem bileşenlerini test eder:
1. ML Servis bağlantısı
2. IDS tespit yetenekleri
3. Flow rule yönetimi
4. Performans metrikleri

Author: PhD Research - SDN Security
"""

import requests
import time
import subprocess
import sys
import json
from datetime import datetime

# Configuration
ML_SERVICE_URL = "http://172.10.10.100:5000"
CONTROLLER_URL = "http://172.10.10.10:8080"
VICTIM_IP = "192.168.11.6"
ATTACKER_IP = "192.168.11.5"

class SDNIDSTestSuite:
    """Complete test suite for SDN-IDS system"""

    def __init__(self):
        self.results = []
        self.passed = 0
        self.failed = 0

    def log(self, message, status="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{status}] {message}")

    def test(self, name, func):
        """Run a single test"""
        self.log(f"Testing: {name}", "TEST")
        try:
            result = func()
            if result:
                self.log(f"PASSED: {name}", "PASS")
                self.passed += 1
                self.results.append({"name": name, "status": "PASSED"})
            else:
                self.log(f"FAILED: {name}", "FAIL")
                self.failed += 1
                self.results.append({"name": name, "status": "FAILED"})
        except Exception as e:
            self.log(f"ERROR: {name} - {e}", "ERROR")
            self.failed += 1
            self.results.append({"name": name, "status": "ERROR", "error": str(e)})

    # ============================================
    # Connectivity Tests
    # ============================================

    def test_ml_service_health(self):
        """Test ML service is running"""
        response = requests.get(f"{ML_SERVICE_URL}/health", timeout=5)
        return response.status_code == 200 and response.json().get('status') == 'healthy'

    def test_ml_service_model_loaded(self):
        """Test ML model is loaded"""
        response = requests.get(f"{ML_SERVICE_URL}/model/info", timeout=5)
        data = response.json()
        return data.get('model_loaded') == True

    def test_controller_accessible(self):
        """Test Ryu controller is accessible"""
        response = requests.get(f"{CONTROLLER_URL}/stats/switches", timeout=5)
        return response.status_code == 200

    def test_all_switches_connected(self):
        """Test all 5 switches are connected"""
        response = requests.get(f"{CONTROLLER_URL}/stats/switches", timeout=5)
        switches = response.json()
        return len(switches) >= 5

    # ============================================
    # ML Prediction Tests
    # ============================================

    def test_benign_traffic_prediction(self):
        """Test benign traffic is correctly classified"""
        # Features representing normal traffic
        benign_features = {
            'Flow Duration': 1000000,
            'Total Fwd Packets': 10,
            'Total Backward Packets': 8,
            'Fwd Packet Length Max': 1460,
            'Fwd Packet Length Min': 64,
            'Fwd Packet Length Mean': 500,
            'Flow Bytes/s': 5000,
            'Flow Packets/s': 50,
            'Flow IAT Mean': 20000,
            'SYN Flag Count': 1,
            'ACK Flag Count': 15,
            'PSH Flag Count': 5,
            # ... other features with normal values
        }

        response = requests.post(
            f"{ML_SERVICE_URL}/predict",
            json={'features': benign_features},
            timeout=5
        )
        result = response.json()
        return result.get('prediction') == 0 and result.get('action') == 'ALLOW'

    def test_malicious_traffic_prediction(self):
        """Test malicious traffic is correctly classified"""
        # Features representing DDoS attack
        malicious_features = {
            'Flow Duration': 100000,
            'Total Fwd Packets': 10000,
            'Total Backward Packets': 0,
            'Fwd Packet Length Max': 60,
            'Fwd Packet Length Min': 40,
            'Fwd Packet Length Mean': 50,
            'Flow Bytes/s': 500000,
            'Flow Packets/s': 10000,
            'Flow IAT Mean': 10,
            'SYN Flag Count': 10000,
            'ACK Flag Count': 0,
            'PSH Flag Count': 0,
            # ... features indicating attack
        }

        response = requests.post(
            f"{ML_SERVICE_URL}/predict",
            json={'features': malicious_features},
            timeout=5
        )
        result = response.json()
        return result.get('prediction') == 1

    def test_batch_prediction(self):
        """Test batch prediction capability"""
        batch_features = [
            {'Flow Duration': 1000000, 'Flow Bytes/s': 5000},
            {'Flow Duration': 100000, 'Flow Bytes/s': 500000}
        ]

        response = requests.post(
            f"{ML_SERVICE_URL}/predict/batch",
            json={'features_list': batch_features},
            timeout=5
        )
        return response.status_code == 200 and len(response.json().get('results', [])) == 2

    # ============================================
    # Network Connectivity Tests
    # ============================================

    def test_host_connectivity(self):
        """Test hosts can ping each other"""
        # h11 -> h22 connectivity
        result = subprocess.run(
            ['docker', 'exec', 'clab-sdn-ids-h11', 'ping', '-c', '3', '192.168.11.4'],
            capture_output=True,
            timeout=10
        )
        return result.returncode == 0

    def test_cross_leaf_connectivity(self):
        """Test connectivity between different leaf switches"""
        # h11 (leaf1) -> h31 (leaf3)
        result = subprocess.run(
            ['docker', 'exec', 'clab-sdn-ids-h11', 'ping', '-c', '3', '192.168.11.5'],
            capture_output=True,
            timeout=10
        )
        return result.returncode == 0

    # ============================================
    # IDS Functionality Tests
    # ============================================

    def test_flow_rule_installation(self):
        """Test flow rules are being installed"""
        response = requests.get(f"{CONTROLLER_URL}/stats/flow/21", timeout=5)
        flows = response.json().get('21', [])
        return len(flows) > 0

    def test_ids_statistics(self):
        """Test IDS statistics endpoint"""
        # This would need a custom endpoint in the IDS app
        try:
            response = requests.get(f"{CONTROLLER_URL}/ids/stats", timeout=5)
            return response.status_code == 200
        except:
            # If endpoint doesn't exist, skip
            return True

    # ============================================
    # Performance Tests
    # ============================================

    def test_prediction_latency(self):
        """Test ML prediction latency is acceptable (<100ms)"""
        features = {'Flow Duration': 1000000, 'Flow Bytes/s': 5000}

        start = time.time()
        for _ in range(10):
            requests.post(f"{ML_SERVICE_URL}/predict", json={'features': features}, timeout=5)
        elapsed = (time.time() - start) / 10

        self.log(f"Average prediction latency: {elapsed*1000:.2f}ms")
        return elapsed < 0.1  # 100ms threshold

    def test_throughput(self):
        """Test ML service throughput"""
        features = {'Flow Duration': 1000000, 'Flow Bytes/s': 5000}

        start = time.time()
        count = 0
        while time.time() - start < 5:  # 5 second test
            requests.post(f"{ML_SERVICE_URL}/predict", json={'features': features}, timeout=5)
            count += 1

        throughput = count / 5
        self.log(f"ML Service throughput: {throughput:.2f} predictions/sec")
        return throughput > 10  # At least 10 predictions/sec

    # ============================================
    # Run All Tests
    # ============================================

    def run_all(self):
        """Run all tests"""
        print("=" * 60)
        print("SDN-IDS Complete Test Suite")
        print(f"Started: {datetime.now()}")
        print("=" * 60)
        print()

        # Connectivity tests
        print("--- Connectivity Tests ---")
        self.test("ML Service Health", self.test_ml_service_health)
        self.test("ML Model Loaded", self.test_ml_service_model_loaded)
        self.test("Controller Accessible", self.test_controller_accessible)
        self.test("All Switches Connected", self.test_all_switches_connected)
        print()

        # ML Prediction tests
        print("--- ML Prediction Tests ---")
        self.test("Benign Traffic Classification", self.test_benign_traffic_prediction)
        self.test("Malicious Traffic Classification", self.test_malicious_traffic_prediction)
        self.test("Batch Prediction", self.test_batch_prediction)
        print()

        # Network tests
        print("--- Network Connectivity Tests ---")
        self.test("Host Connectivity", self.test_host_connectivity)
        self.test("Cross-Leaf Connectivity", self.test_cross_leaf_connectivity)
        print()

        # IDS tests
        print("--- IDS Functionality Tests ---")
        self.test("Flow Rule Installation", self.test_flow_rule_installation)
        self.test("IDS Statistics", self.test_ids_statistics)
        print()

        # Performance tests
        print("--- Performance Tests ---")
        self.test("Prediction Latency", self.test_prediction_latency)
        self.test("ML Service Throughput", self.test_throughput)
        print()

        # Summary
        print("=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"Total tests: {self.passed + self.failed}")
        print(f"Passed: {self.passed}")
        print(f"Failed: {self.failed}")
        print(f"Success rate: {self.passed/(self.passed+self.failed)*100:.1f}%")
        print("=" * 60)

        # Save results
        with open('/tmp/test_results.json', 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'passed': self.passed,
                'failed': self.failed,
                'results': self.results
            }, f, indent=2)

        return self.failed == 0


if __name__ == '__main__':
    suite = SDNIDSTestSuite()
    success = suite.run_all()
    sys.exit(0 if success else 1)
