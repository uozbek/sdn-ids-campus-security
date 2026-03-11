#!/usr/bin/env python3
"""
==============================================================================
DENEY 3: FARKLI SALDIRI TÜRLERİ (Different Attack Types)
==============================================================================

Bu deney, farklı DDoS saldırı türlerinde IDS performansını ölçer:
- SYN Flood
- UDP Flood
- ICMP Flood
- HTTP Flood
- Slowloris
- DNS Amplification

CIC-DDoS2019 veri setindeki saldırı türlerini simüle eder.

Author: PhD Research - SDN Security
"""

import os
import sys
import json
import time
import random
import threading
import subprocess
import requests
import numpy as np
import pandas as pd
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List

# Configuration
ML_SERVICE_URL = "http://172.10.10.100:5000"
RESULTS_DIR = "/tmp/experiment_results/exp3_attack_types"

@dataclass
class AttackType:
    """Saldırı türü tanımı"""
    name: str
    description: str
    cic_label: str  # CIC-DDoS2019 etiketi
    feature_profile: Dict


class AttackTypesExperiment:
    """
    Deney 3: Farklı Saldırı Türleri Analizi

    CIC-DDoS2019 veri setindeki saldırı türleri:
    - DrDoS_DNS, DrDoS_LDAP, DrDoS_MSSQL, DrDoS_NetBIOS
    - DrDoS_NTP, DrDoS_SNMP, DrDoS_SSDP, DrDoS_UDP
    - Syn, TFTP, UDP, UDP-lag
    - WebDDoS
    """

    # Saldırı türleri ve karakteristik özellikleri
    ATTACK_PROFILES = {
        'SYN_Flood': {
            'description': 'TCP SYN Flood Attack',
            'cic_label': 'Syn',
            'features': {
                'Total Fwd Packets': (5000, 100000),
                'Total Backward Packets': (0, 10),
                'Flow Bytes/s': (100000, 10000000),
                'Flow Packets/s': (5000, 100000),
                'SYN Flag Count': (5000, 100000),
                'ACK Flag Count': (0, 10),
                'FIN Flag Count': (0, 5),
                'Fwd Packet Length Mean': (40, 80),
                'Flow IAT Mean': (0.1, 100),
                'Subflow Bwd Packets': (0, 5),
            }
        },
        'UDP_Flood': {
            'description': 'UDP Flood Attack',
            'cic_label': 'UDP',
            'features': {
                'Total Fwd Packets': (10000, 500000),
                'Total Backward Packets': (0, 50),
                'Flow Bytes/s': (500000, 50000000),
                'Flow Packets/s': (10000, 500000),
                'SYN Flag Count': (0, 0),
                'ACK Flag Count': (0, 0),
                'Fwd Packet Length Mean': (100, 1400),
                'Flow IAT Mean': (0.01, 50),
                'Average Packet Size': (100, 1400),
            }
        },
        'ICMP_Flood': {
            'description': 'ICMP Ping Flood',
            'cic_label': 'ICMP',
            'features': {
                'Total Fwd Packets': (1000, 50000),
                'Total Backward Packets': (0, 1000),
                'Flow Bytes/s': (50000, 5000000),
                'Flow Packets/s': (1000, 50000),
                'SYN Flag Count': (0, 0),
                'ACK Flag Count': (0, 0),
                'Fwd Packet Length Mean': (64, 1500),
                'Flow IAT Mean': (1, 1000),
            }
        },
        'HTTP_Flood': {
            'description': 'HTTP GET/POST Flood',
            'cic_label': 'WebDDoS',
            'features': {
                'Total Fwd Packets': (100, 10000),
                'Total Backward Packets': (50, 5000),
                'Flow Bytes/s': (10000, 1000000),
                'Flow Packets/s': (100, 10000),
                'SYN Flag Count': (100, 10000),
                'ACK Flag Count': (200, 20000),
                'PSH Flag Count': (100, 10000),
                'Fwd Packet Length Mean': (200, 1000),
                'Flow IAT Mean': (10, 1000),
            }
        },
        'Slowloris': {
            'description': 'Slow HTTP DoS',
            'cic_label': 'Slowloris',
            'features': {
                'Total Fwd Packets': (10, 500),
                'Total Backward Packets': (5, 200),
                'Flow Duration': (10000000, 100000000),  # Long duration
                'Flow Bytes/s': (10, 1000),  # Low bandwidth
                'Flow Packets/s': (0.1, 10),  # Low packet rate
                'SYN Flag Count': (1, 10),
                'ACK Flag Count': (10, 500),
                'Flow IAT Mean': (1000000, 30000000),  # Long intervals
            }
        },
        'DNS_Amplification': {
            'description': 'DNS Amplification DDoS',
            'cic_label': 'DrDoS_DNS',
            'features': {
                'Total Fwd Packets': (100, 10000),
                'Total Backward Packets': (100, 10000),
                'Flow Bytes/s': (100000, 50000000),
                'Flow Packets/s': (100, 10000),
                'Bwd Packet Length Mean': (500, 4000),  # Large responses
                'Fwd Packet Length Mean': (40, 100),  # Small queries
                'Flow IAT Mean': (100, 10000),
            }
        },
        'NTP_Amplification': {
            'description': 'NTP Amplification DDoS',
            'cic_label': 'DrDoS_NTP',
            'features': {
                'Total Fwd Packets': (100, 5000),
                'Total Backward Packets': (100, 5000),
                'Flow Bytes/s': (500000, 100000000),
                'Bwd Packet Length Mean': (200, 500),
                'Fwd Packet Length Mean': (40, 100),
            }
        },
        'SSDP_Amplification': {
            'description': 'SSDP Amplification DDoS',
            'cic_label': 'DrDoS_SSDP',
            'features': {
                'Total Fwd Packets': (100, 10000),
                'Total Backward Packets': (100, 10000),
                'Flow Bytes/s': (100000, 20000000),
                'Bwd Packet Length Mean': (300, 3000),
            }
        }
    }

    def __init__(self):
        self.results = {
            'experiment_name': 'Attack Types Analysis',
            'start_time': None,
            'end_time': None,
            'config': {},
            'attack_results': {},
            'summary': {}
        }

        os.makedirs(RESULTS_DIR, exist_ok=True)

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] [{level}] {message}")

    def generate_benign_features(self):
        """Normal trafik özellikleri"""
        return {
            'Flow Duration': random.uniform(100000, 10000000),
            'Total Fwd Packets': random.randint(5, 100),
            'Total Backward Packets': random.randint(3, 80),
            'Total Length of Fwd Packets': random.randint(500, 50000),
            'Total Length of Bwd Packets': random.randint(300, 40000),
            'Fwd Packet Length Max': random.randint(500, 1500),
            'Fwd Packet Length Min': random.randint(40, 100),
            'Fwd Packet Length Mean': random.uniform(200, 800),
            'Bwd Packet Length Max': random.randint(500, 1500),
            'Bwd Packet Length Min': random.randint(40, 100),
            'Bwd Packet Length Mean': random.uniform(200, 800),
            'Flow Bytes/s': random.uniform(1000, 100000),
            'Flow Packets/s': random.uniform(10, 500),
            'Flow IAT Mean': random.uniform(1000, 100000),
            'Flow IAT Max': random.uniform(10000, 500000),
            'Flow IAT Min': random.uniform(100, 10000),
            'Fwd IAT Total': random.uniform(10000, 1000000),
            'Fwd IAT Mean': random.uniform(1000, 50000),
            'Fwd IAT Max': random.uniform(5000, 200000),
            'Bwd IAT Total': random.uniform(10000, 1000000),
            'Bwd IAT Mean': random.uniform(1000, 50000),
            'PSH Flag Count': random.randint(1, 20),
            'ACK Flag Count': random.randint(5, 100),
            'URG Flag Count': 0,
            'SYN Flag Count': random.randint(1, 3),
            'RST Flag Count': random.randint(0, 2),
            'FIN Flag Count': random.randint(1, 3),
            'Subflow Fwd Packets': random.randint(5, 50),
            'Subflow Fwd Bytes': random.randint(500, 25000),
            'Subflow Bwd Packets': random.randint(3, 40),
            'Subflow Bwd Bytes': random.randint(300, 20000),
            'Init_Win_bytes_forward': random.randint(8000, 65535),
            'Init_Win_bytes_backward': random.randint(8000, 65535),
            'Average Packet Size': random.uniform(200, 1000),
            'Packet Length Max': random.randint(500, 1500),
            'Packet Length Min': random.randint(40, 100),
            'Packet Length Mean': random.uniform(200, 800),
            'Idle Mean': random.uniform(10000, 500000),
        }

    def generate_attack_features(self, attack_type):
        """Belirli saldırı türü için özellik üret"""
        profile = self.ATTACK_PROFILES.get(attack_type, {}).get('features', {})

        # Start with benign baseline
        features = self.generate_benign_features()

        # Override with attack characteristics
        for feature_name, (min_val, max_val) in profile.items():
            if isinstance(min_val, int) and isinstance(max_val, int):
                features[feature_name] = random.randint(min_val, max_val)
            else:
                features[feature_name] = random.uniform(min_val, max_val)

        return features

    def query_ml_service(self, features):
        """ML servisine sorgu"""
        try:
            response = requests.post(
                f"{ML_SERVICE_URL}/predict",
                json={'features': features},
                timeout=5
            )
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            self.log(f"ML error: {e}", "ERROR")
        return None

    def test_attack_type(self, attack_type, num_samples=200):
        """Tek bir saldırı türünü test et"""
        self.log(f"Testing attack type: {attack_type}")

        profile = self.ATTACK_PROFILES.get(attack_type, {})

        results = {
            'attack_type': attack_type,
            'description': profile.get('description', ''),
            'cic_label': profile.get('cic_label', ''),
            'samples': num_samples,
            'true_positive': 0,
            'false_negative': 0,
            'predictions': [],
            'confidences': []
        }

        for i in range(num_samples):
            features = self.generate_attack_features(attack_type)
            result = self.query_ml_service(features)

            if result:
                prediction = result.get('prediction', -1)
                confidence = result.get('confidence', 0)

                results['predictions'].append(prediction)
                results['confidences'].append(confidence)

                if prediction == 1:  # Correctly detected
                    results['true_positive'] += 1
                else:  # Missed
                    results['false_negative'] += 1

        # Calculate metrics
        total = results['true_positive'] + results['false_negative']
        results['detection_rate'] = (results['true_positive'] / total * 100) if total > 0 else 0
        results['miss_rate'] = (results['false_negative'] / total * 100) if total > 0 else 0
        results['avg_confidence'] = np.mean(results['confidences']) if results['confidences'] else 0

        self.log(f"  Detection Rate: {results['detection_rate']:.2f}%")
        self.log(f"  Avg Confidence: {results['avg_confidence']:.2f}")

        return results

    def test_benign_baseline(self, num_samples=500):
        """Normal trafik için FPR ölç"""
        self.log("Testing benign traffic baseline...")

        results = {
            'samples': num_samples,
            'true_negative': 0,
            'false_positive': 0,
            'predictions': [],
            'confidences': []
        }

        for i in range(num_samples):
            features = self.generate_benign_features()
            result = self.query_ml_service(features)

            if result:
                prediction = result.get('prediction', -1)
                confidence = result.get('confidence', 0)

                results['predictions'].append(prediction)
                results['confidences'].append(confidence)

                if prediction == 0:  # Correctly classified as benign
                    results['true_negative'] += 1
                else:  # False alarm
                    results['false_positive'] += 1

        total = results['true_negative'] + results['false_positive']
        results['specificity'] = (results['true_negative'] / total * 100) if total > 0 else 0
        results['fpr'] = (results['false_positive'] / total * 100) if total > 0 else 0

        self.log(f"  Specificity: {results['specificity']:.2f}%")
        self.log(f"  False Positive Rate: {results['fpr']:.2f}%")

        return results

    def run_experiment(self, config=None):
        """Ana deney prosedürü"""
        if config is None:
            config = {
                'attack_samples': 200,
                'benign_samples': 500,
                'attack_types': list(self.ATTACK_PROFILES.keys())
            }

        self.results['config'] = config
        self.results['start_time'] = datetime.now().isoformat()

        self.log("=" * 60)
        self.log("DENEY 3: FARKLI SALDIRI TÜRLERİ")
        self.log("=" * 60)
        self.log(f"Attack types to test: {len(config['attack_types'])}")
        self.log(f"Samples per attack: {config['attack_samples']}")
        self.log("=" * 60)

        # Test benign baseline first
        self.log("\n[0/{0}] Testing Benign Baseline".format(len(config['attack_types'])))
        benign_results = self.test_benign_baseline(config['benign_samples'])
        self.results['attack_results']['BENIGN'] = benign_results

        # Test each attack type
        for idx, attack_type in enumerate(config['attack_types'], 1):
            self.log(f"\n[{idx}/{len(config['attack_types'])}] Testing {attack_type}")
            attack_results = self.test_attack_type(attack_type, config['attack_samples'])
            self.results['attack_results'][attack_type] = attack_results

        # Generate summary
        self.generate_summary()

        self.results['end_time'] = datetime.now().isoformat()

        self.print_results()
        self.save_results()

        return self.results

    def generate_summary(self):
        """Özet istatistikler"""
        attack_results = self.results['attack_results']

        detection_rates = []
        for attack_type, results in attack_results.items():
            if attack_type != 'BENIGN':
                detection_rates.append(results.get('detection_rate', 0))

        self.results['summary'] = {
            'total_attack_types': len(detection_rates),
            'avg_detection_rate': np.mean(detection_rates) if detection_rates else 0,
            'min_detection_rate': min(detection_rates) if detection_rates else 0,
            'max_detection_rate': max(detection_rates) if detection_rates else 0,
            'benign_fpr': attack_results.get('BENIGN', {}).get('fpr', 0),
            'best_detected': max(attack_results.items(),
                                key=lambda x: x[1].get('detection_rate', 0) if x[0] != 'BENIGN' else 0)[0],
            'worst_detected': min((k, v) for k, v in attack_results.items() if k != 'BENIGN',
                                 key=lambda x: x[1].get('detection_rate', 100))[0]
        }

    def print_results(self):
        """Sonuçları yazdır"""
        print("\n" + "=" * 70)
        print("DENEY SONUÇLARI: FARKLI SALDIRI TÜRLERİ")
        print("=" * 70)

        print("\n{:<25} {:>12} {:>12} {:>12}".format(
            "Attack Type", "DR (%)", "Miss (%)", "Avg Conf"
        ))
        print("-" * 70)

        for attack_type, results in self.results['attack_results'].items():
            if attack_type == 'BENIGN':
                print(f"{'BENIGN':<25} {'N/A':>12} {'FPR: ' + str(round(results.get('fpr', 0), 1)):>12} "
                      f"{results.get('avg_confidence', 0):>12.2f}")
            else:
                print(f"{attack_type:<25} {results.get('detection_rate', 0):>12.1f} "
                      f"{results.get('miss_rate', 0):>12.1f} {results.get('avg_confidence', 0):>12.2f}")

        print("-" * 70)
        summary = self.results['summary']
        print(f"\nÖzet:")
        print(f"  Ortalama Detection Rate: {summary.get('avg_detection_rate', 0):.2f}%")
        print(f"  En İyi Tespit: {summary.get('best_detected', 'N/A')}")
        print(f"  En Kötü Tespit: {summary.get('worst_detected', 'N/A')}")
        print(f"  False Positive Rate: {summary.get('benign_fpr', 0):.2f}%")
        print("=" * 70)

    def save_results(self):
        """Sonuçları kaydet"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # JSON
        json_file = f"{RESULTS_DIR}/exp3_results_{timestamp}.json"
        with open(json_file, 'w') as f:
            # Remove raw lists for JSON
            results_copy = json.loads(json.dumps(self.results, default=str))
            for attack in results_copy.get('attack_results', {}).values():
                attack.pop('predictions', None)
                attack.pop('confidences', None)
            json.dump(results_copy, f, indent=2)
        self.log(f"Results saved to: {json_file}")

        # CSV summary
        csv_data = []
        for attack_type, results in self.results['attack_results'].items():
            csv_data.append({
                'attack_type': attack_type,
                'detection_rate': results.get('detection_rate', results.get('specificity', 0)),
                'miss_rate': results.get('miss_rate', results.get('fpr', 0)),
                'avg_confidence': results.get('avg_confidence', 0),
                'samples': results.get('samples', 0)
            })

        df = pd.DataFrame(csv_data)
        csv_file = f"{RESULTS_DIR}/exp3_summary_{timestamp}.csv"
        df.to_csv(csv_file, index=False)
        self.log(f"Summary saved to: {csv_file}")


def main():
    experiment = AttackTypesExperiment()

    config = {
        'attack_samples': 200,
        'benign_samples': 500,
        'attack_types': [
            'SYN_Flood',
            'UDP_Flood',
            'ICMP_Flood',
            'HTTP_Flood',
            'Slowloris',
            'DNS_Amplification',
            'NTP_Amplification',
            'SSDP_Amplification'
        ]
    }

    results = experiment.run_experiment(config)

    # Success: avg detection rate > 85%
    return 0 if results['summary'].get('avg_detection_rate', 0) > 85 else 1


if __name__ == '__main__':
    sys.exit(main())
