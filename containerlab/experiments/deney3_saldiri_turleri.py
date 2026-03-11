#!/usr/bin/env python3
"""
============================================
Deney 3: Farklı Saldırı Türleri Analizi
============================================

Bu deney, farklı DDoS saldırı türlerinin tespit performansını ölçer:
- SYN Flood
- UDP Flood
- HTTP Flood
- ICMP Flood
- Slowloris
- DNS Amplification

Author: PhD Research - SDN Security
"""

import requests
import time
import json
import csv
import random
import statistics
import os
from datetime import datetime
from collections import defaultdict

# Configuration
ML_SERVICE_URL = "http://172.10.10.100:5000"
RESULTS_DIR = "/tmp/experiment_results"
EXPERIMENT_NAME = "deney3_saldiri_turleri"

# Test parameters
SAMPLES_PER_ATTACK = 200


class AttackTypeExperiment:
    """Deney 3: Farklı Saldırı Türleri Analizi"""

    def __init__(self):
        self.results = defaultdict(lambda: {
            'true_positive': 0,
            'false_negative': 0,
            'predictions': [],
            'confidences': [],
            'latencies': []
        })
        os.makedirs(RESULTS_DIR, exist_ok=True)

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] [{level}] {message}")

    # ============================================
    # Attack Feature Generators (CIC-DDoS2019 Format)
    # ============================================

    def generate_syn_flood(self):
        """SYN Flood Attack Features"""
        return {
            'Flow Duration': random.uniform(500, 30000),
            'Total Fwd Packets': random.randint(5000, 100000),
            'Total Backward Packets': random.randint(0, 50),
            'Total Length of Fwd Packets': random.randint(200000, 5000000),
            'Total Length of Bwd Packets': random.randint(0, 2000),

            'Fwd Packet Length Max': random.randint(40, 60),
            'Fwd Packet Length Min': 40,
            'Fwd Packet Length Mean': random.uniform(40, 55),
            'Bwd Packet Length Max': random.randint(0, 60),
            'Bwd Packet Length Min': 0,
            'Bwd Packet Length Mean': 0,
            'Packet Length Max': random.randint(40, 60),
            'Packet Length Min': 40,
            'Packet Length Mean': random.uniform(40, 55),
            'Packet Length Variance': random.uniform(0, 50),

            'Flow Bytes/s': random.uniform(1000000, 50000000),
            'Flow Packets/s': random.uniform(50000, 500000),

            'Flow IAT Mean': random.uniform(0.5, 20),
            'Flow IAT Max': random.uniform(10, 200),
            'Flow IAT Min': random.uniform(0, 5),
            'Fwd IAT Total': random.uniform(50, 5000),
            'Fwd IAT Mean': random.uniform(0.5, 15),
            'Fwd IAT Max': random.uniform(5, 100),
            'Bwd IAT Total': 0,
            'Bwd IAT Mean': 0,

            'PSH Flag Count': 0,
            'ACK Flag Count': random.randint(0, 100),
            'URG Flag Count': 0,
            'SYN Flag Count': random.randint(5000, 100000),
            'RST Flag Count': random.randint(0, 500),
            'FIN Flag Count': 0,

            'Subflow Fwd Packets': random.randint(5000, 100000),
            'Subflow Fwd Bytes': random.randint(200000, 5000000),
            'Subflow Bwd Packets': random.randint(0, 50),
            'Subflow Bwd Bytes': random.randint(0, 2000),

            'Init_Win_bytes_forward': random.randint(512, 4096),
            'Init_Win_bytes_backward': 0,

            'min_seg_size_forward': 40,
            'Average Packet Size': random.uniform(40, 55),
            'Avg Fwd Segment Size': random.uniform(40, 55),
            'Avg Bwd Segment Size': 0,

            'Idle Mean': random.uniform(0, 50),
            'Idle Max': random.uniform(10, 200),
            'Idle Min': 0,
            'Active Mean': random.uniform(0, 30),
        }

    def generate_udp_flood(self):
        """UDP Flood Attack Features"""
        return {
            'Flow Duration': random.uniform(1000, 100000),
            'Total Fwd Packets': random.randint(10000, 200000),
            'Total Backward Packets': random.randint(0, 100),
            'Total Length of Fwd Packets': random.randint(1000000, 50000000),
            'Total Length of Bwd Packets': random.randint(0, 5000),

            'Fwd Packet Length Max': random.randint(500, 1400),
            'Fwd Packet Length Min': random.randint(64, 200),
            'Fwd Packet Length Mean': random.uniform(200, 800),
            'Bwd Packet Length Max': random.randint(0, 100),
            'Bwd Packet Length Min': 0,
            'Bwd Packet Length Mean': 0,
            'Packet Length Max': random.randint(500, 1400),
            'Packet Length Min': random.randint(64, 200),
            'Packet Length Mean': random.uniform(200, 800),
            'Packet Length Variance': random.uniform(10000, 100000),

            'Flow Bytes/s': random.uniform(5000000, 100000000),
            'Flow Packets/s': random.uniform(100000, 1000000),

            'Flow IAT Mean': random.uniform(0.1, 10),
            'Flow IAT Max': random.uniform(5, 100),
            'Flow IAT Min': random.uniform(0, 2),
            'Fwd IAT Total': random.uniform(100, 10000),
            'Fwd IAT Mean': random.uniform(0.1, 5),
            'Fwd IAT Max': random.uniform(5, 50),
            'Bwd IAT Total': 0,
            'Bwd IAT Mean': 0,

            # UDP has no TCP flags
            'PSH Flag Count': 0,
            'ACK Flag Count': 0,
            'URG Flag Count': 0,
            'SYN Flag Count': 0,
            'RST Flag Count': 0,
            'FIN Flag Count': 0,

            'Subflow Fwd Packets': random.randint(10000, 200000),
            'Subflow Fwd Bytes': random.randint(1000000, 50000000),
            'Subflow Bwd Packets': random.randint(0, 100),
            'Subflow Bwd Bytes': random.randint(0, 5000),

            'Init_Win_bytes_forward': 0,
            'Init_Win_bytes_backward': 0,

            'min_seg_size_forward': random.randint(64, 200),
            'Average Packet Size': random.uniform(200, 800),
            'Avg Fwd Segment Size': random.uniform(200, 800),
            'Avg Bwd Segment Size': 0,

            'Idle Mean': random.uniform(0, 20),
            'Idle Max': random.uniform(5, 100),
            'Idle Min': 0,
            'Active Mean': random.uniform(0, 10),
        }

    def generate_http_flood(self):
        """HTTP Flood Attack Features"""
        return {
            'Flow Duration': random.uniform(10000, 300000),
            'Total Fwd Packets': random.randint(1000, 20000),
            'Total Backward Packets': random.randint(500, 10000),
            'Total Length of Fwd Packets': random.randint(200000, 4000000),
            'Total Length of Bwd Packets': random.randint(100000, 2000000),

            'Fwd Packet Length Max': random.randint(200, 600),
            'Fwd Packet Length Min': random.randint(40, 100),
            'Fwd Packet Length Mean': random.uniform(100, 400),
            'Bwd Packet Length Max': random.randint(500, 1460),
            'Bwd Packet Length Min': random.randint(40, 100),
            'Bwd Packet Length Mean': random.uniform(200, 700),
            'Packet Length Max': random.randint(500, 1460),
            'Packet Length Min': random.randint(40, 100),
            'Packet Length Mean': random.uniform(150, 500),
            'Packet Length Variance': random.uniform(5000, 80000),

            'Flow Bytes/s': random.uniform(500000, 10000000),
            'Flow Packets/s': random.uniform(5000, 100000),

            'Flow IAT Mean': random.uniform(5, 200),
            'Flow IAT Max': random.uniform(50, 1000),
            'Flow IAT Min': random.uniform(0.5, 20),
            'Fwd IAT Total': random.uniform(1000, 100000),
            'Fwd IAT Mean': random.uniform(5, 100),
            'Fwd IAT Max': random.uniform(50, 500),
            'Bwd IAT Total': random.uniform(500, 50000),
            'Bwd IAT Mean': random.uniform(3, 80),

            'PSH Flag Count': random.randint(1000, 20000),
            'ACK Flag Count': random.randint(2000, 40000),
            'URG Flag Count': 0,
            'SYN Flag Count': random.randint(1000, 20000),
            'RST Flag Count': random.randint(0, 1000),
            'FIN Flag Count': random.randint(0, 1000),

            'Subflow Fwd Packets': random.randint(1000, 20000),
            'Subflow Fwd Bytes': random.randint(200000, 4000000),
            'Subflow Bwd Packets': random.randint(500, 10000),
            'Subflow Bwd Bytes': random.randint(100000, 2000000),

            'Init_Win_bytes_forward': random.randint(4096, 16384),
            'Init_Win_bytes_backward': random.randint(8192, 65535),

            'min_seg_size_forward': random.randint(20, 60),
            'Average Packet Size': random.uniform(150, 500),
            'Avg Fwd Segment Size': random.uniform(100, 400),
            'Avg Bwd Segment Size': random.uniform(200, 700),

            'Idle Mean': random.uniform(50, 500),
            'Idle Max': random.uniform(200, 2000),
            'Idle Min': random.uniform(5, 50),
            'Active Mean': random.uniform(30, 300),
        }

    def generate_icmp_flood(self):
        """ICMP Flood Attack Features"""
        return {
            'Flow Duration': random.uniform(1000, 50000),
            'Total Fwd Packets': random.randint(5000, 50000),
            'Total Backward Packets': random.randint(0, 5000),
            'Total Length of Fwd Packets': random.randint(500000, 5000000),
            'Total Length of Bwd Packets': random.randint(0, 500000),

            'Fwd Packet Length Max': random.randint(64, 1500),
            'Fwd Packet Length Min': 64,
            'Fwd Packet Length Mean': random.uniform(64, 800),
            'Bwd Packet Length Max': random.randint(0, 1500),
            'Bwd Packet Length Min': 0,
            'Bwd Packet Length Mean': random.uniform(0, 400),
            'Packet Length Max': random.randint(64, 1500),
            'Packet Length Min': 64,
            'Packet Length Mean': random.uniform(64, 600),
            'Packet Length Variance': random.uniform(5000, 200000),

            'Flow Bytes/s': random.uniform(1000000, 20000000),
            'Flow Packets/s': random.uniform(20000, 200000),

            'Flow IAT Mean': random.uniform(1, 50),
            'Flow IAT Max': random.uniform(10, 200),
            'Flow IAT Min': random.uniform(0, 10),
            'Fwd IAT Total': random.uniform(100, 10000),
            'Fwd IAT Mean': random.uniform(1, 30),
            'Fwd IAT Max': random.uniform(10, 150),
            'Bwd IAT Total': random.uniform(0, 5000),
            'Bwd IAT Mean': random.uniform(0, 20),

            # ICMP has no TCP flags
            'PSH Flag Count': 0,
            'ACK Flag Count': 0,
            'URG Flag Count': 0,
            'SYN Flag Count': 0,
            'RST Flag Count': 0,
            'FIN Flag Count': 0,

            'Subflow Fwd Packets': random.randint(5000, 50000),
            'Subflow Fwd Bytes': random.randint(500000, 5000000),
            'Subflow Bwd Packets': random.randint(0, 5000),
            'Subflow Bwd Bytes': random.randint(0, 500000),

            'Init_Win_bytes_forward': 0,
            'Init_Win_bytes_backward': 0,

            'min_seg_size_forward': 64,
            'Average Packet Size': random.uniform(64, 600),
            'Avg Fwd Segment Size': random.uniform(64, 800),
            'Avg Bwd Segment Size': random.uniform(0, 400),

            'Idle Mean': random.uniform(10, 100),
            'Idle Max': random.uniform(50, 500),
            'Idle Min': random.uniform(0, 20),
            'Active Mean': random.uniform(5, 50),
        }

    def generate_slowloris(self):
        """Slowloris Attack Features"""
        return {
            'Flow Duration': random.uniform(1000000, 10000000),  # Very long duration
            'Total Fwd Packets': random.randint(50, 500),
            'Total Backward Packets': random.randint(10, 200),
            'Total Length of Fwd Packets': random.randint(5000, 50000),
            'Total Length of Bwd Packets': random.randint(1000, 20000),

            'Fwd Packet Length Max': random.randint(50, 200),
            'Fwd Packet Length Min': random.randint(20, 50),
            'Fwd Packet Length Mean': random.uniform(30, 100),
            'Bwd Packet Length Max': random.randint(100, 500),
            'Bwd Packet Length Min': random.randint(40, 100),
            'Bwd Packet Length Mean': random.uniform(60, 200),
            'Packet Length Max': random.randint(100, 500),
            'Packet Length Min': random.randint(20, 50),
            'Packet Length Mean': random.uniform(40, 150),
            'Packet Length Variance': random.uniform(500, 10000),

            'Flow Bytes/s': random.uniform(10, 500),  # Very low rate
            'Flow Packets/s': random.uniform(0.1, 5),  # Very low rate

            'Flow IAT Mean': random.uniform(100000, 1000000),  # Very long intervals
            'Flow IAT Max': random.uniform(500000, 5000000),
            'Flow IAT Min': random.uniform(50000, 200000),
            'Fwd IAT Total': random.uniform(500000, 5000000),
            'Fwd IAT Mean': random.uniform(100000, 500000),
            'Fwd IAT Max': random.uniform(200000, 2000000),
            'Bwd IAT Total': random.uniform(200000, 2000000),
            'Bwd IAT Mean': random.uniform(50000, 300000),

            'PSH Flag Count': random.randint(20, 200),
            'ACK Flag Count': random.randint(50, 400),
            'URG Flag Count': 0,
            'SYN Flag Count': random.randint(1, 10),
            'RST Flag Count': 0,
            'FIN Flag Count': 0,

            'Subflow Fwd Packets': random.randint(50, 500),
            'Subflow Fwd Bytes': random.randint(5000, 50000),
            'Subflow Bwd Packets': random.randint(10, 200),
            'Subflow Bwd Bytes': random.randint(1000, 20000),

            'Init_Win_bytes_forward': random.randint(8192, 65535),
            'Init_Win_bytes_backward': random.randint(8192, 65535),

            'min_seg_size_forward': random.randint(20, 50),
            'Average Packet Size': random.uniform(40, 150),
            'Avg Fwd Segment Size': random.uniform(30, 100),
            'Avg Bwd Segment Size': random.uniform(60, 200),

            'Idle Mean': random.uniform(100000, 500000),
            'Idle Max': random.uniform(500000, 2000000),
            'Idle Min': random.uniform(50000, 200000),
            'Active Mean': random.uniform(50000, 200000),
        }

    def generate_dns_amplification(self):
        """DNS Amplification Attack Features"""
        return {
            'Flow Duration': random.uniform(1000, 100000),
            'Total Fwd Packets': random.randint(100, 5000),
            'Total Backward Packets': random.randint(100, 50000),  # Amplified responses
            'Total Length of Fwd Packets': random.randint(5000, 200000),
            'Total Length of Bwd Packets': random.randint(500000, 50000000),  # Amplified

            'Fwd Packet Length Max': random.randint(60, 100),
            'Fwd Packet Length Min': random.randint(40, 60),
            'Fwd Packet Length Mean': random.uniform(50, 80),
            'Bwd Packet Length Max': random.randint(3000, 4096),  # Large DNS responses
            'Bwd Packet Length Min': random.randint(100, 500),
            'Bwd Packet Length Mean': random.uniform(1000, 3000),
            'Packet Length Max': random.randint(3000, 4096),
            'Packet Length Min': random.randint(40, 60),
            'Packet Length Mean': random.uniform(500, 1500),
            'Packet Length Variance': random.uniform(500000, 5000000),

            'Flow Bytes/s': random.uniform(5000000, 100000000),
            'Flow Packets/s': random.uniform(10000, 100000),

            'Flow IAT Mean': random.uniform(1, 100),
            'Flow IAT Max': random.uniform(10, 500),
            'Flow IAT Min': random.uniform(0, 10),
            'Fwd IAT Total': random.uniform(100, 10000),
            'Fwd IAT Mean': random.uniform(1, 50),
            'Fwd IAT Max': random.uniform(10, 200),
            'Bwd IAT Total': random.uniform(100, 50000),
            'Bwd IAT Mean': random.uniform(1, 100),

            # DNS uses UDP - no TCP flags
            'PSH Flag Count': 0,
            'ACK Flag Count': 0,
            'URG Flag Count': 0,
            'SYN Flag Count': 0,
            'RST Flag Count': 0,
            'FIN Flag Count': 0,

            'Subflow Fwd Packets': random.randint(100, 5000),
            'Subflow Fwd Bytes': random.randint(5000, 200000),
            'Subflow Bwd Packets': random.randint(100, 50000),
            'Subflow Bwd Bytes': random.randint(500000, 50000000),

            'Init_Win_bytes_forward': 0,
            'Init_Win_bytes_backward': 0,

            'min_seg_size_forward': random.randint(40, 60),
            'Average Packet Size': random.uniform(500, 1500),
            'Avg Fwd Segment Size': random.uniform(50, 80),
            'Avg Bwd Segment Size': random.uniform(1000, 3000),

            'Idle Mean': random.uniform(10, 200),
            'Idle Max': random.uniform(50, 1000),
            'Idle Min': random.uniform(0, 20),
            'Active Mean': random.uniform(5, 100),
        }

    # ============================================
    # Attack Type Mapping
    # ============================================

    def get_attack_generator(self, attack_type):
        """Saldırı tipine göre generator döndür"""
        generators = {
            'SYN Flood': self.generate_syn_flood,
            'UDP Flood': self.generate_udp_flood,
            'HTTP Flood': self.generate_http_flood,
            'ICMP Flood': self.generate_icmp_flood,
            'Slowloris': self.generate_slowloris,
            'DNS Amplification': self.generate_dns_amplification,
        }
        return generators.get(attack_type)

    # ============================================
    # Test Execution
    # ============================================

    def test_attack_type(self, attack_type, num_samples):
        """Belirli bir saldırı tipini test et"""
        self.log(f"Testing {attack_type} ({num_samples} samples)...")

        generator = self.get_attack_generator(attack_type)
        if not generator:
            self.log(f"Unknown attack type: {attack_type}", "ERROR")
            return

        for i in range(num_samples):
            features = generator()

            start_time = time.perf_counter()

            try:
                response = requests.post(
                    f"{ML_SERVICE_URL}/predict",
                    json={'features': features},
                    timeout=5
                )

                latency = (time.perf_counter() - start_time) * 1000

                if response.status_code == 200:
                    result = response.json()
                    prediction = result.get('prediction', -1)
                    confidence = result.get('confidence', 0)

                    if prediction == 1:
                        self.results[attack_type]['true_positive'] += 1
                    else:
                        self.results[attack_type]['false_negative'] += 1

                    self.results[attack_type]['predictions'].append(prediction)
                    self.results[attack_type]['confidences'].append(confidence)
                    self.results[attack_type]['latencies'].append(latency)

            except Exception as e:
                self.log(f"Request failed: {e}", "ERROR")

            if (i + 1) % 50 == 0:
                tp = self.results[attack_type]['true_positive']
                total = tp + self.results[attack_type]['false_negative']
                rate = tp / total * 100 if total > 0 else 0
                self.log(f"  {attack_type}: {i + 1}/{num_samples} (DR: {rate:.1f}%)")

    # ============================================
    # Calculate Metrics
    # ============================================

    def calculate_metrics(self):
        """Her saldırı tipi için metrikleri hesapla"""
        metrics = {}

        for attack_type, data in self.results.items():
            tp = data['true_positive']
            fn = data['false_negative']
            total = tp + fn

            detection_rate = tp / total if total > 0 else 0
            miss_rate = fn / total if total > 0 else 0

            confidences = data['confidences']
            latencies = data['latencies']

            metrics[attack_type] = {
                'total_samples': total,
                'true_positive': tp,
                'false_negative': fn,
                'detection_rate': detection_rate,
                'miss_rate': miss_rate,
                'avg_confidence': statistics.mean(confidences) if confidences else 0,
                'std_confidence': statistics.stdev(confidences) if len(confidences) > 1 else 0,
                'avg_latency_ms': statistics.mean(latencies) if latencies else 0,
                'std_latency_ms': statistics.stdev(latencies) if len(latencies) > 1 else 0,
            }

        return metrics

    # ============================================
    # Generate Report
    # ============================================

    def generate_report(self, metrics):
        """Detaylı rapor oluştur"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{RESULTS_DIR}/{EXPERIMENT_NAME}_{timestamp}.txt"

        report = []
        report.append("=" * 80)
        report.append("DENEY 3: FARKLI SALDIRI TÜRLERİ ANALİZİ")
        report.append("Different Attack Types Analysis Report")
        report.append("=" * 80)
        report.append(f"Tarih/Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"ML Service: {ML_SERVICE_URL}")
        report.append("")

        # Summary Table
        report.append("-" * 80)
        report.append("ÖZET TABLO / SUMMARY TABLE")
        report.append("-" * 80)
        report.append(f"{'Saldırı Tipi':<20} {'Tespit Oranı':<15} {'TP':<8} {'FN':<8} {'Güven':<12} {'Gecikme':<12}")
        report.append("-" * 80)

        for attack_type, data in metrics.items():
            dr = f"{data['detection_rate']*100:.2f}%"
            conf = f"{data['avg_confidence']*100:.1f}%"
            lat = f"{data['avg_latency_ms']:.2f}ms"
            report.append(f"{attack_type:<20} {dr:<15} {data['true_positive']:<8} {data['false_negative']:<8} {conf:<12} {lat:<12}")

        report.append("")

        # Detailed Results per Attack Type
        for attack_type, data in metrics.items():
            report.append("-" * 80)
            report.append(f"SALDIRI TİPİ: {attack_type}")
            report.append("-" * 80)
            report.append(f"Toplam Örnek:            {data['total_samples']}")
            report.append(f"Doğru Tespit (TP):       {data['true_positive']}")
            report.append(f"Kaçırılan (FN):          {data['false_negative']}")
            report.append(f"Tespit Oranı (DR):       {data['detection_rate']*100:.2f}%")
            report.append(f"Kaçırma Oranı:           {data['miss_rate']*100:.2f}%")
            report.append(f"Ort. Güven Skoru:        {data['avg_confidence']*100:.2f}%")
            report.append(f"Güven Std Sapma:         {data['std_confidence']*100:.2f}%")
            report.append(f"Ort. Gecikme:            {data['avg_latency_ms']:.2f} ms")
            report.append(f"Gecikme Std Sapma:       {data['std_latency_ms']:.2f} ms")
            report.append("")

        # Overall Statistics
        report.append("-" * 80)
        report.append("GENEL İSTATİSTİKLER / OVERALL STATISTICS")
        report.append("-" * 80)

        total_tp = sum(m['true_positive'] for m in metrics.values())
        total_fn = sum(m['false_negative'] for m in metrics.values())
        total_samples = total_tp + total_fn
        overall_dr = total_tp / total_samples if total_samples > 0 else 0

        report.append(f"Toplam Test Örneği:      {total_samples}")
        report.append(f"Toplam Doğru Tespit:     {total_tp}")
        report.append(f"Toplam Kaçırılan:        {total_fn}")
        report.append(f"Genel Tespit Oranı:      {overall_dr*100:.2f}%")

        # Best/Worst performing attacks
        sorted_by_dr = sorted(metrics.items(), key=lambda x: x[1]['detection_rate'], reverse=True)
        report.append(f"\nEn İyi Tespit:           {sorted_by_dr[0][0]} ({sorted_by_dr[0][1]['detection_rate']*100:.2f}%)")
        report.append(f"En Düşük Tespit:         {sorted_by_dr[-1][0]} ({sorted_by_dr[-1][1]['detection_rate']*100:.2f}%)")

        report.append("")
        report.append("=" * 80)
        report.append("DENEY TAMAMLANDI / EXPERIMENT COMPLETED")
        report.append("=" * 80)

        report_text = "\n".join(report)
        print(report_text)

        # Save files
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_text)

        json_file = f"{RESULTS_DIR}/{EXPERIMENT_NAME}_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump({
                'experiment': EXPERIMENT_NAME,
                'timestamp': timestamp,
                'metrics': metrics
            }, f, indent=2)

        # Save CSV
        csv_file = f"{RESULTS_DIR}/{EXPERIMENT_NAME}_{timestamp}.csv"
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Attack Type', 'Detection Rate', 'TP', 'FN', 'Avg Confidence', 'Avg Latency'])
            for attack_type, data in metrics.items():
                writer.writerow([
                    attack_type,
                    f"{data['detection_rate']*100:.2f}",
                    data['true_positive'],
                    data['false_negative'],
                    f"{data['avg_confidence']*100:.2f}",
                    f"{data['avg_latency_ms']:.2f}"
                ])

        self.log(f"Results saved to: {RESULTS_DIR}")
        return report_file

    # ============================================
    # Main Execution
    # ============================================

    def run(self, samples_per_attack=SAMPLES_PER_ATTACK):
        """Deneyi çalıştır"""
        self.log("=" * 60)
        self.log("DENEY 3: FARKLI SALDIRI TÜRLERİ ANALİZİ BAŞLIYOR")
        self.log("=" * 60)

        start_time = datetime.now()

        # Check ML service
        try:
            response = requests.get(f"{ML_SERVICE_URL}/health", timeout=5)
            if response.status_code != 200:
                self.log("ML service is not healthy!", "ERROR")
                return None
        except Exception as e:
            self.log(f"Cannot connect to ML service: {e}", "ERROR")
            return None

        # Test each attack type
        attack_types = [
            'SYN Flood',
            'UDP Flood',
            'HTTP Flood',
            'ICMP Flood',
            'Slowloris',
            'DNS Amplification'
        ]

        for attack_type in attack_types:
            self.log("")
            self.test_attack_type(attack_type, samples_per_attack)

        # Calculate metrics
        metrics = self.calculate_metrics()

        # Generate report
        self.generate_report(metrics)

        self.log(f"\nTotal experiment duration: {datetime.now() - start_time}")

        return metrics


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Deney 3: Farklı Saldırı Türleri Analizi')
    parser.add_argument('-s', '--samples', type=int, default=SAMPLES_PER_ATTACK,
                       help='Her saldırı tipi için örnek sayısı')

    args = parser.parse_args()

    experiment = AttackTypeExperiment()
    experiment.run(args.samples)
