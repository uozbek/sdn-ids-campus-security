#!/usr/bin/env python3
"""
============================================
Deney 1: Tespit Doğruluğu (Detection Rate, False Positive Rate)
============================================

Bu deney, HHO-BDT tabanlı IDS sisteminin tespit doğruluğunu ölçer.

Metrikler:
- True Positive Rate (TPR) / Detection Rate (DR)
- False Positive Rate (FPR)
- True Negative Rate (TNR) / Specificity
- False Negative Rate (FNR)
- Precision, Recall, F1-Score
- Accuracy

Author: PhD Research - SDN Security
"""

import requests
import time
import json
import csv
import subprocess
import threading
import random
from datetime import datetime
from collections import defaultdict
import statistics
import os

# Configuration
ML_SERVICE_URL = "http://172.10.10.100:5000"
CONTROLLER_URL = "http://172.10.10.10:8080"
RESULTS_DIR = "/tmp/experiment_results"
EXPERIMENT_NAME = "deney1_tespit_dogrulugu"

# Test parameters
BENIGN_TRAFFIC_DURATION = 120  # seconds
ATTACK_TRAFFIC_DURATION = 60   # seconds
BENIGN_SAMPLES = 500
ATTACK_SAMPLES = 500


class DetectionAccuracyExperiment:
    """Deney 1: Tespit Doğruluğu Ölçümü"""

    def __init__(self):
        self.results = {
            'true_positive': 0,    # Saldırı doğru tespit
            'false_positive': 0,   # Normal trafik yanlış alarm
            'true_negative': 0,    # Normal trafik doğru izin
            'false_negative': 0,   # Saldırı kaçırıldı
            'predictions': [],
            'latencies': []
        }
        self.start_time = None
        os.makedirs(RESULTS_DIR, exist_ok=True)

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] [{level}] {message}")

    # ============================================
    # Benign Traffic Feature Generators
    # ============================================

    def generate_benign_features(self):
        """Normal trafik özelliklerini üret (CIC-DDoS2019 formatında)"""
        return {
            # Flow statistics - normal patterns
            'Flow Duration': random.uniform(100000, 5000000),
            'Total Fwd Packets': random.randint(5, 50),
            'Total Backward Packets': random.randint(3, 40),
            'Total Length of Fwd Packets': random.randint(500, 5000),
            'Total Length of Bwd Packets': random.randint(300, 4000),

            # Packet lengths - normal sizes
            'Fwd Packet Length Max': random.randint(500, 1460),
            'Fwd Packet Length Min': random.randint(40, 100),
            'Fwd Packet Length Mean': random.uniform(200, 800),
            'Bwd Packet Length Max': random.randint(400, 1460),
            'Bwd Packet Length Min': random.randint(40, 100),
            'Bwd Packet Length Mean': random.uniform(150, 700),
            'Packet Length Max': random.randint(600, 1460),
            'Packet Length Min': random.randint(40, 100),
            'Packet Length Mean': random.uniform(200, 700),
            'Packet Length Variance': random.uniform(1000, 50000),

            # Flow rates - normal
            'Flow Bytes/s': random.uniform(1000, 50000),
            'Flow Packets/s': random.uniform(10, 200),

            # IAT features - normal timing
            'Flow IAT Mean': random.uniform(10000, 100000),
            'Flow IAT Max': random.uniform(50000, 500000),
            'Flow IAT Min': random.uniform(100, 10000),
            'Fwd IAT Total': random.uniform(100000, 1000000),
            'Fwd IAT Mean': random.uniform(10000, 100000),
            'Fwd IAT Max': random.uniform(50000, 300000),
            'Bwd IAT Total': random.uniform(80000, 800000),
            'Bwd IAT Mean': random.uniform(8000, 80000),

            # TCP Flags - normal patterns
            'PSH Flag Count': random.randint(1, 20),
            'ACK Flag Count': random.randint(5, 50),
            'URG Flag Count': 0,
            'SYN Flag Count': random.randint(1, 3),
            'RST Flag Count': random.randint(0, 2),
            'FIN Flag Count': random.randint(0, 2),

            # Subflow
            'Subflow Fwd Packets': random.randint(5, 50),
            'Subflow Fwd Bytes': random.randint(500, 5000),
            'Subflow Bwd Packets': random.randint(3, 40),
            'Subflow Bwd Bytes': random.randint(300, 4000),

            # Window sizes
            'Init_Win_bytes_forward': random.randint(8000, 65535),
            'Init_Win_bytes_backward': random.randint(8000, 65535),

            # Additional metrics
            'min_seg_size_forward': random.randint(20, 60),
            'Average Packet Size': random.uniform(200, 800),
            'Avg Fwd Segment Size': random.uniform(150, 600),
            'Avg Bwd Segment Size': random.uniform(100, 500),

            # Idle/Active
            'Idle Mean': random.uniform(50000, 200000),
            'Idle Max': random.uniform(100000, 500000),
            'Idle Min': random.uniform(1000, 50000),
            'Active Mean': random.uniform(10000, 100000),
        }

    # ============================================
    # Attack Traffic Feature Generators
    # ============================================

    def generate_syn_flood_features(self):
        """SYN Flood saldırı özellikleri"""
        return {
            'Flow Duration': random.uniform(1000, 50000),
            'Total Fwd Packets': random.randint(1000, 50000),
            'Total Backward Packets': random.randint(0, 10),
            'Total Length of Fwd Packets': random.randint(40000, 2000000),
            'Total Length of Bwd Packets': random.randint(0, 500),

            'Fwd Packet Length Max': random.randint(40, 60),
            'Fwd Packet Length Min': 40,
            'Fwd Packet Length Mean': random.uniform(40, 60),
            'Bwd Packet Length Max': random.randint(0, 60),
            'Bwd Packet Length Min': 0,
            'Bwd Packet Length Mean': random.uniform(0, 30),
            'Packet Length Max': random.randint(40, 60),
            'Packet Length Min': 40,
            'Packet Length Mean': random.uniform(40, 55),
            'Packet Length Variance': random.uniform(0, 100),

            'Flow Bytes/s': random.uniform(100000, 5000000),
            'Flow Packets/s': random.uniform(5000, 100000),

            'Flow IAT Mean': random.uniform(1, 100),
            'Flow IAT Max': random.uniform(10, 500),
            'Flow IAT Min': random.uniform(0, 10),
            'Fwd IAT Total': random.uniform(100, 10000),
            'Fwd IAT Mean': random.uniform(1, 50),
            'Fwd IAT Max': random.uniform(10, 200),
            'Bwd IAT Total': 0,
            'Bwd IAT Mean': 0,

            'PSH Flag Count': 0,
            'ACK Flag Count': random.randint(0, 10),
            'URG Flag Count': 0,
            'SYN Flag Count': random.randint(1000, 50000),
            'RST Flag Count': random.randint(0, 100),
            'FIN Flag Count': 0,

            'Subflow Fwd Packets': random.randint(1000, 50000),
            'Subflow Fwd Bytes': random.randint(40000, 2000000),
            'Subflow Bwd Packets': random.randint(0, 10),
            'Subflow Bwd Bytes': random.randint(0, 500),

            'Init_Win_bytes_forward': random.randint(1024, 8192),
            'Init_Win_bytes_backward': 0,

            'min_seg_size_forward': 40,
            'Average Packet Size': random.uniform(40, 60),
            'Avg Fwd Segment Size': random.uniform(40, 60),
            'Avg Bwd Segment Size': 0,

            'Idle Mean': random.uniform(0, 100),
            'Idle Max': random.uniform(10, 500),
            'Idle Min': 0,
            'Active Mean': random.uniform(0, 50),
        }

    def generate_udp_flood_features(self):
        """UDP Flood saldırı özellikleri"""
        return {
            'Flow Duration': random.uniform(1000, 100000),
            'Total Fwd Packets': random.randint(5000, 100000),
            'Total Backward Packets': random.randint(0, 50),
            'Total Length of Fwd Packets': random.randint(500000, 10000000),
            'Total Length of Bwd Packets': random.randint(0, 2000),

            'Fwd Packet Length Max': random.randint(500, 1400),
            'Fwd Packet Length Min': random.randint(64, 200),
            'Fwd Packet Length Mean': random.uniform(200, 800),
            'Bwd Packet Length Max': random.randint(0, 100),
            'Bwd Packet Length Min': 0,
            'Bwd Packet Length Mean': random.uniform(0, 50),
            'Packet Length Max': random.randint(500, 1400),
            'Packet Length Min': random.randint(64, 200),
            'Packet Length Mean': random.uniform(200, 800),
            'Packet Length Variance': random.uniform(10000, 100000),

            'Flow Bytes/s': random.uniform(500000, 10000000),
            'Flow Packets/s': random.uniform(10000, 200000),

            'Flow IAT Mean': random.uniform(1, 50),
            'Flow IAT Max': random.uniform(10, 200),
            'Flow IAT Min': random.uniform(0, 5),
            'Fwd IAT Total': random.uniform(100, 5000),
            'Fwd IAT Mean': random.uniform(1, 30),
            'Fwd IAT Max': random.uniform(10, 150),
            'Bwd IAT Total': 0,
            'Bwd IAT Mean': 0,

            'PSH Flag Count': 0,
            'ACK Flag Count': 0,
            'URG Flag Count': 0,
            'SYN Flag Count': 0,
            'RST Flag Count': 0,
            'FIN Flag Count': 0,

            'Subflow Fwd Packets': random.randint(5000, 100000),
            'Subflow Fwd Bytes': random.randint(500000, 10000000),
            'Subflow Bwd Packets': random.randint(0, 50),
            'Subflow Bwd Bytes': random.randint(0, 2000),

            'Init_Win_bytes_forward': 0,
            'Init_Win_bytes_backward': 0,

            'min_seg_size_forward': random.randint(64, 200),
            'Average Packet Size': random.uniform(200, 800),
            'Avg Fwd Segment Size': random.uniform(200, 800),
            'Avg Bwd Segment Size': 0,

            'Idle Mean': random.uniform(0, 50),
            'Idle Max': random.uniform(10, 200),
            'Idle Min': 0,
            'Active Mean': random.uniform(0, 30),
        }

    def generate_http_flood_features(self):
        """HTTP Flood saldırı özellikleri"""
        return {
            'Flow Duration': random.uniform(10000, 200000),
            'Total Fwd Packets': random.randint(500, 10000),
            'Total Backward Packets': random.randint(100, 2000),
            'Total Length of Fwd Packets': random.randint(100000, 2000000),
            'Total Length of Bwd Packets': random.randint(50000, 1000000),

            'Fwd Packet Length Max': random.randint(200, 500),
            'Fwd Packet Length Min': random.randint(40, 100),
            'Fwd Packet Length Mean': random.uniform(100, 300),
            'Bwd Packet Length Max': random.randint(500, 1460),
            'Bwd Packet Length Min': random.randint(40, 100),
            'Bwd Packet Length Mean': random.uniform(200, 600),
            'Packet Length Max': random.randint(500, 1460),
            'Packet Length Min': random.randint(40, 100),
            'Packet Length Mean': random.uniform(150, 400),
            'Packet Length Variance': random.uniform(5000, 50000),

            'Flow Bytes/s': random.uniform(100000, 2000000),
            'Flow Packets/s': random.uniform(1000, 20000),

            'Flow IAT Mean': random.uniform(10, 500),
            'Flow IAT Max': random.uniform(100, 2000),
            'Flow IAT Min': random.uniform(1, 50),
            'Fwd IAT Total': random.uniform(1000, 50000),
            'Fwd IAT Mean': random.uniform(10, 200),
            'Fwd IAT Max': random.uniform(100, 1000),
            'Bwd IAT Total': random.uniform(500, 30000),
            'Bwd IAT Mean': random.uniform(5, 150),

            'PSH Flag Count': random.randint(500, 10000),
            'ACK Flag Count': random.randint(1000, 20000),
            'URG Flag Count': 0,
            'SYN Flag Count': random.randint(500, 10000),
            'RST Flag Count': random.randint(0, 500),
            'FIN Flag Count': random.randint(0, 500),

            'Subflow Fwd Packets': random.randint(500, 10000),
            'Subflow Fwd Bytes': random.randint(100000, 2000000),
            'Subflow Bwd Packets': random.randint(100, 2000),
            'Subflow Bwd Bytes': random.randint(50000, 1000000),

            'Init_Win_bytes_forward': random.randint(4096, 16384),
            'Init_Win_bytes_backward': random.randint(8192, 65535),

            'min_seg_size_forward': random.randint(20, 60),
            'Average Packet Size': random.uniform(150, 400),
            'Avg Fwd Segment Size': random.uniform(100, 300),
            'Avg Bwd Segment Size': random.uniform(200, 600),

            'Idle Mean': random.uniform(100, 1000),
            'Idle Max': random.uniform(500, 5000),
            'Idle Min': random.uniform(10, 100),
            'Active Mean': random.uniform(50, 500),
        }

    def generate_attack_features(self, attack_type='random'):
        """Saldırı türüne göre özellik üret"""
        if attack_type == 'syn':
            return self.generate_syn_flood_features()
        elif attack_type == 'udp':
            return self.generate_udp_flood_features()
        elif attack_type == 'http':
            return self.generate_http_flood_features()
        else:
            # Random attack type
            return random.choice([
                self.generate_syn_flood_features,
                self.generate_udp_flood_features,
                self.generate_http_flood_features
            ])()

    # ============================================
    # ML Service Query
    # ============================================

    def query_ml_service(self, features):
        """ML servisine sorgu gönder"""
        start_time = time.time()
        try:
            response = requests.post(
                f"{ML_SERVICE_URL}/predict",
                json={'features': features},
                timeout=5
            )
            latency = (time.time() - start_time) * 1000  # ms
            self.results['latencies'].append(latency)

            if response.status_code == 200:
                return response.json()
        except Exception as e:
            self.log(f"ML service error: {e}", "ERROR")
        return None

    # ============================================
    # Test Execution
    # ============================================

    def test_benign_traffic(self, num_samples):
        """Normal trafik testleri"""
        self.log(f"Testing {num_samples} benign traffic samples...")

        for i in range(num_samples):
            features = self.generate_benign_features()
            result = self.query_ml_service(features)

            if result:
                prediction = result.get('prediction', -1)
                confidence = result.get('confidence', 0)

                if prediction == 0:  # Correctly classified as benign
                    self.results['true_negative'] += 1
                else:  # False alarm
                    self.results['false_positive'] += 1

                self.results['predictions'].append({
                    'type': 'benign',
                    'prediction': prediction,
                    'confidence': confidence,
                    'expected': 0
                })

            if (i + 1) % 100 == 0:
                self.log(f"Benign samples tested: {i + 1}/{num_samples}")

    def test_attack_traffic(self, num_samples):
        """Saldırı trafik testleri"""
        self.log(f"Testing {num_samples} attack traffic samples...")

        attack_types = ['syn', 'udp', 'http']

        for i in range(num_samples):
            attack_type = attack_types[i % len(attack_types)]
            features = self.generate_attack_features(attack_type)
            result = self.query_ml_service(features)

            if result:
                prediction = result.get('prediction', -1)
                confidence = result.get('confidence', 0)

                if prediction == 1:  # Correctly detected attack
                    self.results['true_positive'] += 1
                else:  # Missed attack
                    self.results['false_negative'] += 1

                self.results['predictions'].append({
                    'type': f'attack_{attack_type}',
                    'prediction': prediction,
                    'confidence': confidence,
                    'expected': 1
                })

            if (i + 1) % 100 == 0:
                self.log(f"Attack samples tested: {i + 1}/{num_samples}")

    # ============================================
    # Metrics Calculation
    # ============================================

    def calculate_metrics(self):
        """Performans metriklerini hesapla"""
        tp = self.results['true_positive']
        fp = self.results['false_positive']
        tn = self.results['true_negative']
        fn = self.results['false_negative']

        total = tp + fp + tn + fn

        # Temel metrikler
        accuracy = (tp + tn) / total if total > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0  # TPR / Detection Rate
        f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        # Detaylı metrikler
        tpr = recall  # True Positive Rate = Detection Rate
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0  # False Positive Rate
        tnr = tn / (tn + fp) if (tn + fp) > 0 else 0  # True Negative Rate = Specificity
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0  # False Negative Rate

        # Latency statistics
        latencies = self.results['latencies']
        avg_latency = statistics.mean(latencies) if latencies else 0
        std_latency = statistics.stdev(latencies) if len(latencies) > 1 else 0
        min_latency = min(latencies) if latencies else 0
        max_latency = max(latencies) if latencies else 0

        return {
            'confusion_matrix': {
                'true_positive': tp,
                'false_positive': fp,
                'true_negative': tn,
                'false_negative': fn
            },
            'basic_metrics': {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1_score
            },
            'detection_metrics': {
                'detection_rate_tpr': tpr,
                'false_positive_rate_fpr': fpr,
                'specificity_tnr': tnr,
                'false_negative_rate_fnr': fnr
            },
            'latency_stats': {
                'mean_ms': avg_latency,
                'std_ms': std_latency,
                'min_ms': min_latency,
                'max_ms': max_latency
            },
            'sample_counts': {
                'total_samples': total,
                'benign_samples': tn + fp,
                'attack_samples': tp + fn
            }
        }

    # ============================================
    # Report Generation
    # ============================================

    def generate_report(self, metrics):
        """Detaylı rapor oluştur"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{RESULTS_DIR}/{EXPERIMENT_NAME}_{timestamp}.txt"

        report = []
        report.append("=" * 70)
        report.append("DENEY 1: TESPİT DOĞRULUĞU ANALİZİ")
        report.append("Detection Accuracy Analysis Report")
        report.append("=" * 70)
        report.append(f"Tarih/Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"ML Service: {ML_SERVICE_URL}")
        report.append("")

        report.append("-" * 70)
        report.append("CONFUSION MATRIX")
        report.append("-" * 70)
        cm = metrics['confusion_matrix']
        report.append(f"                    Predicted")
        report.append(f"                    Benign    Attack")
        report.append(f"Actual  Benign      {cm['true_negative']:6d}    {cm['false_positive']:6d}")
        report.append(f"        Attack      {cm['false_negative']:6d}    {cm['true_positive']:6d}")
        report.append("")

        report.append("-" * 70)
        report.append("TEMEL METRİKLER / BASIC METRICS")
        report.append("-" * 70)
        bm = metrics['basic_metrics']
        report.append(f"Accuracy     (Doğruluk):     {bm['accuracy']:.4f}  ({bm['accuracy']*100:.2f}%)")
        report.append(f"Precision    (Kesinlik):     {bm['precision']:.4f}  ({bm['precision']*100:.2f}%)")
        report.append(f"Recall       (Duyarlılık):   {bm['recall']:.4f}  ({bm['recall']*100:.2f}%)")
        report.append(f"F1-Score:                    {bm['f1_score']:.4f}  ({bm['f1_score']*100:.2f}%)")
        report.append("")

        report.append("-" * 70)
        report.append("TESPİT METRİKLERİ / DETECTION METRICS")
        report.append("-" * 70)
        dm = metrics['detection_metrics']
        report.append(f"Detection Rate (TPR):        {dm['detection_rate_tpr']:.4f}  ({dm['detection_rate_tpr']*100:.2f}%)")
        report.append(f"False Positive Rate (FPR):   {dm['false_positive_rate_fpr']:.4f}  ({dm['false_positive_rate_fpr']*100:.2f}%)")
        report.append(f"Specificity (TNR):           {dm['specificity_tnr']:.4f}  ({dm['specificity_tnr']*100:.2f}%)")
        report.append(f"False Negative Rate (FNR):   {dm['false_negative_rate_fnr']:.4f}  ({dm['false_negative_rate_fnr']*100:.2f}%)")
        report.append("")

        report.append("-" * 70)
        report.append("GECİKME İSTATİSTİKLERİ / LATENCY STATISTICS")
        report.append("-" * 70)
        ls = metrics['latency_stats']
        report.append(f"Ortalama Gecikme (Mean):     {ls['mean_ms']:.2f} ms")
        report.append(f"Standart Sapma (Std):        {ls['std_ms']:.2f} ms")
        report.append(f"Minimum Gecikme:             {ls['min_ms']:.2f} ms")
        report.append(f"Maximum Gecikme:             {ls['max_ms']:.2f} ms")
        report.append("")

        report.append("-" * 70)
        report.append("ÖRNEK SAYILARI / SAMPLE COUNTS")
        report.append("-" * 70)
        sc = metrics['sample_counts']
        report.append(f"Toplam Test Örneği:          {sc['total_samples']}")
        report.append(f"Normal Trafik Örneği:        {sc['benign_samples']}")
        report.append(f"Saldırı Trafik Örneği:       {sc['attack_samples']}")
        report.append("")

        report.append("=" * 70)
        report.append("DENEY TAMAMLANDI / EXPERIMENT COMPLETED")
        report.append("=" * 70)

        report_text = "\n".join(report)
        print(report_text)

        # Save to file
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_text)

        # Save JSON results
        json_file = f"{RESULTS_DIR}/{EXPERIMENT_NAME}_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump({
                'experiment': EXPERIMENT_NAME,
                'timestamp': timestamp,
                'metrics': metrics,
                'predictions': self.results['predictions']
            }, f, indent=2)

        # Save CSV for further analysis
        csv_file = f"{RESULTS_DIR}/{EXPERIMENT_NAME}_{timestamp}.csv"
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['type', 'expected', 'prediction', 'confidence'])
            for pred in self.results['predictions']:
                writer.writerow([
                    pred['type'],
                    pred['expected'],
                    pred['prediction'],
                    pred['confidence']
                ])

        self.log(f"Results saved to: {RESULTS_DIR}")
        return report_file

    # ============================================
    # Main Execution
    # ============================================

    def run(self, benign_samples=BENIGN_SAMPLES, attack_samples=ATTACK_SAMPLES):
        """Deneyi çalıştır"""
        self.log("=" * 60)
        self.log("DENEY 1: TESPİT DOĞRULUĞU (DR, FPR) BAŞLIYOR")
        self.log("=" * 60)

        self.start_time = datetime.now()

        # Check ML service
        self.log("Checking ML service health...")
        try:
            response = requests.get(f"{ML_SERVICE_URL}/health", timeout=5)
            if response.status_code != 200:
                self.log("ML service is not healthy!", "ERROR")
                return None
        except Exception as e:
            self.log(f"Cannot connect to ML service: {e}", "ERROR")
            return None

        self.log("ML service is healthy. Starting tests...")

        # Run tests
        self.test_benign_traffic(benign_samples)
        self.test_attack_traffic(attack_samples)

        # Calculate metrics
        metrics = self.calculate_metrics()

        # Generate report
        report_file = self.generate_report(metrics)

        self.log(f"Total experiment duration: {datetime.now() - self.start_time}")

        return metrics


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Deney 1: Tespit Doğruluğu Analizi')
    parser.add_argument('-b', '--benign', type=int, default=BENIGN_SAMPLES,
                       help='Normal trafik örnek sayısı')
    parser.add_argument('-a', '--attack', type=int, default=ATTACK_SAMPLES,
                       help='Saldırı trafik örnek sayısı')

    args = parser.parse_args()

    experiment = DetectionAccuracyExperiment()
    experiment.run(args.benign, args.attack)
