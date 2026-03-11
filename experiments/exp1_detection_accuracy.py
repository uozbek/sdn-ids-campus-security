#!/usr/bin/env python3
"""
==============================================================================
DENEY 1: TESPİT DOĞRULUĞU (Detection Rate & False Positive Rate)
==============================================================================

Bu deney, HHO-BDT modelinin tespit doğruluğunu ölçer:
- Detection Rate (DR): Gerçek saldırıların tespit oranı
- False Positive Rate (FPR): Yanlış alarm oranı
- Precision, Recall, F1-Score
- Confusion Matrix

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
from collections import defaultdict

# Configuration
ML_SERVICE_URL = "http://172.10.10.100:5000"
CONTROLLER_URL = "http://172.10.10.10:8080"
RESULTS_DIR = "/tmp/experiment_results/exp1_accuracy"
VICTIM_IP = "192.168.11.6"

class DetectionAccuracyExperiment:
    """
    Deney 1: Tespit Doğruluğu Ölçümü

    Amaç: IDS sisteminin saldırı tespit doğruluğunu değerlendirmek

    Metrikler:
    - True Positive (TP): Doğru tespit edilen saldırılar
    - True Negative (TN): Doğru sınıflandırılan normal trafik
    - False Positive (FP): Yanlış alarm (normal trafik saldırı olarak işaretlendi)
    - False Negative (FN): Kaçırılan saldırılar
    """

    def __init__(self):
        self.results = {
            'experiment_name': 'Detection Accuracy',
            'start_time': None,
            'end_time': None,
            'config': {},
            'metrics': {},
            'raw_data': []
        }

        # Confusion matrix counters
        self.tp = 0  # True Positive
        self.tn = 0  # True Negative
        self.fp = 0  # False Positive
        self.fn = 0  # False Negative

        # Detailed logs
        self.predictions = []

        os.makedirs(RESULTS_DIR, exist_ok=True)

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] [{level}] {message}")

    def generate_benign_features(self):
        """CIC-DDoS2019 formatında normal trafik özellikleri üret"""
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
            'min_seg_size_forward': random.randint(20, 60),
            'Average Packet Size': random.uniform(200, 1000),
            'Avg Fwd Segment Size': random.uniform(200, 800),
            'Avg Bwd Segment Size': random.uniform(200, 800),
            'Packet Length Max': random.randint(500, 1500),
            'Packet Length Min': random.randint(40, 100),
            'Packet Length Mean': random.uniform(200, 800),
            'Packet Length Variance': random.uniform(1000, 50000),
            'Idle Mean': random.uniform(10000, 500000),
            'Idle Max': random.uniform(50000, 1000000),
            'Idle Min': random.uniform(1000, 50000),
            'Active Mean': random.uniform(1000, 50000),
        }

    def generate_attack_features(self, attack_type='syn_flood'):
        """CIC-DDoS2019 formatında saldırı trafiği özellikleri üret"""

        if attack_type == 'syn_flood':
            return {
                'Flow Duration': random.uniform(1000, 100000),
                'Total Fwd Packets': random.randint(1000, 50000),
                'Total Backward Packets': random.randint(0, 10),
                'Total Length of Fwd Packets': random.randint(40000, 2000000),
                'Total Length of Bwd Packets': random.randint(0, 1000),
                'Fwd Packet Length Max': random.randint(40, 80),
                'Fwd Packet Length Min': random.randint(40, 60),
                'Fwd Packet Length Mean': random.uniform(40, 60),
                'Bwd Packet Length Max': 0,
                'Bwd Packet Length Min': 0,
                'Bwd Packet Length Mean': 0,
                'Flow Bytes/s': random.uniform(500000, 10000000),
                'Flow Packets/s': random.uniform(5000, 100000),
                'Flow IAT Mean': random.uniform(1, 100),
                'Flow IAT Max': random.uniform(10, 1000),
                'Flow IAT Min': random.uniform(0, 10),
                'Fwd IAT Total': random.uniform(100, 10000),
                'Fwd IAT Mean': random.uniform(1, 100),
                'Fwd IAT Max': random.uniform(10, 500),
                'Bwd IAT Total': 0,
                'Bwd IAT Mean': 0,
                'PSH Flag Count': 0,
                'ACK Flag Count': 0,
                'URG Flag Count': 0,
                'SYN Flag Count': random.randint(1000, 50000),
                'RST Flag Count': random.randint(0, 100),
                'FIN Flag Count': 0,
                'Subflow Fwd Packets': random.randint(1000, 50000),
                'Subflow Fwd Bytes': random.randint(40000, 2000000),
                'Subflow Bwd Packets': 0,
                'Subflow Bwd Bytes': 0,
                'Init_Win_bytes_forward': random.randint(1024, 4096),
                'Init_Win_bytes_backward': 0,
                'min_seg_size_forward': random.randint(40, 60),
                'Average Packet Size': random.uniform(40, 60),
                'Avg Fwd Segment Size': random.uniform(40, 60),
                'Avg Bwd Segment Size': 0,
                'Packet Length Max': random.randint(40, 80),
                'Packet Length Min': random.randint(40, 60),
                'Packet Length Mean': random.uniform(40, 60),
                'Packet Length Variance': random.uniform(0, 100),
                'Idle Mean': random.uniform(0, 100),
                'Idle Max': random.uniform(0, 500),
                'Idle Min': 0,
                'Active Mean': random.uniform(1, 100),
            }

        elif attack_type == 'udp_flood':
            return {
                'Flow Duration': random.uniform(1000, 50000),
                'Total Fwd Packets': random.randint(5000, 100000),
                'Total Backward Packets': 0,
                'Flow Bytes/s': random.uniform(1000000, 50000000),
                'Flow Packets/s': random.uniform(10000, 500000),
                'Flow IAT Mean': random.uniform(0.1, 10),
                'SYN Flag Count': 0,
                'ACK Flag Count': 0,
                'Subflow Fwd Packets': random.randint(5000, 100000),
                'Average Packet Size': random.uniform(100, 1400),
                # ... other features
            }

        # Default attack pattern
        return self.generate_benign_features()  # Will be modified

    def query_ml_service(self, features):
        """ML servisine sorgu gönder"""
        try:
            response = requests.post(
                f"{ML_SERVICE_URL}/predict",
                json={'features': features},
                timeout=5
            )
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            self.log(f"ML service error: {e}", "ERROR")
        return None

    def run_test_round(self, num_benign=100, num_attack=100, attack_type='syn_flood'):
        """Tek bir test turu çalıştır"""
        self.log(f"Test round: {num_benign} benign, {num_attack} {attack_type} attack")

        round_results = []

        # Test benign traffic
        self.log("Testing benign traffic...")
        for i in range(num_benign):
            features = self.generate_benign_features()
            result = self.query_ml_service(features)

            if result:
                prediction = result.get('prediction', -1)
                confidence = result.get('confidence', 0)

                # Ground truth: 0 (benign)
                if prediction == 0:
                    self.tn += 1  # Correctly classified as benign
                else:
                    self.fp += 1  # Incorrectly classified as attack (False Positive)

                round_results.append({
                    'sample_id': f'benign_{i}',
                    'ground_truth': 0,
                    'prediction': prediction,
                    'confidence': confidence,
                    'correct': prediction == 0
                })

        # Test attack traffic
        self.log(f"Testing {attack_type} attack traffic...")
        for i in range(num_attack):
            features = self.generate_attack_features(attack_type)
            result = self.query_ml_service(features)

            if result:
                prediction = result.get('prediction', -1)
                confidence = result.get('confidence', 0)

                # Ground truth: 1 (attack)
                if prediction == 1:
                    self.tp += 1  # Correctly classified as attack
                else:
                    self.fn += 1  # Missed attack (False Negative)

                round_results.append({
                    'sample_id': f'attack_{i}',
                    'ground_truth': 1,
                    'prediction': prediction,
                    'confidence': confidence,
                    'correct': prediction == 1
                })

        return round_results

    def calculate_metrics(self):
        """Performans metriklerini hesapla"""
        total = self.tp + self.tn + self.fp + self.fn

        if total == 0:
            return {}

        # Basic metrics
        accuracy = (self.tp + self.tn) / total

        # Detection Rate (Recall/Sensitivity)
        dr = self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0

        # False Positive Rate
        fpr = self.fp / (self.fp + self.tn) if (self.fp + self.tn) > 0 else 0

        # Precision
        precision = self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0

        # F1-Score
        f1 = 2 * (precision * dr) / (precision + dr) if (precision + dr) > 0 else 0

        # Specificity (True Negative Rate)
        specificity = self.tn / (self.tn + self.fp) if (self.tn + self.fp) > 0 else 0

        return {
            'total_samples': total,
            'true_positive': self.tp,
            'true_negative': self.tn,
            'false_positive': self.fp,
            'false_negative': self.fn,
            'accuracy': round(accuracy * 100, 2),
            'detection_rate': round(dr * 100, 2),
            'false_positive_rate': round(fpr * 100, 2),
            'precision': round(precision * 100, 2),
            'recall': round(dr * 100, 2),
            'f1_score': round(f1 * 100, 2),
            'specificity': round(specificity * 100, 2)
        }

    def run_experiment(self, config=None):
        """Ana deney prosedürü"""
        if config is None:
            config = {
                'num_rounds': 10,
                'benign_per_round': 100,
                'attack_per_round': 100,
                'attack_types': ['syn_flood'],
                'description': 'Detection Accuracy Experiment'
            }

        self.results['config'] = config
        self.results['start_time'] = datetime.now().isoformat()

        self.log("=" * 60)
        self.log("DENEY 1: TESPİT DOĞRULUĞU")
        self.log("=" * 60)
        self.log(f"Configuration: {json.dumps(config, indent=2)}")
        self.log("=" * 60)

        all_results = []

        for round_num in range(config['num_rounds']):
            self.log(f"\n--- Round {round_num + 1}/{config['num_rounds']} ---")

            for attack_type in config['attack_types']:
                round_results = self.run_test_round(
                    num_benign=config['benign_per_round'],
                    num_attack=config['attack_per_round'],
                    attack_type=attack_type
                )
                all_results.extend(round_results)

            # Intermediate metrics
            metrics = self.calculate_metrics()
            self.log(f"Cumulative DR: {metrics.get('detection_rate', 0)}%, FPR: {metrics.get('false_positive_rate', 0)}%")

        # Final metrics
        self.results['metrics'] = self.calculate_metrics()
        self.results['raw_data'] = all_results
        self.results['end_time'] = datetime.now().isoformat()

        self.print_results()
        self.save_results()

        return self.results

    def print_results(self):
        """Sonuçları yazdır"""
        metrics = self.results['metrics']

        print("\n" + "=" * 60)
        print("DENEY SONUÇLARI: TESPİT DOĞRULUĞU")
        print("=" * 60)
        print(f"\nConfusion Matrix:")
        print(f"                  Predicted")
        print(f"                  Attack    Benign")
        print(f"Actual  Attack    {self.tp:<8}  {self.fn:<8}")
        print(f"        Benign    {self.fp:<8}  {self.tn:<8}")
        print()
        print(f"Performans Metrikleri:")
        print(f"  - Accuracy:           {metrics.get('accuracy', 0):.2f}%")
        print(f"  - Detection Rate:     {metrics.get('detection_rate', 0):.2f}%")
        print(f"  - False Positive Rate:{metrics.get('false_positive_rate', 0):.2f}%")
        print(f"  - Precision:          {metrics.get('precision', 0):.2f}%")
        print(f"  - Recall:             {metrics.get('recall', 0):.2f}%")
        print(f"  - F1-Score:           {metrics.get('f1_score', 0):.2f}%")
        print(f"  - Specificity:        {metrics.get('specificity', 0):.2f}%")
        print("=" * 60)

    def save_results(self):
        """Sonuçları dosyaya kaydet"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # JSON results
        json_file = f"{RESULTS_DIR}/exp1_results_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        self.log(f"Results saved to: {json_file}")

        # CSV for detailed analysis
        if self.results['raw_data']:
            df = pd.DataFrame(self.results['raw_data'])
            csv_file = f"{RESULTS_DIR}/exp1_detailed_{timestamp}.csv"
            df.to_csv(csv_file, index=False)
            self.log(f"Detailed data saved to: {csv_file}")


def main():
    """Ana fonksiyon"""
    experiment = DetectionAccuracyExperiment()

    # Deney konfigürasyonu
    config = {
        'num_rounds': 10,
        'benign_per_round': 100,
        'attack_per_round': 100,
        'attack_types': ['syn_flood'],
        'description': 'HHO-BDT Model Detection Accuracy Experiment'
    }

    results = experiment.run_experiment(config)

    return 0 if results['metrics'].get('detection_rate', 0) > 90 else 1


if __name__ == '__main__':
    sys.exit(main())
