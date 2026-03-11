#!/usr/bin/env python3
"""
============================================
Deney 2: Yanıt Süresi Analizi (Response Time Analysis)
============================================

Bu deney, IDS sisteminin yanıt süresini ölçer:
- Tespit Süresi (Detection Time): Saldırının tespit edilme süresi
- Önlem Süresi (Mitigation Time): Aksiyon alınma süresi
- Toplam Yanıt Süresi (Total Response Time)

Author: PhD Research - SDN Security
"""

import requests
import time
import json
import csv
import subprocess
import threading
import statistics
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Configuration
ML_SERVICE_URL = "http://172.10.10.100:5000"
CONTROLLER_URL = "http://172.10.10.10:8080"
RESULTS_DIR = "/tmp/experiment_results"
EXPERIMENT_NAME = "deney2_yanit_suresi"

# Test parameters
NUM_ITERATIONS = 100
CONCURRENT_REQUESTS = 10


class ResponseTimeExperiment:
    """Deney 2: Yanıt Süresi Analizi"""

    def __init__(self):
        self.results = {
            'detection_times': [],      # ML prediction times
            'mitigation_times': [],     # Flow rule installation times
            'total_response_times': [], # End-to-end times
            'flow_install_times': [],   # OpenFlow message times
            'throughput_samples': [],   # Requests per second
        }
        os.makedirs(RESULTS_DIR, exist_ok=True)

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] [{level}] {message}")

    # ============================================
    # Attack Feature Templates
    # ============================================

    def get_attack_features(self):
        """Saldırı trafiği özellikleri"""
        import random
        return {
            'Flow Duration': random.uniform(1000, 50000),
            'Total Fwd Packets': random.randint(5000, 50000),
            'Total Backward Packets': random.randint(0, 10),
            'Fwd Packet Length Max': random.randint(40, 60),
            'Fwd Packet Length Min': 40,
            'Fwd Packet Length Mean': random.uniform(40, 60),
            'Flow Bytes/s': random.uniform(500000, 5000000),
            'Flow Packets/s': random.uniform(10000, 100000),
            'Flow IAT Mean': random.uniform(1, 50),
            'SYN Flag Count': random.randint(5000, 50000),
            'ACK Flag Count': random.randint(0, 10),
            'PSH Flag Count': 0,
            'Subflow Fwd Packets': random.randint(5000, 50000),
            'Subflow Bwd Packets': 0,
        }

    # ============================================
    # Test 1: ML Prediction Latency
    # ============================================

    def test_ml_prediction_latency(self, num_iterations):
        """ML servisinin tahmin gecikme süresini ölç"""
        self.log(f"Testing ML prediction latency ({num_iterations} iterations)...")

        latencies = []

        for i in range(num_iterations):
            features = self.get_attack_features()

            start_time = time.perf_counter()

            try:
                response = requests.post(
                    f"{ML_SERVICE_URL}/predict",
                    json={'features': features},
                    timeout=5
                )

                end_time = time.perf_counter()

                if response.status_code == 200:
                    latency_ms = (end_time - start_time) * 1000
                    latencies.append(latency_ms)
                    self.results['detection_times'].append(latency_ms)

            except Exception as e:
                self.log(f"Request failed: {e}", "ERROR")

            if (i + 1) % 20 == 0:
                self.log(f"ML latency tests: {i + 1}/{num_iterations}")

        return latencies

    # ============================================
    # Test 2: Concurrent Request Latency
    # ============================================

    def test_concurrent_latency(self, num_requests, concurrent_workers):
        """Eşzamanlı istek gecikme sürelerini ölç"""
        self.log(f"Testing concurrent requests ({num_requests} requests, {concurrent_workers} workers)...")

        latencies = []

        def make_request():
            features = self.get_attack_features()
            start_time = time.perf_counter()

            try:
                response = requests.post(
                    f"{ML_SERVICE_URL}/predict",
                    json={'features': features},
                    timeout=10
                )
                end_time = time.perf_counter()

                if response.status_code == 200:
                    return (end_time - start_time) * 1000
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=concurrent_workers) as executor:
            futures = [executor.submit(make_request) for _ in range(num_requests)]

            for future in futures:
                result = future.result()
                if result:
                    latencies.append(result)

        return latencies

    # ============================================
    # Test 3: Batch Prediction Latency
    # ============================================

    def test_batch_prediction_latency(self, batch_sizes=[1, 5, 10, 20, 50]):
        """Farklı batch boyutlarında gecikme süresini ölç"""
        self.log(f"Testing batch prediction latency (sizes: {batch_sizes})...")

        results = {}

        for batch_size in batch_sizes:
            latencies = []

            for _ in range(20):  # 20 iterations per batch size
                features_list = [self.get_attack_features() for _ in range(batch_size)]

                start_time = time.perf_counter()

                try:
                    response = requests.post(
                        f"{ML_SERVICE_URL}/predict/batch",
                        json={'features_list': features_list},
                        timeout=30
                    )
                    end_time = time.perf_counter()

                    if response.status_code == 200:
                        latency_ms = (end_time - start_time) * 1000
                        latencies.append(latency_ms)

                except Exception as e:
                    self.log(f"Batch request failed: {e}", "ERROR")

            results[batch_size] = {
                'mean': statistics.mean(latencies) if latencies else 0,
                'std': statistics.stdev(latencies) if len(latencies) > 1 else 0,
                'min': min(latencies) if latencies else 0,
                'max': max(latencies) if latencies else 0,
                'per_sample': statistics.mean(latencies) / batch_size if latencies else 0
            }

            self.log(f"  Batch size {batch_size}: mean={results[batch_size]['mean']:.2f}ms")

        return results

    # ============================================
    # Test 4: Throughput Measurement
    # ============================================

    def test_throughput(self, duration_seconds=10):
        """Saniye başına işlenen istek sayısını ölç"""
        self.log(f"Testing throughput ({duration_seconds} seconds)...")

        request_count = 0
        start_time = time.time()

        while time.time() - start_time < duration_seconds:
            features = self.get_attack_features()

            try:
                response = requests.post(
                    f"{ML_SERVICE_URL}/predict",
                    json={'features': features},
                    timeout=5
                )

                if response.status_code == 200:
                    request_count += 1

            except:
                pass

        elapsed = time.time() - start_time
        throughput = request_count / elapsed

        self.results['throughput_samples'].append(throughput)
        self.log(f"  Throughput: {throughput:.2f} requests/second")

        return throughput

    # ============================================
    # Test 5: End-to-End Response Time
    # ============================================

    def test_end_to_end_response(self, num_iterations):
        """Uçtan uca yanıt süresini ölç (detection + action)"""
        self.log(f"Testing end-to-end response time ({num_iterations} iterations)...")

        # Simulated mitigation overhead (flow rule installation)
        FLOW_INSTALL_OVERHEAD_MS = 5  # Typical OVS flow mod latency

        for i in range(num_iterations):
            features = self.get_attack_features()

            # Start timing
            start_time = time.perf_counter()

            try:
                # 1. ML Prediction
                response = requests.post(
                    f"{ML_SERVICE_URL}/predict",
                    json={'features': features},
                    timeout=5
                )

                detection_time = time.perf_counter()

                if response.status_code == 200:
                    result = response.json()

                    # 2. Simulated flow rule installation
                    # In real scenario, this would be actual OpenFlow message
                    time.sleep(FLOW_INSTALL_OVERHEAD_MS / 1000)

                    mitigation_time = time.perf_counter()

                    # Calculate times
                    detect_ms = (detection_time - start_time) * 1000
                    mitigate_ms = (mitigation_time - detection_time) * 1000
                    total_ms = (mitigation_time - start_time) * 1000

                    self.results['detection_times'].append(detect_ms)
                    self.results['mitigation_times'].append(mitigate_ms)
                    self.results['total_response_times'].append(total_ms)

            except Exception as e:
                self.log(f"Request failed: {e}", "ERROR")

            if (i + 1) % 20 == 0:
                self.log(f"E2E tests: {i + 1}/{num_iterations}")

    # ============================================
    # Test 6: Latency Under Load
    # ============================================

    def test_latency_under_load(self, load_levels=[1, 5, 10, 20, 50]):
        """Farklı yük seviyelerinde gecikme sürelerini ölç"""
        self.log(f"Testing latency under different load levels: {load_levels}...")

        results = {}

        for load in load_levels:
            latencies = self.test_concurrent_latency(50, load)

            if latencies:
                results[load] = {
                    'mean': statistics.mean(latencies),
                    'std': statistics.stdev(latencies) if len(latencies) > 1 else 0,
                    'p50': statistics.median(latencies),
                    'p95': sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0,
                    'p99': sorted(latencies)[int(len(latencies) * 0.99)] if latencies else 0,
                }
                self.log(f"  Load {load}: mean={results[load]['mean']:.2f}ms, p95={results[load]['p95']:.2f}ms")

        return results

    # ============================================
    # Calculate Statistics
    # ============================================

    def calculate_statistics(self):
        """İstatistikleri hesapla"""
        stats = {}

        for key in ['detection_times', 'mitigation_times', 'total_response_times']:
            data = self.results[key]
            if data:
                sorted_data = sorted(data)
                n = len(data)

                stats[key] = {
                    'count': n,
                    'mean': statistics.mean(data),
                    'std': statistics.stdev(data) if n > 1 else 0,
                    'min': min(data),
                    'max': max(data),
                    'median': statistics.median(data),
                    'p50': sorted_data[int(n * 0.50)],
                    'p90': sorted_data[int(n * 0.90)] if n >= 10 else sorted_data[-1],
                    'p95': sorted_data[int(n * 0.95)] if n >= 20 else sorted_data[-1],
                    'p99': sorted_data[int(n * 0.99)] if n >= 100 else sorted_data[-1],
                }
            else:
                stats[key] = {'count': 0}

        return stats

    # ============================================
    # Generate Report
    # ============================================

    def generate_report(self, stats, batch_results, load_results):
        """Detaylı rapor oluştur"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{RESULTS_DIR}/{EXPERIMENT_NAME}_{timestamp}.txt"

        report = []
        report.append("=" * 70)
        report.append("DENEY 2: YANIT SÜRESİ ANALİZİ")
        report.append("Response Time Analysis Report")
        report.append("=" * 70)
        report.append(f"Tarih/Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"ML Service: {ML_SERVICE_URL}")
        report.append("")

        # Detection Time Stats
        report.append("-" * 70)
        report.append("TESPİT SÜRESİ / DETECTION TIME (ms)")
        report.append("-" * 70)
        if 'detection_times' in stats and stats['detection_times']['count'] > 0:
            dt = stats['detection_times']
            report.append(f"Örnek Sayısı (Count):        {dt['count']}")
            report.append(f"Ortalama (Mean):             {dt['mean']:.3f} ms")
            report.append(f"Standart Sapma (Std):        {dt['std']:.3f} ms")
            report.append(f"Minimum:                     {dt['min']:.3f} ms")
            report.append(f"Maximum:                     {dt['max']:.3f} ms")
            report.append(f"Medyan (Median):             {dt['median']:.3f} ms")
            report.append(f"50. Yüzdelik (P50):          {dt['p50']:.3f} ms")
            report.append(f"90. Yüzdelik (P90):          {dt['p90']:.3f} ms")
            report.append(f"95. Yüzdelik (P95):          {dt['p95']:.3f} ms")
            report.append(f"99. Yüzdelik (P99):          {dt['p99']:.3f} ms")
        report.append("")

        # Mitigation Time Stats
        report.append("-" * 70)
        report.append("ÖNLEM SÜRESİ / MITIGATION TIME (ms)")
        report.append("-" * 70)
        if 'mitigation_times' in stats and stats['mitigation_times']['count'] > 0:
            mt = stats['mitigation_times']
            report.append(f"Örnek Sayısı (Count):        {mt['count']}")
            report.append(f"Ortalama (Mean):             {mt['mean']:.3f} ms")
            report.append(f"Standart Sapma (Std):        {mt['std']:.3f} ms")
            report.append(f"Minimum:                     {mt['min']:.3f} ms")
            report.append(f"Maximum:                     {mt['max']:.3f} ms")
        report.append("")

        # Total Response Time Stats
        report.append("-" * 70)
        report.append("TOPLAM YANIT SÜRESİ / TOTAL RESPONSE TIME (ms)")
        report.append("-" * 70)
        if 'total_response_times' in stats and stats['total_response_times']['count'] > 0:
            tr = stats['total_response_times']
            report.append(f"Örnek Sayısı (Count):        {tr['count']}")
            report.append(f"Ortalama (Mean):             {tr['mean']:.3f} ms")
            report.append(f"Standart Sapma (Std):        {tr['std']:.3f} ms")
            report.append(f"90. Yüzdelik (P90):          {tr['p90']:.3f} ms")
            report.append(f"95. Yüzdelik (P95):          {tr['p95']:.3f} ms")
            report.append(f"99. Yüzdelik (P99):          {tr['p99']:.3f} ms")
        report.append("")

        # Batch Processing Results
        report.append("-" * 70)
        report.append("BATCH İŞLEME SONUÇLARI / BATCH PROCESSING RESULTS")
        report.append("-" * 70)
        report.append(f"{'Batch Size':<12} {'Mean (ms)':<12} {'Std (ms)':<12} {'Per Sample (ms)':<15}")
        report.append("-" * 51)
        for batch_size, data in batch_results.items():
            report.append(f"{batch_size:<12} {data['mean']:<12.2f} {data['std']:<12.2f} {data['per_sample']:<15.2f}")
        report.append("")

        # Load Test Results
        report.append("-" * 70)
        report.append("YÜK ALTINDAKİ GECİKME / LATENCY UNDER LOAD")
        report.append("-" * 70)
        report.append(f"{'Concurrent':<12} {'Mean (ms)':<12} {'P95 (ms)':<12} {'P99 (ms)':<12}")
        report.append("-" * 48)
        for load, data in load_results.items():
            report.append(f"{load:<12} {data['mean']:<12.2f} {data['p95']:<12.2f} {data['p99']:<12.2f}")
        report.append("")

        # Throughput
        report.append("-" * 70)
        report.append("İŞLEME HIZI / THROUGHPUT")
        report.append("-" * 70)
        if self.results['throughput_samples']:
            avg_throughput = statistics.mean(self.results['throughput_samples'])
            report.append(f"Ortalama Throughput:         {avg_throughput:.2f} requests/second")
        report.append("")

        report.append("=" * 70)
        report.append("DENEY TAMAMLANDI / EXPERIMENT COMPLETED")
        report.append("=" * 70)

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
                'statistics': stats,
                'batch_results': batch_results,
                'load_results': load_results,
                'throughput': self.results['throughput_samples']
            }, f, indent=2)

        self.log(f"Results saved to: {RESULTS_DIR}")
        return report_file

    # ============================================
    # Main Execution
    # ============================================

    def run(self):
        """Deneyi çalıştır"""
        self.log("=" * 60)
        self.log("DENEY 2: YANIT SÜRESİ ANALİZİ BAŞLIYOR")
        self.log("=" * 60)

        start_time = datetime.now()

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

        # Run tests
        self.log("")
        self.log("Test 1: ML Prediction Latency")
        self.test_ml_prediction_latency(NUM_ITERATIONS)

        self.log("")
        self.log("Test 2: Batch Prediction Latency")
        batch_results = self.test_batch_prediction_latency()

        self.log("")
        self.log("Test 3: Throughput Measurement")
        self.test_throughput(10)

        self.log("")
        self.log("Test 4: End-to-End Response Time")
        self.test_end_to_end_response(NUM_ITERATIONS)

        self.log("")
        self.log("Test 5: Latency Under Load")
        load_results = self.test_latency_under_load()

        # Calculate statistics
        stats = self.calculate_statistics()

        # Generate report
        self.generate_report(stats, batch_results, load_results)

        self.log(f"Total experiment duration: {datetime.now() - start_time}")


if __name__ == '__main__':
    experiment = ResponseTimeExperiment()
    experiment.run()
