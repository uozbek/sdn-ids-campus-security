#!/usr/bin/env python3
"""
==============================================================================
DENEY 4: ÖLÇEKLENEBİLİRLİK TESTİ (Scalability Testing)
==============================================================================

Bu deney, IDS sisteminin ölçeklenebilirliğini test eder:
- Artan trafik yükü altında performans
- Eşzamanlı flow sayısı limitleri
- Kaynak kullanımı (CPU, Memory)
- Throughput vs Latency trade-off

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
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil

# Configuration
ML_SERVICE_URL = "http://172.10.10.100:5000"
RESULTS_DIR = "/tmp/experiment_results/exp4_scalability"

class ScalabilityExperiment:
    """
    Deney 4: Ölçeklenebilirlik Testi

    Test Senaryoları:
    1. Load Test: Artan istek sayısı
    2. Stress Test: Maksimum kapasite
    3. Concurrent Flow Test: Eşzamanlı flow yönetimi
    4. Resource Usage: CPU/Memory kullanımı
    """

    def __init__(self):
        self.results = {
            'experiment_name': 'Scalability Testing',
            'start_time': None,
            'end_time': None,
            'config': {},
            'load_test': {},
            'stress_test': {},
            'concurrent_test': {},
            'resource_usage': []
        }

        os.makedirs(RESULTS_DIR, exist_ok=True)

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] [{level}] {message}")

    def generate_features(self):
        """Test için rastgele özellik üret"""
        return {
            'Flow Duration': random.uniform(1000, 10000000),
            'Total Fwd Packets': random.randint(1, 10000),
            'Total Backward Packets': random.randint(0, 5000),
            'Flow Bytes/s': random.uniform(100, 10000000),
            'Flow Packets/s': random.uniform(1, 100000),
            'Flow IAT Mean': random.uniform(1, 1000000),
            'SYN Flag Count': random.randint(0, 10000),
            'ACK Flag Count': random.randint(0, 10000),
            'Fwd Packet Length Mean': random.uniform(40, 1500),
            'Average Packet Size': random.uniform(40, 1500),
        }

    def single_request(self):
        """Tek bir prediction isteği gönder"""
        try:
            start = time.perf_counter()
            response = requests.post(
                f"{ML_SERVICE_URL}/predict",
                json={'features': self.generate_features()},
                timeout=30
            )
            latency = (time.perf_counter() - start) * 1000

            return {
                'success': response.status_code == 200,
                'latency': latency,
                'status_code': response.status_code
            }
        except Exception as e:
            return {
                'success': False,
                'latency': None,
                'error': str(e)
            }

    def load_test(self, request_rates=[10, 50, 100, 200, 500, 1000], duration=30):
        """
        Load Test: Farklı istek oranlarında performans ölç

        Her oran için:
        - Throughput (successful requests/sec)
        - Average latency
        - Error rate
        """
        self.log("Running Load Test...")
        results = {}

        for rate in request_rates:
            self.log(f"Testing rate: {rate} requests/sec")

            successful = 0
            failed = 0
            latencies = []

            interval = 1.0 / rate
            start_time = time.time()
            next_request = start_time

            while time.time() - start_time < duration:
                current_time = time.time()

                if current_time >= next_request:
                    result = self.single_request()

                    if result['success']:
                        successful += 1
                        if result['latency']:
                            latencies.append(result['latency'])
                    else:
                        failed += 1

                    next_request += interval

                # Small sleep to prevent busy waiting
                time.sleep(0.001)

            elapsed = time.time() - start_time
            actual_rate = (successful + failed) / elapsed

            results[rate] = {
                'target_rate': rate,
                'actual_rate': round(actual_rate, 2),
                'successful': successful,
                'failed': failed,
                'error_rate': round(failed / (successful + failed) * 100, 2) if (successful + failed) > 0 else 0,
                'avg_latency': round(np.mean(latencies), 2) if latencies else 0,
                'p95_latency': round(np.percentile(latencies, 95), 2) if latencies else 0,
                'p99_latency': round(np.percentile(latencies, 99), 2) if latencies else 0,
                'throughput': round(successful / elapsed, 2)
            }

            self.log(f"  Throughput: {results[rate]['throughput']} req/s, "
                    f"Avg Latency: {results[rate]['avg_latency']} ms, "
                    f"Error Rate: {results[rate]['error_rate']}%")

        return results

    def stress_test(self, max_concurrent=500, step=50, duration=10):
        """
        Stress Test: Maksimum eşzamanlı istek kapasitesi

        Eşzamanlı istek sayısını artırarak sistemin sınırlarını test et.
        """
        self.log("Running Stress Test...")
        results = {}

        for concurrent in range(step, max_concurrent + 1, step):
            self.log(f"Testing {concurrent} concurrent requests...")

            successful = 0
            failed = 0
            latencies = []

            with ThreadPoolExecutor(max_workers=concurrent) as executor:
                start_time = time.time()

                # Submit requests for duration
                futures = []
                while time.time() - start_time < duration:
                    future = executor.submit(self.single_request)
                    futures.append(future)

                    # Limit submission rate
                    if len(futures) >= concurrent * 10:
                        time.sleep(0.1)

                # Collect results
                for future in as_completed(futures):
                    try:
                        result = future.result(timeout=1)
                        if result['success']:
                            successful += 1
                            if result['latency']:
                                latencies.append(result['latency'])
                        else:
                            failed += 1
                    except:
                        failed += 1

            elapsed = duration
            total = successful + failed

            results[concurrent] = {
                'concurrent_requests': concurrent,
                'total_requests': total,
                'successful': successful,
                'failed': failed,
                'success_rate': round(successful / total * 100, 2) if total > 0 else 0,
                'throughput': round(successful / elapsed, 2),
                'avg_latency': round(np.mean(latencies), 2) if latencies else 0,
                'p95_latency': round(np.percentile(latencies, 95), 2) if latencies else 0,
            }

            self.log(f"  Success Rate: {results[concurrent]['success_rate']}%, "
                    f"Throughput: {results[concurrent]['throughput']} req/s")

            # Stop if system is overwhelmed
            if results[concurrent]['success_rate'] < 50:
                self.log("System overwhelmed, stopping stress test")
                break

        return results

    def concurrent_flow_test(self, flow_counts=[100, 500, 1000, 5000, 10000]):
        """
        Concurrent Flow Test: Farklı flow sayılarında bellek/performans

        Simüle edilen flow sayısı arttıkça sistemin davranışını ölç.
        """
        self.log("Running Concurrent Flow Test...")
        results = {}

        for flow_count in flow_counts:
            self.log(f"Testing with {flow_count} concurrent flows...")

            # Simulate multiple flows with batch requests
            batch_size = min(100, flow_count)
            features_list = [self.generate_features() for _ in range(batch_size)]

            start = time.perf_counter()

            # Send batch requests
            iterations = flow_count // batch_size
            successful_batches = 0

            for _ in range(iterations):
                try:
                    response = requests.post(
                        f"{ML_SERVICE_URL}/predict/batch",
                        json={'features_list': features_list},
                        timeout=60
                    )
                    if response.status_code == 200:
                        successful_batches += 1
                except:
                    pass

            elapsed = time.perf_counter() - start

            results[flow_count] = {
                'flow_count': flow_count,
                'batch_size': batch_size,
                'total_time': round(elapsed, 2),
                'flows_per_second': round(flow_count / elapsed, 2),
                'success_rate': round(successful_batches / iterations * 100, 2) if iterations > 0 else 0
            }

            self.log(f"  Processing Rate: {results[flow_count]['flows_per_second']} flows/s")

        return results

    def resource_usage_monitor(self, duration=60, interval=1):
        """
        Resource Usage: CPU ve Memory kullanımını izle

        Belirli süre boyunca kaynak kullanımını kaydet.
        """
        self.log(f"Monitoring resource usage for {duration} seconds...")
        measurements = []

        start_time = time.time()

        while time.time() - start_time < duration:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()

            measurements.append({
                'timestamp': time.time() - start_time,
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_used_mb': memory.used / (1024 * 1024),
                'memory_available_mb': memory.available / (1024 * 1024)
            })

            time.sleep(interval - 0.1)

        return measurements

    def run_experiment(self, config=None):
        """Ana deney prosedürü"""
        if config is None:
            config = {
                'load_test': {
                    'request_rates': [10, 50, 100, 200, 500],
                    'duration': 30
                },
                'stress_test': {
                    'max_concurrent': 300,
                    'step': 50,
                    'duration': 10
                },
                'flow_test': {
                    'flow_counts': [100, 500, 1000, 5000]
                },
                'resource_monitor': {
                    'duration': 60,
                    'interval': 1
                }
            }

        self.results['config'] = config
        self.results['start_time'] = datetime.now().isoformat()

        self.log("=" * 60)
        self.log("DENEY 4: ÖLÇEKLENEBİLİRLİK TESTİ")
        self.log("=" * 60)

        # 1. Load Test
        self.log("\n[1/4] Load Test")
        self.results['load_test'] = self.load_test(
            request_rates=config['load_test']['request_rates'],
            duration=config['load_test']['duration']
        )

        # 2. Stress Test
        self.log("\n[2/4] Stress Test")
        self.results['stress_test'] = self.stress_test(
            max_concurrent=config['stress_test']['max_concurrent'],
            step=config['stress_test']['step'],
            duration=config['stress_test']['duration']
        )

        # 3. Concurrent Flow Test
        self.log("\n[3/4] Concurrent Flow Test")
        self.results['concurrent_test'] = self.concurrent_flow_test(
            flow_counts=config['flow_test']['flow_counts']
        )

        # 4. Resource Usage (optional - needs continuous load)
        self.log("\n[4/4] Resource Usage Monitoring")
        self.log("Note: Run load in parallel for accurate measurements")
        # self.results['resource_usage'] = self.resource_usage_monitor(...)

        self.results['end_time'] = datetime.now().isoformat()

        self.generate_summary()
        self.print_results()
        self.save_results()

        return self.results

    def generate_summary(self):
        """Özet metrikleri hesapla"""
        load_results = self.results['load_test']
        stress_results = self.results['stress_test']

        # Find optimal operating point
        max_throughput = 0
        optimal_rate = 0
        for rate, data in load_results.items():
            if data['throughput'] > max_throughput and data['error_rate'] < 5:
                max_throughput = data['throughput']
                optimal_rate = rate

        # Find breaking point
        breaking_point = None
        for concurrent, data in stress_results.items():
            if data['success_rate'] < 90:
                breaking_point = concurrent
                break

        self.results['summary'] = {
            'max_throughput': max_throughput,
            'optimal_rate': optimal_rate,
            'breaking_point': breaking_point,
            'max_concurrent_tested': max(stress_results.keys()) if stress_results else 0
        }

    def print_results(self):
        """Sonuçları yazdır"""
        print("\n" + "=" * 70)
        print("DENEY SONUÇLARI: ÖLÇEKLENEBİLİRLİK")
        print("=" * 70)

        print("\n1. Load Test Results:")
        print("{:<15} {:>15} {:>15} {:>15}".format(
            "Rate (req/s)", "Throughput", "Avg Latency", "Error Rate"
        ))
        print("-" * 60)
        for rate, data in self.results['load_test'].items():
            print(f"{rate:<15} {data['throughput']:>15.2f} "
                  f"{data['avg_latency']:>12.2f} ms {data['error_rate']:>12.2f}%")

        print("\n2. Stress Test Results:")
        print("{:<15} {:>15} {:>15} {:>15}".format(
            "Concurrent", "Success Rate", "Throughput", "P95 Latency"
        ))
        print("-" * 60)
        for concurrent, data in self.results['stress_test'].items():
            print(f"{concurrent:<15} {data['success_rate']:>14.1f}% "
                  f"{data['throughput']:>15.2f} {data['p95_latency']:>12.2f} ms")

        print("\n3. Concurrent Flow Test:")
        for flow_count, data in self.results['concurrent_test'].items():
            print(f"  {flow_count} flows: {data['flows_per_second']:.2f} flows/s")

        summary = self.results.get('summary', {})
        print("\n" + "-" * 70)
        print("ÖZET:")
        print(f"  Maksimum Throughput: {summary.get('max_throughput', 0):.2f} req/s")
        print(f"  Optimal Request Rate: {summary.get('optimal_rate', 0)} req/s")
        print(f"  Breaking Point: {summary.get('breaking_point', 'N/A')} concurrent")
        print("=" * 70)

    def save_results(self):
        """Sonuçları kaydet"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # JSON
        json_file = f"{RESULTS_DIR}/exp4_results_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        self.log(f"Results saved to: {json_file}")

        # CSV - Load test
        if self.results['load_test']:
            df = pd.DataFrame(self.results['load_test']).T
            csv_file = f"{RESULTS_DIR}/exp4_load_test_{timestamp}.csv"
            df.to_csv(csv_file)
            self.log(f"Load test data saved to: {csv_file}")

        # CSV - Stress test
        if self.results['stress_test']:
            df = pd.DataFrame(self.results['stress_test']).T
            csv_file = f"{RESULTS_DIR}/exp4_stress_test_{timestamp}.csv"
            df.to_csv(csv_file)
            self.log(f"Stress test data saved to: {csv_file}")


def main():
    experiment = ScalabilityExperiment()

    config = {
        'load_test': {
            'request_rates': [10, 50, 100, 200, 500],
            'duration': 30
        },
        'stress_test': {
            'max_concurrent': 300,
            'step': 50,
            'duration': 10
        },
        'flow_test': {
            'flow_counts': [100, 500, 1000, 5000]
        },
        'resource_monitor': {
            'duration': 60,
            'interval': 1
        }
    }

    results = experiment.run_experiment(config)

    # Success: max throughput > 100 req/s
    return 0 if results['summary'].get('max_throughput', 0) > 100 else 1


if __name__ == '__main__':
    sys.exit(main())
