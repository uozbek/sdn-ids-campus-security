#!/usr/bin/env python3
"""
============================================
Deney 4: Ölçeklenebilirlik Testi (Scalability Test)
============================================

Bu deney, sistemin ölçeklenebilirliğini test eder:
- Farklı trafik yüklerinde performans
- CPU ve bellek kullanımı
- Throughput vs Latency trade-off
- Sistem kapasitesi limitleri

Author: PhD Research - SDN Security
"""

import requests
import time
import json
import csv
import threading
import statistics
import os
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Configuration
ML_SERVICE_URL = "http://172.10.10.100:5000"
CONTROLLER_URL = "http://172.10.10.10:8080"
RESULTS_DIR = "/tmp/experiment_results"
EXPERIMENT_NAME = "deney4_olceklenebilirlik"


class ScalabilityExperiment:
    """Deney 4: Ölçeklenebilirlik Testi"""

    def __init__(self):
        self.results = {
            'load_tests': [],
            'throughput_tests': [],
            'stress_tests': [],
            'resource_usage': []
        }
        os.makedirs(RESULTS_DIR, exist_ok=True)

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] [{level}] {message}")

    def get_attack_features(self):
        """Test için saldırı özellikleri"""
        import random
        return {
            'Flow Duration': random.uniform(1000, 50000),
            'Total Fwd Packets': random.randint(5000, 50000),
            'Total Backward Packets': random.randint(0, 10),
            'Fwd Packet Length Max': random.randint(40, 60),
            'Fwd Packet Length Mean': random.uniform(40, 60),
            'Flow Bytes/s': random.uniform(500000, 5000000),
            'Flow Packets/s': random.uniform(10000, 100000),
            'Flow IAT Mean': random.uniform(1, 50),
            'SYN Flag Count': random.randint(5000, 50000),
            'Subflow Fwd Packets': random.randint(5000, 50000),
        }

    # ============================================
    # Test 1: Load Testing (Different Request Rates)
    # ============================================

    def test_load_levels(self, load_levels=[10, 25, 50, 100, 200, 500]):
        """Farklı yük seviyelerinde test"""
        self.log(f"Testing load levels: {load_levels}")

        results = []

        for target_rps in load_levels:
            self.log(f"\n  Testing {target_rps} requests/second...")

            # Calculate delay between requests
            delay = 1.0 / target_rps
            duration = 10  # 10 seconds per test
            expected_requests = target_rps * duration

            latencies = []
            success_count = 0
            error_count = 0
            start_time = time.time()

            while time.time() - start_time < duration:
                request_start = time.perf_counter()

                try:
                    response = requests.post(
                        f"{ML_SERVICE_URL}/predict",
                        json={'features': self.get_attack_features()},
                        timeout=5
                    )

                    if response.status_code == 200:
                        latency = (time.perf_counter() - request_start) * 1000
                        latencies.append(latency)
                        success_count += 1
                    else:
                        error_count += 1

                except Exception as e:
                    error_count += 1

                # Wait to maintain target rate
                elapsed = time.perf_counter() - request_start
                sleep_time = delay - elapsed
                if sleep_time > 0:
                    time.sleep(sleep_time)

            actual_duration = time.time() - start_time
            actual_rps = success_count / actual_duration

            result = {
                'target_rps': target_rps,
                'actual_rps': actual_rps,
                'success_count': success_count,
                'error_count': error_count,
                'error_rate': error_count / (success_count + error_count) if (success_count + error_count) > 0 else 0,
                'avg_latency_ms': statistics.mean(latencies) if latencies else 0,
                'p50_latency_ms': sorted(latencies)[len(latencies)//2] if latencies else 0,
                'p95_latency_ms': sorted(latencies)[int(len(latencies)*0.95)] if len(latencies) > 20 else (sorted(latencies)[-1] if latencies else 0),
                'p99_latency_ms': sorted(latencies)[int(len(latencies)*0.99)] if len(latencies) > 100 else (sorted(latencies)[-1] if latencies else 0),
            }

            results.append(result)
            self.results['load_tests'].append(result)

            self.log(f"    Target: {target_rps} RPS, Actual: {actual_rps:.1f} RPS, "
                    f"Latency: {result['avg_latency_ms']:.2f}ms, Errors: {error_count}")

        return results

    # ============================================
    # Test 2: Concurrent Users Simulation
    # ============================================

    def test_concurrent_users(self, user_counts=[1, 5, 10, 20, 50, 100]):
        """Eşzamanlı kullanıcı simülasyonu"""
        self.log(f"\nTesting concurrent users: {user_counts}")

        results = []

        for num_users in user_counts:
            self.log(f"\n  Testing {num_users} concurrent users...")

            requests_per_user = 50
            all_latencies = []
            all_errors = []

            def user_session():
                """Simulate a user making requests"""
                latencies = []
                errors = 0

                for _ in range(requests_per_user):
                    start = time.perf_counter()
                    try:
                        response = requests.post(
                            f"{ML_SERVICE_URL}/predict",
                            json={'features': self.get_attack_features()},
                            timeout=10
                        )
                        if response.status_code == 200:
                            latencies.append((time.perf_counter() - start) * 1000)
                        else:
                            errors += 1
                    except:
                        errors += 1

                    time.sleep(0.01)  # Small delay between requests

                return latencies, errors

            start_time = time.time()

            with ThreadPoolExecutor(max_workers=num_users) as executor:
                futures = [executor.submit(user_session) for _ in range(num_users)]

                for future in as_completed(futures):
                    lat, err = future.result()
                    all_latencies.extend(lat)
                    all_errors.append(err)

            duration = time.time() - start_time
            total_requests = len(all_latencies) + sum(all_errors)
            throughput = len(all_latencies) / duration

            result = {
                'concurrent_users': num_users,
                'total_requests': total_requests,
                'successful_requests': len(all_latencies),
                'failed_requests': sum(all_errors),
                'throughput_rps': throughput,
                'avg_latency_ms': statistics.mean(all_latencies) if all_latencies else 0,
                'p95_latency_ms': sorted(all_latencies)[int(len(all_latencies)*0.95)] if len(all_latencies) > 20 else 0,
                'duration_seconds': duration
            }

            results.append(result)
            self.log(f"    Users: {num_users}, Throughput: {throughput:.1f} RPS, "
                    f"Latency: {result['avg_latency_ms']:.2f}ms")

        return results

    # ============================================
    # Test 3: Stress Test (Find Breaking Point)
    # ============================================

    def test_stress(self, duration_per_level=30):
        """Sistem kapasitesini test et"""
        self.log(f"\nStress testing (finding system limits)...")

        results = []
        current_rps = 50
        max_rps = 0
        breaking_point_found = False

        while not breaking_point_found and current_rps < 2000:
            self.log(f"\n  Testing at {current_rps} RPS...")

            latencies = []
            errors = 0
            success = 0

            start_time = time.time()
            delay = 1.0 / current_rps

            while time.time() - start_time < duration_per_level:
                req_start = time.perf_counter()

                try:
                    response = requests.post(
                        f"{ML_SERVICE_URL}/predict",
                        json={'features': self.get_attack_features()},
                        timeout=5
                    )

                    if response.status_code == 200:
                        latencies.append((time.perf_counter() - req_start) * 1000)
                        success += 1
                    else:
                        errors += 1

                except:
                    errors += 1

                elapsed = time.perf_counter() - req_start
                if delay > elapsed:
                    time.sleep(delay - elapsed)

            duration = time.time() - start_time
            actual_rps = success / duration
            error_rate = errors / (success + errors) if (success + errors) > 0 else 0
            avg_latency = statistics.mean(latencies) if latencies else 0

            result = {
                'target_rps': current_rps,
                'actual_rps': actual_rps,
                'error_rate': error_rate,
                'avg_latency_ms': avg_latency,
                'success_count': success,
                'error_count': errors
            }

            results.append(result)
            self.results['stress_tests'].append(result)

            self.log(f"    Actual: {actual_rps:.1f} RPS, Errors: {error_rate*100:.1f}%, "
                    f"Latency: {avg_latency:.2f}ms")

            # Check for breaking point conditions
            if error_rate > 0.1:  # >10% error rate
                self.log(f"    Breaking point reached: High error rate")
                breaking_point_found = True
            elif avg_latency > 1000:  # >1 second latency
                self.log(f"    Breaking point reached: High latency")
                breaking_point_found = True
            elif actual_rps < current_rps * 0.8:  # Can't keep up
                self.log(f"    Breaking point reached: Can't maintain target rate")
                breaking_point_found = True
            else:
                max_rps = current_rps
                current_rps = int(current_rps * 1.5)  # Increase by 50%

        self.log(f"\n  Maximum sustainable RPS: {max_rps}")
        return results, max_rps

    # ============================================
    # Test 4: Batch Size Scaling
    # ============================================

    def test_batch_scaling(self, batch_sizes=[1, 5, 10, 20, 50, 100, 200]):
        """Batch boyutu ölçeklendirme testi"""
        self.log(f"\nTesting batch size scaling: {batch_sizes}")

        results = []

        for batch_size in batch_sizes:
            self.log(f"\n  Testing batch size: {batch_size}...")

            latencies = []
            throughputs = []

            for _ in range(10):  # 10 iterations per batch size
                features_list = [self.get_attack_features() for _ in range(batch_size)]

                start = time.perf_counter()

                try:
                    response = requests.post(
                        f"{ML_SERVICE_URL}/predict/batch",
                        json={'features_list': features_list},
                        timeout=60
                    )

                    if response.status_code == 200:
                        elapsed = (time.perf_counter() - start) * 1000
                        latencies.append(elapsed)
                        throughputs.append(batch_size / (elapsed / 1000))

                except Exception as e:
                    self.log(f"    Batch request failed: {e}", "ERROR")

            if latencies:
                result = {
                    'batch_size': batch_size,
                    'avg_latency_ms': statistics.mean(latencies),
                    'std_latency_ms': statistics.stdev(latencies) if len(latencies) > 1 else 0,
                    'avg_throughput_rps': statistics.mean(throughputs),
                    'latency_per_sample_ms': statistics.mean(latencies) / batch_size
                }

                results.append(result)
                self.log(f"    Latency: {result['avg_latency_ms']:.2f}ms, "
                        f"Throughput: {result['avg_throughput_rps']:.1f} samples/sec")

        return results

    # ============================================
    # Test 5: Long Running Stability
    # ============================================

    def test_stability(self, duration_minutes=5, target_rps=50):
        """Uzun süreli kararlılık testi"""
        self.log(f"\nStability test ({duration_minutes} minutes at {target_rps} RPS)...")

        duration_seconds = duration_minutes * 60
        delay = 1.0 / target_rps

        # Collect metrics every 30 seconds
        interval = 30
        metrics_timeline = []

        start_time = time.time()
        interval_start = start_time
        interval_latencies = []
        interval_errors = 0

        while time.time() - start_time < duration_seconds:
            req_start = time.perf_counter()

            try:
                response = requests.post(
                    f"{ML_SERVICE_URL}/predict",
                    json={'features': self.get_attack_features()},
                    timeout=5
                )

                if response.status_code == 200:
                    interval_latencies.append((time.perf_counter() - req_start) * 1000)
                else:
                    interval_errors += 1

            except:
                interval_errors += 1

            # Check if interval completed
            if time.time() - interval_start >= interval:
                metrics_timeline.append({
                    'timestamp': time.time() - start_time,
                    'requests': len(interval_latencies) + interval_errors,
                    'errors': interval_errors,
                    'avg_latency_ms': statistics.mean(interval_latencies) if interval_latencies else 0,
                    'p95_latency_ms': sorted(interval_latencies)[int(len(interval_latencies)*0.95)] if len(interval_latencies) > 20 else 0
                })

                elapsed_min = (time.time() - start_time) / 60
                self.log(f"  [{elapsed_min:.1f}min] "
                        f"Latency: {metrics_timeline[-1]['avg_latency_ms']:.2f}ms, "
                        f"Errors: {interval_errors}")

                interval_start = time.time()
                interval_latencies = []
                interval_errors = 0

            elapsed = time.perf_counter() - req_start
            if delay > elapsed:
                time.sleep(delay - elapsed)

        return metrics_timeline

    # ============================================
    # Calculate Overall Metrics
    # ============================================

    def calculate_scalability_metrics(self, load_results, user_results, batch_results, max_rps):
        """Ölçeklenebilirlik metriklerini hesapla"""
        metrics = {
            'max_sustainable_rps': max_rps,
            'load_test_summary': {},
            'user_test_summary': {},
            'batch_test_summary': {},
            'scalability_factors': {}
        }

        # Load test analysis
        if load_results:
            metrics['load_test_summary'] = {
                'tested_levels': [r['target_rps'] for r in load_results],
                'achieved_rps': [r['actual_rps'] for r in load_results],
                'latency_growth': [r['avg_latency_ms'] for r in load_results]
            }

        # User scaling analysis
        if user_results:
            base_throughput = user_results[0]['throughput_rps']
            scaling_efficiency = []
            for r in user_results:
                expected = base_throughput * r['concurrent_users']
                actual = r['throughput_rps']
                efficiency = actual / expected if expected > 0 else 0
                scaling_efficiency.append(efficiency)

            metrics['user_test_summary'] = {
                'max_concurrent_users': user_results[-1]['concurrent_users'],
                'scaling_efficiency': scaling_efficiency
            }

        # Batch scaling analysis
        if batch_results:
            metrics['batch_test_summary'] = {
                'optimal_batch_size': max(batch_results, key=lambda x: x['avg_throughput_rps'])['batch_size'],
                'max_throughput_rps': max(r['avg_throughput_rps'] for r in batch_results)
            }

        return metrics

    # ============================================
    # Generate Report
    # ============================================

    def generate_report(self, load_results, user_results, stress_results, batch_results, stability_results, max_rps):
        """Detaylı rapor oluştur"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{RESULTS_DIR}/{EXPERIMENT_NAME}_{timestamp}.txt"

        report = []
        report.append("=" * 80)
        report.append("DENEY 4: ÖLÇEKLENEBİLİRLİK TESTİ")
        report.append("Scalability Test Report")
        report.append("=" * 80)
        report.append(f"Tarih/Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"ML Service: {ML_SERVICE_URL}")
        report.append("")

        # Load Test Results
        report.append("-" * 80)
        report.append("YÜK TESTİ SONUÇLARI / LOAD TEST RESULTS")
        report.append("-" * 80)
        report.append(f"{'Hedef RPS':<12} {'Gerçek RPS':<12} {'Ort. Gecikme':<15} {'P95 Gecikme':<15} {'Hata %':<10}")
        report.append("-" * 64)
        for r in load_results:
            report.append(f"{r['target_rps']:<12} {r['actual_rps']:<12.1f} {r['avg_latency_ms']:<15.2f} "
                         f"{r['p95_latency_ms']:<15.2f} {r['error_rate']*100:<10.2f}")
        report.append("")

        # Concurrent Users Results
        report.append("-" * 80)
        report.append("EŞZAMANLI KULLANICI TESTİ / CONCURRENT USERS TEST")
        report.append("-" * 80)
        report.append(f"{'Kullanıcı':<12} {'Throughput':<15} {'Ort. Gecikme':<15} {'P95 Gecikme':<15}")
        report.append("-" * 57)
        for r in user_results:
            report.append(f"{r['concurrent_users']:<12} {r['throughput_rps']:<15.1f} {r['avg_latency_ms']:<15.2f} "
                         f"{r['p95_latency_ms']:<15.2f}")
        report.append("")

        # Stress Test Results
        report.append("-" * 80)
        report.append("STRES TESTİ SONUÇLARI / STRESS TEST RESULTS")
        report.append("-" * 80)
        report.append(f"Maksimum Sürdürülebilir RPS: {max_rps}")
        report.append("")
        for r in stress_results:
            report.append(f"  {r['target_rps']} RPS -> Actual: {r['actual_rps']:.1f}, "
                         f"Errors: {r['error_rate']*100:.1f}%, Latency: {r['avg_latency_ms']:.2f}ms")
        report.append("")

        # Batch Scaling Results
        report.append("-" * 80)
        report.append("BATCH ÖLÇEKLENDİRME / BATCH SCALING")
        report.append("-" * 80)
        report.append(f"{'Batch Boyutu':<15} {'Toplam Gecikme':<18} {'Örnek Başına':<18} {'Throughput':<15}")
        report.append("-" * 66)
        for r in batch_results:
            report.append(f"{r['batch_size']:<15} {r['avg_latency_ms']:<18.2f} "
                         f"{r['latency_per_sample_ms']:<18.3f} {r['avg_throughput_rps']:<15.1f}")
        report.append("")

        # Stability Test Results
        if stability_results:
            report.append("-" * 80)
            report.append("KARARLILIK TESTİ / STABILITY TEST")
            report.append("-" * 80)
            avg_latency = statistics.mean([m['avg_latency_ms'] for m in stability_results])
            max_latency = max([m['avg_latency_ms'] for m in stability_results])
            total_errors = sum([m['errors'] for m in stability_results])
            report.append(f"Ortalama Gecikme: {avg_latency:.2f} ms")
            report.append(f"Maksimum Gecikme: {max_latency:.2f} ms")
            report.append(f"Toplam Hata: {total_errors}")
            report.append(f"Gecikme Varyasyonu: {statistics.stdev([m['avg_latency_ms'] for m in stability_results]):.2f} ms")
        report.append("")

        # Summary
        report.append("-" * 80)
        report.append("ÖZET / SUMMARY")
        report.append("-" * 80)
        report.append(f"Maksimum Sürdürülebilir Yük:    {max_rps} RPS")
        if batch_results:
            optimal_batch = max(batch_results, key=lambda x: x['avg_throughput_rps'])
            report.append(f"Optimal Batch Boyutu:           {optimal_batch['batch_size']}")
            report.append(f"Maksimum Batch Throughput:      {optimal_batch['avg_throughput_rps']:.1f} samples/sec")
        if user_results:
            report.append(f"Test Edilen Maks Kullanıcı:     {user_results[-1]['concurrent_users']}")
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
                'load_results': load_results,
                'user_results': user_results,
                'stress_results': stress_results,
                'batch_results': batch_results,
                'stability_results': stability_results,
                'max_sustainable_rps': max_rps
            }, f, indent=2)

        self.log(f"Results saved to: {RESULTS_DIR}")
        return report_file

    # ============================================
    # Main Execution
    # ============================================

    def run(self, include_stability=False):
        """Deneyi çalıştır"""
        self.log("=" * 60)
        self.log("DENEY 4: ÖLÇEKLENEBİLİRLİK TESTİ BAŞLIYOR")
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

        # Run tests
        self.log("\n" + "="*50)
        self.log("Test 1: Load Levels")
        self.log("="*50)
        load_results = self.test_load_levels()

        self.log("\n" + "="*50)
        self.log("Test 2: Concurrent Users")
        self.log("="*50)
        user_results = self.test_concurrent_users()

        self.log("\n" + "="*50)
        self.log("Test 3: Stress Test")
        self.log("="*50)
        stress_results, max_rps = self.test_stress()

        self.log("\n" + "="*50)
        self.log("Test 4: Batch Scaling")
        self.log("="*50)
        batch_results = self.test_batch_scaling()

        stability_results = []
        if include_stability:
            self.log("\n" + "="*50)
            self.log("Test 5: Stability Test")
            self.log("="*50)
            stability_results = self.test_stability(duration_minutes=5)

        # Generate report
        self.generate_report(load_results, user_results, stress_results,
                           batch_results, stability_results, max_rps)

        self.log(f"\nTotal experiment duration: {datetime.now() - start_time}")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Deney 4: Ölçeklenebilirlik Testi')
    parser.add_argument('--stability', action='store_true',
                       help='Kararlılık testini de çalıştır (5 dakika)')

    args = parser.parse_args()

    experiment = ScalabilityExperiment()
    experiment.run(include_stability=args.stability)
