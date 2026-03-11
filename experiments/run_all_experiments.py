#!/usr/bin/env python3
"""
==============================================================================
TÜM DENEYLERİ ÇALIŞTIR - MASTER SCRIPT
==============================================================================

Bu script tüm tez deneylerini sırayla çalıştırır ve sonuçları birleştirir.

Deneyler:
1. Tespit Doğruluğu (Detection Rate, FPR)
2. Yanıt Süresi Analizi
3. Farklı Saldırı Türleri
4. Ölçeklenebilirlik Testi

Author: PhD Research - SDN Security
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def run_experiment(exp_name, exp_module, config=None):
    """Tek bir deneyi çalıştır"""
    print(f"\n{'='*60}")
    print(f"RUNNING: {exp_name}")
    print(f"{'='*60}")

    start_time = time.time()

    try:
        if exp_name == "Detection Accuracy":
            from exp1_detection_accuracy import DetectionAccuracyExperiment
            exp = DetectionAccuracyExperiment()
            results = exp.run_experiment(config)

        elif exp_name == "Response Time":
            from exp2_response_time import ResponseTimeExperiment
            exp = ResponseTimeExperiment()
            results = exp.run_experiment(config)

        elif exp_name == "Attack Types":
            from exp3_attack_types import AttackTypesExperiment
            exp = AttackTypesExperiment()
            results = exp.run_experiment(config)

        elif exp_name == "Scalability":
            from exp4_scalability import ScalabilityExperiment
            exp = ScalabilityExperiment()
            results = exp.run_experiment(config)
        else:
            print(f"Unknown experiment: {exp_name}")
            return None

        elapsed = time.time() - start_time
        print(f"\n{exp_name} completed in {elapsed:.2f} seconds")

        return results

    except Exception as e:
        print(f"ERROR in {exp_name}: {e}")
        import traceback
        traceback.print_exc()
        return None


def main():
    parser = argparse.ArgumentParser(description='Run all thesis experiments')
    parser.add_argument('--exp', type=int, choices=[1, 2, 3, 4],
                       help='Run specific experiment (1-4)')
    parser.add_argument('--quick', action='store_true',
                       help='Run quick test with reduced samples')
    parser.add_argument('--skip-analysis', action='store_true',
                       help='Skip final analysis')

    args = parser.parse_args()

    print("=" * 70)
    print("SDN-IDS TEZ DENEYLERİ")
    print(f"Başlangıç: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    # Quick test configurations
    if args.quick:
        configs = {
            1: {'num_rounds': 2, 'benign_per_round': 20, 'attack_per_round': 20, 'attack_types': ['syn_flood']},
            2: {'inference_samples': 100, 'batch_sizes': [1, 10, 50], 'detection_tests': 10, 'throughput_duration': 10},
            3: {'attack_samples': 50, 'benign_samples': 100, 'attack_types': ['SYN_Flood', 'UDP_Flood', 'HTTP_Flood']},
            4: {'load_test': {'request_rates': [10, 50, 100], 'duration': 10},
                'stress_test': {'max_concurrent': 100, 'step': 25, 'duration': 5},
                'flow_test': {'flow_counts': [100, 500]},
                'resource_monitor': {'duration': 30, 'interval': 2}}
        }
    else:
        configs = {1: None, 2: None, 3: None, 4: None}

    experiments = [
        (1, "Detection Accuracy", "exp1_detection_accuracy"),
        (2, "Response Time", "exp2_response_time"),
        (3, "Attack Types", "exp3_attack_types"),
        (4, "Scalability", "exp4_scalability")
    ]

    all_results = {}
    total_start = time.time()

    for exp_num, exp_name, exp_module in experiments:
        if args.exp and args.exp != exp_num:
            continue

        results = run_experiment(exp_name, exp_module, configs.get(exp_num))
        all_results[exp_name] = results

    total_elapsed = time.time() - total_start

    # Run analysis
    if not args.skip_analysis and not args.exp:
        print(f"\n{'='*60}")
        print("RUNNING ANALYSIS")
        print(f"{'='*60}")

        try:
            from analyze_results import ExperimentAnalyzer
            analyzer = ExperimentAnalyzer()
            analyzer.run_all_analysis()
        except Exception as e:
            print(f"Analysis error: {e}")

    # Summary
    print("\n" + "=" * 70)
    print("TÜM DENEYLER TAMAMLANDI")
    print("=" * 70)
    print(f"Toplam Süre: {total_elapsed/60:.2f} dakika")
    print(f"Bitiş: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Quick summary of key metrics
    print("\n--- ÖZET METRİKLER ---")

    if "Detection Accuracy" in all_results and all_results["Detection Accuracy"]:
        metrics = all_results["Detection Accuracy"].get('metrics', {})
        print(f"Detection Rate: {metrics.get('detection_rate', 'N/A')}%")
        print(f"False Positive Rate: {metrics.get('false_positive_rate', 'N/A')}%")

    if "Response Time" in all_results and all_results["Response Time"]:
        metrics = all_results["Response Time"].get('metrics', {})
        inf = metrics.get('ml_inference', {})
        print(f"ML Inference (avg): {inf.get('mean', 'N/A')} ms")

    if "Attack Types" in all_results and all_results["Attack Types"]:
        summary = all_results["Attack Types"].get('summary', {})
        print(f"Avg Attack Detection: {summary.get('avg_detection_rate', 'N/A')}%")

    if "Scalability" in all_results and all_results["Scalability"]:
        summary = all_results["Scalability"].get('summary', {})
        print(f"Max Throughput: {summary.get('max_throughput', 'N/A')} req/s")

    print("=" * 70)
    print("\nSonuç dosyaları: /tmp/experiment_results/")
    print("Grafik dosyaları: /tmp/experiment_results/analysis/")


if __name__ == '__main__':
    main()
