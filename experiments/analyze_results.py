#!/usr/bin/env python3
"""
==============================================================================
DENEY SONUÇLARI ANALİZ VE GÖRSELLEŞTİRME
==============================================================================

Bu script, tüm deney sonuçlarını analiz eder ve görselleştirir:
- Confusion Matrix
- ROC Curve
- Performance comparison charts
- Latency distribution
- Scalability curves

Author: PhD Research - SDN Security
"""

import os
import json
import glob
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

# Configuration
RESULTS_BASE_DIR = "/tmp/experiment_results"
OUTPUT_DIR = "/tmp/experiment_results/analysis"

class ExperimentAnalyzer:
    """Deney sonuçlarını analiz et ve görselleştir"""

    def __init__(self):
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        plt.style.use('seaborn-v0_8-whitegrid')

    def load_latest_results(self, exp_dir):
        """En son deney sonuçlarını yükle"""
        json_files = glob.glob(f"{RESULTS_BASE_DIR}/{exp_dir}/*.json")
        if not json_files:
            return None

        latest_file = max(json_files, key=os.path.getctime)
        with open(latest_file, 'r') as f:
            return json.load(f)

    # ============================================
    # Deney 1: Tespit Doğruluğu Analizi
    # ============================================

    def analyze_detection_accuracy(self):
        """Deney 1 sonuçlarını analiz et"""
        results = self.load_latest_results('exp1_accuracy')
        if not results:
            print("No Experiment 1 results found")
            return

        metrics = results.get('metrics', {})

        # 1. Confusion Matrix
        fig, ax = plt.subplots(figsize=(8, 6))

        cm = np.array([
            [metrics.get('true_positive', 0), metrics.get('false_negative', 0)],
            [metrics.get('false_positive', 0), metrics.get('true_negative', 0)]
        ])

        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                   xticklabels=['Attack', 'Benign'],
                   yticklabels=['Attack', 'Benign'])
        ax.set_xlabel('Predicted', fontsize=12)
        ax.set_ylabel('Actual', fontsize=12)
        ax.set_title('Confusion Matrix - HHO-BDT Model', fontsize=14)

        plt.tight_layout()
        plt.savefig(f"{OUTPUT_DIR}/exp1_confusion_matrix.png", dpi=150)
        plt.close()

        # 2. Metrics Bar Chart
        fig, ax = plt.subplots(figsize=(10, 6))

        metric_names = ['Accuracy', 'Detection Rate', 'Precision', 'F1-Score', 'Specificity']
        metric_values = [
            metrics.get('accuracy', 0),
            metrics.get('detection_rate', 0),
            metrics.get('precision', 0),
            metrics.get('f1_score', 0),
            metrics.get('specificity', 0)
        ]

        bars = ax.bar(metric_names, metric_values, color=['#2ecc71', '#3498db', '#9b59b6', '#e74c3c', '#f39c12'])

        ax.set_ylabel('Percentage (%)', fontsize=12)
        ax.set_title('Detection Performance Metrics', fontsize=14)
        ax.set_ylim(0, 105)

        # Add value labels
        for bar, val in zip(bars, metric_values):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                   f'{val:.1f}%', ha='center', fontsize=11)

        plt.tight_layout()
        plt.savefig(f"{OUTPUT_DIR}/exp1_metrics.png", dpi=150)
        plt.close()

        print("Experiment 1 analysis complete")
        return metrics

    # ============================================
    # Deney 2: Yanıt Süresi Analizi
    # ============================================

    def analyze_response_time(self):
        """Deney 2 sonuçlarını analiz et"""
        results = self.load_latest_results('exp2_response_time')
        if not results:
            print("No Experiment 2 results found")
            return

        metrics = results.get('metrics', {})

        # 1. Latency Distribution
        fig, ax = plt.subplots(figsize=(10, 6))

        measurements = [m['value'] for m in results.get('measurements', []) if m['type'] == 'ml_inference']
        if measurements:
            ax.hist(measurements, bins=50, color='#3498db', edgecolor='white', alpha=0.7)
            ax.axvline(np.mean(measurements), color='red', linestyle='--', label=f'Mean: {np.mean(measurements):.2f}ms')
            ax.axvline(np.percentile(measurements, 95), color='orange', linestyle='--', label=f'P95: {np.percentile(measurements, 95):.2f}ms')

            ax.set_xlabel('Latency (ms)', fontsize=12)
            ax.set_ylabel('Frequency', fontsize=12)
            ax.set_title('ML Inference Latency Distribution', fontsize=14)
            ax.legend()

        plt.tight_layout()
        plt.savefig(f"{OUTPUT_DIR}/exp2_latency_distribution.png", dpi=150)
        plt.close()

        # 2. Batch Processing Time
        batch_results = metrics.get('batch_inference', {})
        if batch_results:
            fig, ax = plt.subplots(figsize=(10, 6))

            batch_sizes = list(batch_results.keys())
            per_sample_times = [batch_results[bs]['per_sample'] for bs in batch_sizes]

            ax.plot(batch_sizes, per_sample_times, 'o-', color='#e74c3c', markersize=8, linewidth=2)
            ax.set_xlabel('Batch Size', fontsize=12)
            ax.set_ylabel('Time per Sample (ms)', fontsize=12)
            ax.set_title('Batch Processing Efficiency', fontsize=14)
            ax.grid(True, alpha=0.3)

            plt.tight_layout()
            plt.savefig(f"{OUTPUT_DIR}/exp2_batch_efficiency.png", dpi=150)
            plt.close()

        # 3. Response Time Breakdown
        fig, ax = plt.subplots(figsize=(8, 6))

        dtm = metrics.get('detection_mitigation', {})
        if dtm:
            components = ['ML Inference', 'Detection', 'Mitigation', 'Flow Rule']
            times = [
                metrics.get('ml_inference', {}).get('mean', 0),
                dtm.get('detection', {}).get('mean', 0),
                dtm.get('mitigation', {}).get('mean', 0),
                metrics.get('flow_rule', {}).get('mean', 0)
            ]

            colors = ['#3498db', '#2ecc71', '#e74c3c', '#9b59b6']
            ax.barh(components, times, color=colors)
            ax.set_xlabel('Time (ms)', fontsize=12)
            ax.set_title('Response Time Breakdown', fontsize=14)

            for i, v in enumerate(times):
                ax.text(v + 0.5, i, f'{v:.2f}ms', va='center')

        plt.tight_layout()
        plt.savefig(f"{OUTPUT_DIR}/exp2_time_breakdown.png", dpi=150)
        plt.close()

        print("Experiment 2 analysis complete")
        return metrics

    # ============================================
    # Deney 3: Saldırı Türleri Analizi
    # ============================================

    def analyze_attack_types(self):
        """Deney 3 sonuçlarını analiz et"""
        results = self.load_latest_results('exp3_attack_types')
        if not results:
            print("No Experiment 3 results found")
            return

        attack_results = results.get('attack_results', {})

        # 1. Detection Rate by Attack Type
        fig, ax = plt.subplots(figsize=(12, 6))

        attack_types = []
        detection_rates = []

        for attack_type, data in attack_results.items():
            if attack_type != 'BENIGN':
                attack_types.append(attack_type.replace('_', '\n'))
                detection_rates.append(data.get('detection_rate', 0))

        colors = ['#2ecc71' if dr >= 90 else '#f39c12' if dr >= 70 else '#e74c3c' for dr in detection_rates]

        bars = ax.bar(attack_types, detection_rates, color=colors)
        ax.set_ylabel('Detection Rate (%)', fontsize=12)
        ax.set_title('Detection Rate by Attack Type', fontsize=14)
        ax.set_ylim(0, 105)
        ax.axhline(y=90, color='green', linestyle='--', alpha=0.5, label='90% threshold')

        for bar, val in zip(bars, detection_rates):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                   f'{val:.1f}%', ha='center', fontsize=10)

        plt.xticks(rotation=0)
        plt.tight_layout()
        plt.savefig(f"{OUTPUT_DIR}/exp3_detection_by_type.png", dpi=150)
        plt.close()

        # 2. Radar Chart for Attack Types
        if len(attack_types) >= 3:
            fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(projection='polar'))

            angles = np.linspace(0, 2 * np.pi, len(attack_types), endpoint=False).tolist()
            angles += angles[:1]  # Complete the loop

            values = detection_rates + detection_rates[:1]

            ax.plot(angles, values, 'o-', linewidth=2, color='#3498db')
            ax.fill(angles, values, alpha=0.25, color='#3498db')
            ax.set_xticks(angles[:-1])
            ax.set_xticklabels([at.replace('\n', ' ') for at in attack_types], size=10)
            ax.set_ylim(0, 100)
            ax.set_title('Attack Detection Profile', fontsize=14, pad=20)

            plt.tight_layout()
            plt.savefig(f"{OUTPUT_DIR}/exp3_radar_chart.png", dpi=150)
            plt.close()

        print("Experiment 3 analysis complete")
        return attack_results

    # ============================================
    # Deney 4: Ölçeklenebilirlik Analizi
    # ============================================

    def analyze_scalability(self):
        """Deney 4 sonuçlarını analiz et"""
        results = self.load_latest_results('exp4_scalability')
        if not results:
            print("No Experiment 4 results found")
            return

        # 1. Throughput vs Latency
        load_test = results.get('load_test', {})
        if load_test:
            fig, ax1 = plt.subplots(figsize=(10, 6))

            rates = list(load_test.keys())
            throughputs = [load_test[r]['throughput'] for r in rates]
            latencies = [load_test[r]['avg_latency'] for r in rates]

            ax1.set_xlabel('Request Rate (req/s)', fontsize=12)
            ax1.set_ylabel('Throughput (req/s)', color='#3498db', fontsize=12)
            ax1.plot(rates, throughputs, 'o-', color='#3498db', linewidth=2, markersize=8, label='Throughput')
            ax1.tick_params(axis='y', labelcolor='#3498db')

            ax2 = ax1.twinx()
            ax2.set_ylabel('Latency (ms)', color='#e74c3c', fontsize=12)
            ax2.plot(rates, latencies, 's--', color='#e74c3c', linewidth=2, markersize=8, label='Latency')
            ax2.tick_params(axis='y', labelcolor='#e74c3c')

            ax1.set_title('Throughput vs Latency Trade-off', fontsize=14)

            # Combined legend
            lines1, labels1 = ax1.get_legend_handles_labels()
            lines2, labels2 = ax2.get_legend_handles_labels()
            ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')

            plt.tight_layout()
            plt.savefig(f"{OUTPUT_DIR}/exp4_throughput_latency.png", dpi=150)
            plt.close()

        # 2. Stress Test Results
        stress_test = results.get('stress_test', {})
        if stress_test:
            fig, ax = plt.subplots(figsize=(10, 6))

            concurrent = list(stress_test.keys())
            success_rates = [stress_test[c]['success_rate'] for c in concurrent]

            ax.plot(concurrent, success_rates, 'o-', color='#2ecc71', linewidth=2, markersize=8)
            ax.fill_between(concurrent, success_rates, alpha=0.3, color='#2ecc71')
            ax.axhline(y=90, color='orange', linestyle='--', alpha=0.7, label='90% threshold')
            ax.axhline(y=50, color='red', linestyle='--', alpha=0.7, label='50% threshold')

            ax.set_xlabel('Concurrent Requests', fontsize=12)
            ax.set_ylabel('Success Rate (%)', fontsize=12)
            ax.set_title('System Stress Test', fontsize=14)
            ax.legend()
            ax.set_ylim(0, 105)

            plt.tight_layout()
            plt.savefig(f"{OUTPUT_DIR}/exp4_stress_test.png", dpi=150)
            plt.close()

        print("Experiment 4 analysis complete")
        return results

    # ============================================
    # Özet Rapor
    # ============================================

    def generate_summary_report(self):
        """Tüm deneylerin özet raporunu oluştur"""
        report = []
        report.append("=" * 70)
        report.append("TEZ DENEYLERİ ÖZET RAPORU")
        report.append(f"Oluşturulma Tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 70)

        # Exp 1
        exp1 = self.load_latest_results('exp1_accuracy')
        if exp1:
            metrics = exp1.get('metrics', {})
            report.append("\nDENEY 1: TESPİT DOĞRULUĞU")
            report.append("-" * 40)
            report.append(f"  Accuracy:       {metrics.get('accuracy', 0):.2f}%")
            report.append(f"  Detection Rate: {metrics.get('detection_rate', 0):.2f}%")
            report.append(f"  FPR:            {metrics.get('false_positive_rate', 0):.2f}%")
            report.append(f"  F1-Score:       {metrics.get('f1_score', 0):.2f}%")

        # Exp 2
        exp2 = self.load_latest_results('exp2_response_time')
        if exp2:
            metrics = exp2.get('metrics', {})
            report.append("\nDENEY 2: YANIT SÜRESİ")
            report.append("-" * 40)
            inf = metrics.get('ml_inference', {})
            report.append(f"  ML Inference (avg): {inf.get('mean', 0):.2f} ms")
            report.append(f"  ML Inference (p95): {inf.get('p95', 0):.2f} ms")
            tp = metrics.get('throughput', {})
            report.append(f"  Throughput:         {tp.get('throughput', 0):.2f} req/s")

        # Exp 3
        exp3 = self.load_latest_results('exp3_attack_types')
        if exp3:
            summary = exp3.get('summary', {})
            report.append("\nDENEY 3: SALDIRI TÜRLERİ")
            report.append("-" * 40)
            report.append(f"  Avg Detection Rate: {summary.get('avg_detection_rate', 0):.2f}%")
            report.append(f"  Best Detected:      {summary.get('best_detected', 'N/A')}")
            report.append(f"  Worst Detected:     {summary.get('worst_detected', 'N/A')}")

        # Exp 4
        exp4 = self.load_latest_results('exp4_scalability')
        if exp4:
            summary = exp4.get('summary', {})
            report.append("\nDENEY 4: ÖLÇEKLENEBİLİRLİK")
            report.append("-" * 40)
            report.append(f"  Max Throughput:   {summary.get('max_throughput', 0):.2f} req/s")
            report.append(f"  Optimal Rate:     {summary.get('optimal_rate', 0)} req/s")
            report.append(f"  Breaking Point:   {summary.get('breaking_point', 'N/A')} concurrent")

        report.append("\n" + "=" * 70)

        # Save report
        report_text = "\n".join(report)
        print(report_text)

        report_file = f"{OUTPUT_DIR}/summary_report.txt"
        with open(report_file, 'w') as f:
            f.write(report_text)

        print(f"\nReport saved to: {report_file}")

        return report_text

    def run_all_analysis(self):
        """Tüm analizleri çalıştır"""
        print("=" * 60)
        print("Running All Experiment Analysis")
        print("=" * 60)

        self.analyze_detection_accuracy()
        self.analyze_response_time()
        self.analyze_attack_types()
        self.analyze_scalability()
        self.generate_summary_report()

        print("\n" + "=" * 60)
        print(f"All analysis outputs saved to: {OUTPUT_DIR}")
        print("=" * 60)


def main():
    analyzer = ExperimentAnalyzer()
    analyzer.run_all_analysis()


if __name__ == '__main__':
    main()
