#!/usr/bin/env python3
"""
==============================================================================
ANA DENEY ÇALIŞTIRMA SCRIPTİ
==============================================================================

Tüm deneyleri sırasıyla çalıştırır ve sonuçları analiz eder.

Kullanım:
    python run_experiments.py [--exp N] [--skip-analysis]

Author: PhD Research - SDN Security
"""

import os
import sys
import argparse
import subprocess
import time
from datetime import datetime

# Experiment scripts
EXPERIMENTS = {
    1: {
        'name': 'Detection Accuracy (DR, FPR)',
        'script': 'exp1_detection_accuracy.py',
        'description': 'Tespit doğruluğu, yanlış pozitif oranı'
    },
    2: {
        'name': 'Response Time Analysis',
        'script': 'exp2_response_time.py',
        'description': 'ML inference, detection, mitigation süreleri'
    },
    3: {
        'name': 'Attack Types',
        'script': 'exp3_attack_types.py',
        'description': 'Farklı DDoS saldırı türlerinde performans'
    },
    4: {
        'name': 'Scalability Testing',
        'script': 'exp4_scalability.py',
        'description': 'Yük testi, stress testi, ölçeklenebilirlik'
    }
}

def print_header():
    print("=" * 70)
    print("   SDN-IDS TEZ DENEYLERİ")
    print("   HHO-BDT Tabanlı Sızma Tespit Sistemi")
    print("=" * 70)
    print(f"   Başlangıç: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

def run_experiment(exp_id, script_dir):
    """Tek bir deneyi çalıştır"""
    exp_info = EXPERIMENTS.get(exp_id)
    if not exp_info:
        return False

    script_path = os.path.join(script_dir, exp_info['script'])
    print(f"\n[DENEY {exp_id}] {exp_info['name']}")
    print(f"  Script: {exp_info['script']}")

    start_time = time.time()
    try:
        result = subprocess.run([sys.executable, script_path], cwd=script_dir, timeout=3600)
        elapsed = time.time() - start_time
        print(f"  Süre: {elapsed:.1f}s, Sonuç: {'BAŞARILI' if result.returncode == 0 else 'BAŞARISIZ'}")
        return result.returncode == 0
    except Exception as e:
        print(f"  Hata: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Run SDN-IDS Experiments')
    parser.add_argument('--exp', type=int, nargs='+', help='Specific experiment(s)')
    args = parser.parse_args()

    print_header()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    experiments = args.exp if args.exp else list(EXPERIMENTS.keys())

    results = {exp_id: run_experiment(exp_id, script_dir) for exp_id in experiments}

    print("\n" + "=" * 50)
    print("ÖZET:")
    for exp_id, success in results.items():
        print(f"  Deney {exp_id}: {'✓' if success else '✗'}")
    print("=" * 50)

    return 0 if all(results.values()) else 1

if __name__ == '__main__':
    sys.exit(main())
