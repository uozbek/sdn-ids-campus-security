#!/usr/bin/env python3
"""
============================================
Tüm Deneyleri Çalıştır ve Analiz Et
============================================

Bu script tüm deneyleri sırayla çalıştırır ve
birleşik analiz raporu oluşturur.

Author: PhD Research - SDN Security
"""

import os
import sys
import json
import time
from datetime import datetime
import subprocess

# Add experiment directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

RESULTS_DIR = "/tmp/experiment_results"


def run_all_experiments():
    """Tüm deneyleri çalıştır"""
    print("=" * 70)
    print("SDN-IDS TEZ DENEYLERİ")
    print("Tüm Deneyleri Çalıştır ve Analiz Et")
    print("=" * 70)
    print(f"Başlangıç: {datetime.now()}")
    print("=" * 70)
    print()

    os.makedirs(RESULTS_DIR, exist_ok=True)

    results = {}

    # Deney 1: Tespit Doğruluğu
    print("\n" + "=" * 70)
    print("DENEY 1: TESPİT DOĞRULUĞU (DR, FPR)")
    print("=" * 70)
    try:
        from deney1_tespit_dogrulugu import DetectionAccuracyExperiment
        exp1 = DetectionAccuracyExperiment()
        results['deney1'] = exp1.run(benign_samples=200, attack_samples=200)
    except Exception as e:
        print(f"Deney 1 hatası: {e}")
        results['deney1'] = None

    print("\n" + "-" * 70)
    print("30 saniye bekleniyor...")
    time.sleep(30)

    # Deney 2: Yanıt Süresi
    print("\n" + "=" * 70)
    print("DENEY 2: YANIT SÜRESİ ANALİZİ")
    print("=" * 70)
    try:
        from deney2_yanit_suresi import ResponseTimeExperiment
        exp2 = ResponseTimeExperiment()
        results['deney2'] = exp2.run()
    except Exception as e:
        print(f"Deney 2 hatası: {e}")
        results['deney2'] = None

    print("\n" + "-" * 70)
    print("30 saniye bekleniyor...")
    time.sleep(30)

    # Deney 3: Farklı Saldırı Türleri
    print("\n" + "=" * 70)
    print("DENEY 3: FARKLI SALDIRI TÜRLERİ")
    print("=" * 70)
    try:
        from deney3_saldiri_turleri import AttackTypeExperiment
        exp3 = AttackTypeExperiment()
        results['deney3'] = exp3.run(samples_per_attack=100)
    except Exception as e:
        print(f"Deney 3 hatası: {e}")
        results['deney3'] = None

    print("\n" + "-" * 70)
    print("30 saniye bekleniyor...")
    time.sleep(30)

    # Deney 4: Ölçeklenebilirlik
    print("\n" + "=" * 70)
    print("DENEY 4: ÖLÇEKLENEBİLİRLİK TESTİ")
    print("=" * 70)
    try:
        from deney4_olceklenebilirlik import ScalabilityExperiment
        exp4 = ScalabilityExperiment()
        results['deney4'] = exp4.run(include_stability=False)
    except Exception as e:
        print(f"Deney 4 hatası: {e}")
        results['deney4'] = None

    # Birleşik Rapor
    generate_combined_report(results)

    print("\n" + "=" * 70)
    print("TÜM DENEYLER TAMAMLANDI")
    print(f"Bitiş: {datetime.now()}")
    print(f"Sonuçlar: {RESULTS_DIR}")
    print("=" * 70)


def generate_combined_report(results):
    """Birleşik özet rapor oluştur"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"{RESULTS_DIR}/tum_deneyler_ozet_{timestamp}.txt"

    report = []
    report.append("=" * 70)
    report.append("SDN-IDS TEZ DENEYLERİ - BİRLEŞİK ÖZET RAPOR")
    report.append("=" * 70)
    report.append(f"Rapor Tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")

    # Deney 1 Özeti
    report.append("-" * 70)
    report.append("DENEY 1: TESPİT DOĞRULUĞU ÖZETİ")
    report.append("-" * 70)
    if results.get('deney1'):
        d1 = results['deney1']
        if 'basic_metrics' in d1:
            report.append(f"Accuracy:        {d1['basic_metrics']['accuracy']*100:.2f}%")
            report.append(f"Precision:       {d1['basic_metrics']['precision']*100:.2f}%")
            report.append(f"Recall (DR):     {d1['basic_metrics']['recall']*100:.2f}%")
            report.append(f"F1-Score:        {d1['basic_metrics']['f1_score']*100:.2f}%")
        if 'detection_metrics' in d1:
            report.append(f"Detection Rate:  {d1['detection_metrics']['detection_rate_tpr']*100:.2f}%")
            report.append(f"False Pos Rate:  {d1['detection_metrics']['false_positive_rate_fpr']*100:.2f}%")
    else:
        report.append("Deney tamamlanamadı")
    report.append("")

    # Deney 2 Özeti
    report.append("-" * 70)
    report.append("DENEY 2: YANIT SÜRESİ ÖZETİ")
    report.append("-" * 70)
    if results.get('deney2'):
        report.append("Yanıt süresi analizi tamamlandı")
        report.append("Detaylar için deney2_*.json dosyasına bakın")
    else:
        report.append("Deney tamamlanamadı")
    report.append("")

    # Deney 3 Özeti
    report.append("-" * 70)
    report.append("DENEY 3: SALDIRI TÜRLERİ ÖZETİ")
    report.append("-" * 70)
    if results.get('deney3'):
        d3 = results['deney3']
        for attack_type, data in d3.items():
            dr = data.get('detection_rate', 0) * 100
            report.append(f"{attack_type:<20}: {dr:.2f}%")
    else:
        report.append("Deney tamamlanamadı")
    report.append("")

    # Deney 4 Özeti
    report.append("-" * 70)
    report.append("DENEY 4: ÖLÇEKLENEBİLİRLİK ÖZETİ")
    report.append("-" * 70)
    if results.get('deney4'):
        report.append("Ölçeklenebilirlik testi tamamlandı")
        report.append("Detaylar için deney4_*.json dosyasına bakın")
    else:
        report.append("Deney tamamlanamadı")
    report.append("")

    report.append("=" * 70)
    report.append("RAPOR SONU")
    report.append("=" * 70)

    report_text = "\n".join(report)
    print("\n" + report_text)

    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report_text)

    print(f"\nBirleşik rapor kaydedildi: {report_file}")


if __name__ == '__main__':
    run_all_experiments()
