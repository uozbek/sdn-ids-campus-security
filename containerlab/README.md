# SDN-IDS Containerlab Test Ortamı

## Kurulum ve Çalıştırma Kılavuzu

Bu dokümantasyon, HHO-BDT tabanlı IDS sisteminin Containerlab ortamında nasıl kurulacağını ve test edileceğini açıklar.

---

## İçindekiler

1. [Gereksinimler](#1-gereksinimler)
2. [Kurulum](#2-kurulum)
3. [Sistemi Başlatma](#3-sistemi-başlatma)
4. [Test Senaryoları](#4-test-senaryoları)
5. [Monitoring ve Loglar](#5-monitoring-ve-loglar)
6. [Sorun Giderme](#6-sorun-giderme)

---

## 1. Gereksinimler

### Yazılım Gereksinimleri

| Yazılım | Minimum Versiyon | Açıklama |
|---------|-----------------|----------|
| Docker | 20.10+ | Container runtime |
| Containerlab | 0.40+ | Network emulation |
| Python | 3.8+ | Script çalıştırma |
| Open vSwitch | 2.13+ | SDN switch |

### Donanım Gereksinimleri

| Bileşen | Minimum | Önerilen |
|---------|---------|----------|
| RAM | 8 GB | 16 GB |
| CPU | 4 çekirdek | 8 çekirdek |
| Disk | 20 GB | 50 GB |

### Kurulum Kontrolü

```bash
# Docker kontrolü
docker --version

# Containerlab kontrolü
containerlab version

# OVS kontrolü
ovs-vsctl --version

# Python kontrolü
python3 --version
```

---

## 2. Kurulum

### 2.1 Containerlab Kurulumu (Ubuntu/Debian)

```bash
# Containerlab kurulumu
bash -c "$(curl -sL https://get.containerlab.dev)"

# Docker kurulumu (yoksa)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

### 2.2 Proje Dizin Yapısı

```
sdn_ids_system/
├── containerlab/
│   ├── sdn-ids.clab.yml      # Ana topoloji dosyası
│   ├── setup-ovs.sh          # OVS kurulum scripti
│   ├── reset-ovs.sh          # OVS sıfırlama scripti
│   ├── requirements_ml.txt   # ML servis gereksinimleri
│   ├── ryu_apps/
│   │   └── ids_spine_leaf.py # IDS-entegre Ryu uygulaması
│   ├── attack_scripts/
│   │   ├── ddos_attacks.sh   # Bash saldırı scriptleri
│   │   ├── ddos_simulator.py # Python saldırı simülatörü
│   │   └── legitimate_traffic.py # Normal trafik üretici
│   └── tests/
│       └── run_tests.py      # Test suite
├── ml_service/
│   └── inference_server.py   # ML inference API
├── models/
│   └── hho_bdt_model.pkl     # Eğitilmiş model
├── config/
│   └── config.py             # Sistem konfigürasyonu
├── ryu_ids/
│   └── ids_app.py            # Ana IDS modülü
└── utils/
    └── feature_extractor.py  # Özellik çıkarıcı
```

### 2.3 Gerekli Docker Image'ları

```bash
# Image'ları çek
docker pull martimy/ryu-flowmanager:latest
docker pull python:3.10-slim
docker pull wbitt/network-multitool:alpine-minimal
docker pull kalilinux/kali-rolling

# Image'ları kontrol et
docker images | grep -E "ryu|python|multitool|kali"
```

---

## 3. Sistemi Başlatma

### 3.1 OVS Switch'leri Oluşturma

```bash
# Proje dizinine git
cd /path/to/sdn_ids_system/containerlab

# OVS switch'leri oluştur
sudo bash setup-ovs.sh
```

### 3.2 Containerlab Topolojisini Başlatma

```bash
# Topolojiyi deploy et
sudo containerlab deploy --topo sdn-ids.clab.yml

# Durumu kontrol et
sudo containerlab inspect --topo sdn-ids.clab.yml
```

### 3.3 ML Servisini Başlatma

ML servisi otomatik başlar, ancak manuel başlatmak için:

```bash
# ML servis container'ına bağlan
docker exec -it clab-sdn-ids-ml_service bash

# Servisi başlat
cd /app
python ml_service/inference_server.py
```

### 3.4 Servis Durumlarını Kontrol Etme

```bash
# ML Service health check
curl http://172.10.10.100:5000/health

# Controller health check
curl http://172.10.10.10:8080/stats/switches

# Host bağlantı testi
docker exec clab-sdn-ids-h11 ping -c 3 192.168.11.6
```

---

## 4. Test Senaryoları

### 4.1 Temel Bağlantı Testi

```bash
# Host'lar arası ping
docker exec clab-sdn-ids-h11 ping -c 5 192.168.11.2
docker exec clab-sdn-ids-h11 ping -c 5 192.168.11.4
docker exec clab-sdn-ids-h11 ping -c 5 192.168.11.6

# Tüm host'lara ping
for i in 1 2 3 4 5 6; do
    docker exec clab-sdn-ids-h11 ping -c 1 192.168.11.$i
done
```

### 4.2 Normal Trafik Testi

Normal trafiğin IDS tarafından izin verildiğini doğrula:

```bash
# Normal trafik üret
docker exec clab-sdn-ids-h11 python3 /attack/legitimate_traffic.py 192.168.11.6 -d 60

# Controller loglarını izle
docker logs -f clab-sdn-ids-ctrl
```

### 4.3 DDoS Saldırı Simülasyonu

#### SYN Flood Saldırısı

```bash
# Attacker container'ına bağlan
docker exec -it clab-sdn-ids-attacker1 bash

# SYN flood başlat
python3 /attack/ddos_simulator.py 192.168.11.6 -a syn -d 30 -r 1000
```

#### UDP Flood Saldırısı

```bash
docker exec clab-sdn-ids-attacker1 python3 /attack/ddos_simulator.py 192.168.11.6 -a udp -d 30
```

#### HTTP Flood Saldırısı

```bash
docker exec clab-sdn-ids-attacker1 python3 /attack/ddos_simulator.py 192.168.11.6 -a http -d 30
```

### 4.4 IDS Tespit Doğrulaması

```bash
# Saldırı sırasında controller loglarını izle
docker logs -f clab-sdn-ids-ctrl 2>&1 | grep -E "ALERT|BLOCK|QUARANTINE"

# ML servis loglarını izle
docker logs -f clab-sdn-ids-ml_service

# Flow rule'larını kontrol et
curl http://172.10.10.10:8080/stats/flow/21 | python3 -m json.tool
```

### 4.5 Otomatik Test Suite

```bash
# Tüm testleri çalıştır
python3 tests/run_tests.py

# Sonuçları görüntüle
cat /tmp/test_results.json | python3 -m json.tool
```

---

## 5. Monitoring ve Loglar

### 5.1 Real-time Log İzleme

```bash
# Controller logları
docker logs -f clab-sdn-ids-ctrl

# ML Service logları
docker logs -f clab-sdn-ids-ml_service

# Tüm container logları
docker-compose logs -f
```

### 5.2 FlowManager Web Arayüzü

FlowManager web arayüzüne erişim:

```
URL: http://172.10.10.10:8080
```

Özellikler:
- Topoloji görselleştirme
- Flow tablosu görüntüleme
- Switch istatistikleri
- Port istatistikleri

### 5.3 IDS İstatistikleri

```bash
# ML servis istatistikleri
curl http://172.10.10.100:5000/model/info

# Prediction istatistikleri
curl http://172.10.10.100:5000/stats
```

### 5.4 Network İstatistikleri

```bash
# OVS flow tablosu
sudo ovs-ofctl dump-flows leaf1 -O OpenFlow13

# Port istatistikleri
sudo ovs-ofctl dump-ports leaf1 -O OpenFlow13

# Switch bilgisi
sudo ovs-vsctl show
```

---

## 6. Sorun Giderme

### 6.1 Yaygın Sorunlar

#### ML Servis Bağlantı Hatası

```bash
# Servis durumunu kontrol et
docker ps | grep ml_service

# Container loglarını incele
docker logs clab-sdn-ids-ml_service

# Manuel başlat
docker exec -it clab-sdn-ids-ml_service python /app/ml_service/inference_server.py
```

#### Switch Bağlantı Hatası

```bash
# OVS durumunu kontrol et
sudo ovs-vsctl show

# Controller bağlantısını kontrol et
sudo ovs-vsctl get-controller leaf1

# Switch'leri yeniden yapılandır
sudo bash reset-ovs.sh
sudo bash setup-ovs.sh
```

#### Host Bağlantı Sorunu

```bash
# Host IP yapılandırmasını kontrol et
docker exec clab-sdn-ids-h11 ip addr show eth1

# Route tablosunu kontrol et
docker exec clab-sdn-ids-h11 ip route

# ARP tablosunu kontrol et
docker exec clab-sdn-ids-h11 arp -a
```

### 6.2 Sistemi Yeniden Başlatma

```bash
# Topolojiyi durdur
sudo containerlab destroy --topo sdn-ids.clab.yml

# OVS'i sıfırla
sudo bash reset-ovs.sh

# Temiz başlangıç
sudo bash setup-ovs.sh
sudo containerlab deploy --topo sdn-ids.clab.yml
```

### 6.3 Log Toplama

```bash
# Tüm logları bir dosyaya kaydet
mkdir -p /tmp/sdn_ids_logs
docker logs clab-sdn-ids-ctrl > /tmp/sdn_ids_logs/controller.log 2>&1
docker logs clab-sdn-ids-ml_service > /tmp/sdn_ids_logs/ml_service.log 2>&1
sudo ovs-vsctl show > /tmp/sdn_ids_logs/ovs_config.txt
sudo ovs-ofctl dump-flows leaf1 -O OpenFlow13 > /tmp/sdn_ids_logs/leaf1_flows.txt
```

---

## 7. Tez Deneyleri İçin Önerilen Test Planı

### Deney 1: Tespit Doğruluğu

1. Normal trafik üret (5 dakika)
2. DDoS saldırısı başlat (2 dakika)
3. Tespit süresi ve doğruluğu kaydet
4. False positive/negative oranları hesapla

### Deney 2: Yanıt Süresi

1. Saldırı başlangıç zamanını kaydet
2. IDS tespit zamanını kaydet
3. Bloklama aksiyonu zamanını kaydet
4. Ortalama yanıt süresini hesapla

### Deney 3: Sistem Performansı

1. Farklı trafik yüklerinde test et
2. CPU/Memory kullanımını izle
3. Throughput ölçümleri yap
4. Ölçeklenebilirlik analizi

### Deney 4: Farklı Saldırı Türleri

| Saldırı Türü | Komut | Beklenen Sonuç |
|--------------|-------|----------------|
| SYN Flood | `-a syn` | BLOCK |
| UDP Flood | `-a udp` | BLOCK |
| ICMP Flood | `-a icmp` | QUARANTINE |
| HTTP Flood | `-a http` | BLOCK |
| Slowloris | `-a slowloris` | QUARANTINE |

---

## 8. Performans Metrikleri

### 8.1 Toplanan Metrikler

- **Detection Rate (DR)**: Tespit edilen saldırı oranı
- **False Positive Rate (FPR)**: Yanlış alarm oranı
- **Detection Time (DT)**: Tespit süresi (ms)
- **Mitigation Time (MT)**: Önlem alma süresi (ms)
- **Throughput**: İşlenen flow/saniye

### 8.2 Metrik Toplama Scripti

```bash
# Performans metriklerini topla
python3 tests/collect_metrics.py --duration 300 --output metrics.csv
```

---

## Sonuç

Bu test ortamı, HHO-BDT tabanlı IDS sisteminin SDN ortamında kapsamlı değerlendirmesini sağlar. Tez çalışmanız için gerekli tüm deneyler bu ortamda gerçekleştirilebilir.

**Önemli Notlar:**
- Testleri izole bir ortamda çalıştırın
- Her test öncesi sistemi sıfırlayın
- Tüm sonuçları kaydedin ve yedekleyin
- Farklı parametrelerle karşılaştırmalı testler yapın

---

*Bu dokümantasyon, SDN güvenliği tez çalışması kapsamında hazırlanmıştır.*
*Tarih: 2026*
