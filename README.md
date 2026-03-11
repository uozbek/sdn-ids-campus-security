# SDN-IDS: Makine Ogrenmesi Tabanli Saldiri Tespit Sistemi

## Genel Bakis

Bu proje, Yazilim Tanimli Aglarda (SDN) makine ogrenmesi tabanli gercek zamanli saldiri tespit ve onleme sistemi (IDS/IPS) sunmaktadir.

### Temel Ozellikler

- **HHO-BDT Hibrit Model**: Harris Hawk Optimization ile secilen 45 ozellik ve Boosted Decision Tree siniflandirici
- **Gercek Zamanli Tespit**: Ryu SDN Controller ile entegre calisma
- **Otomatik Mudahale**: Zararli trafigi engelleme veya karantinaya alma
- **CIC-DDoS2019 & NSL-KDD**: Standart veri setleri ile egitilmis model

## Mimari

```
+------------------+     +-----------------+     +------------------+
|   SDN Switches   |<--->|  Ryu Controller |<--->|   ML Service     |
|   (OpenFlow)     |     |   + IDS Module  |     |   (Flask API)    |
+------------------+     +-----------------+     +------------------+
                                |                        |
                                v                        v
                         +-------------+          +-------------+
                         | Flow Rules  |          | HHO-BDT     |
                         | Management  |          | Model       |
                         +-------------+          +-------------+
```

## Kurulum

### Gereksinimler

- Python 3.8+
- Ryu SDN Controller
- Open vSwitch (test ortami icin)
- Docker & Containerlab (opsiyonel)

### Adimlar

```bash
# 1. Bagimliliklari yukle
pip install -r requirements.txt

# 2. ML Servisini Baslat
cd ml_service
python inference_server.py

# 3. Ryu Controller'i IDS Modulu ile Baslat
ryu-manager ryu_ids/ids_app.py
```

## Kullanim

### ML Servisi API

```python
import requests

# Tahmin istegi
response = requests.post('http://localhost:5000/predict', json={
    'features': [/* 45 ozellik */],
    'flow_id': 'flow_001',
    'src_ip': '192.168.1.100',
    'dst_ip': '192.168.1.1'
})

result = response.json()
# {'prediction': 0, 'attack_type': 'BENIGN', 'confidence': 0.98, 'action': 'ALLOW'}
```

### Model Bilgisi

```bash
curl http://localhost:5000/model/info
```

## Proje Yapisi

```
sdn_ids_system/
├── config/
│   └── config.py           # Yapilandirma ayarlari
├── ml_service/
│   └── inference_server.py # ML REST API servisi
├── ryu_ids/
│   └── ids_app.py          # Ryu IDS modulu
├── utils/
│   └── feature_extractor.py # Ozellik cikarici
├── models/
│   └── hho_bdt_model.pkl   # Egitilmis model
├── tests/
│   ├── test_ml_service.py
│   └── test_feature_extractor.py
└── requirements.txt
```

## HHO-Secilmis Ozellikler (45 Ozellik)

Model, Harris Hawk Optimization algoritmasi ile secilen 45 ozellik kullanmaktadir:

1. Subflow Bwd Packets
2. Fwd Packet Length Max
3. Idle Mean
4. Packet Length Max
5. Flow Bytes/s
... (tam liste config.py'de)

## Performans

| Veri Seti | Dogruluk | Precision | Recall | F1-Score | AUC |
|-----------|----------|-----------|--------|----------|-----|
| CIC-DDoS2019 | 100% | 99.9% | 99.9% | 99.9% | 100% |
| NSL-KDD | 99.6% | 99.6% | 99.7% | 99.6% | 100% |

## Aksiyonlar

| Aksiyon | Kosul | Aciklama |
|---------|-------|----------|
| ALLOW | Benign | Normal trafik, iletilir |
| QUARANTINE | Confidence 70-85% | Supheli trafik, izlenir |
| DROP | Confidence >85% | Saldiri tespit, engellenir |

## Test

```bash
# Tum testleri calistir
pytest tests/ -v

# Belirli test dosyasi
pytest tests/test_ml_service.py -v
```

## Containerlab ile Test Ortami

```bash
# Test ortamini baslat
cd ../extracted_project/clab_sdn_dcn-main
sudo ./setup-dc.sh
sudo clab deploy -t sdn-dcn.clab.yml

# IDS ile controller'i baslat
ryu-manager ../sdn_ids_system/ryu_ids/ids_app.py
```

## Lisans

MIT License

## Yazar

Doktora Tez Calismasi - SDN Guvenlik Arastirmasi
