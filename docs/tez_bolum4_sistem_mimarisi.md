# BÖLÜM 4: ÖNERİLEN SİSTEM MİMARİSİ

## 4.1. Genel Bakış

Bu çalışmada, yazılım tanımlı kampüs ağlarında DDoS saldırılarını gerçek zamanlı olarak tespit etmek ve önlemek için makine öğrenmesi tabanlı bir Saldırı Tespit ve Önleme Sistemi (IDS/IPS) önerilmektedir. Önerilen sistem, Harris Hawk Optimization (HHO) algoritması ile seçilen özellikler ve Boosted Decision Tree (BDT) sınıflandırıcısını kullanan hibrit bir yaklaşımı, OpenFlow protokolü üzerinden SDN denetleyicisi ile entegre etmektedir.

Önerilen mimari, Şekil 4.1'de gösterildiği üzere üç temel katmandan oluşmaktadır:

1. **Veri Katmanı (Data Plane)**: OpenFlow destekli ağ anahtarları
2. **Kontrol Katmanı (Control Plane)**: Ryu SDN denetleyicisi ve IDS modülü
3. **Uygulama Katmanı (Application Plane)**: ML çıkarım servisi ve yönetim arayüzü

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           UYGULAMA KATMANI                                   │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐   │
│  │   FlowManager    │  │   REST API       │  │   Yönetim Dashboard'u   │   │
│  │   (GUI)          │  │   Arayüzü        │  │   (Alarm & İstatistik)  │   │
│  └──────────────────┘  └──────────────────┘  └──────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│                           KONTROL KATMANI                                    │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      RYU SDN DENETLEYİCİSİ                            │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌───────────────────────────────┐  │  │
│  │  │  Topoloji   │  │   Akış      │  │       IDS/IPS Modülü          │  │  │
│  │  │  Keşfi      │  │   Yönetimi  │  │  (Özellik Çıkarımı + Karar)   │  │  │
│  │  └─────────────┘  └─────────────┘  └───────────────┬───────────────┘  │  │
│  └────────────────────────────────────────────────────┼──────────────────┘  │
│                                                       │                      │
│  ┌────────────────────────────────────────────────────▼──────────────────┐  │
│  │                    MAKİNE ÖĞRENMESİ MOTORU                            │  │
│  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────┐   │  │
│  │  │ Özellik        │  │  HHO-BDT       │  │   Karar Motoru         │   │  │
│  │  │ Çıkarıcı       │  │  Sınıflandırıcı│  │   (İzin/Karantina/     │   │  │
│  │  │ (45 Özellik)   │  │  Modeli        │  │    Engelle)            │   │  │
│  │  └────────────────┘  └────────────────┘  └────────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────────────────┤
│                            VERİ KATMANI                                      │
│           ┌──────────┐              ┌──────────┐                             │
│           │ SPINE 1  │              │ SPINE 2  │                             │
│           │  (OVS)   │              │  (OVS)   │                             │
│           └────┬─────┘              └────┬─────┘                             │
│      ┌─────────┴──────────┬──────────────┴─────────┐                        │
│   ┌──▼───┐  ┌──▼───┐  ┌───▼───┐  ┌───▼───┐  ┌──▼───┐                       │
│   │LEAF 1│  │LEAF 2│  │LEAF 3 │  │LEAF 4 │  │LEAF 5│                       │
│   │ (OVS)│  │ (OVS)│  │ (OVS) │  │ (OVS) │  │ (OVS)│                       │
│   └──┬───┘  └──┬───┘  └───┬───┘  └───┬───┘  └──┬───┘                       │
│      │         │          │          │         │                            │
│   [Host]    [Host]     [Host]     [Host]    [Host]                         │
└─────────────────────────────────────────────────────────────────────────────┘

                  Şekil 4.1. Önerilen Sistem Mimarisi
```

## 4.2. Veri Katmanı Tasarımı

Veri katmanı, ağ trafiğinin iletildiği fiziksel veya sanal ağ altyapısını temsil etmektedir. Bu çalışmada, kampüs ağı senaryosunu modellemek için Spine-Leaf topolojisi tercih edilmiştir. Bu topoloji, modern veri merkezlerinde ve kampüs ağlarında yaygın olarak kullanılmakta olup, düşük gecikme süresi ve yüksek bant genişliği sunmaktadır.

### 4.2.1. Open vSwitch (OVS) Anahtarları

Veri katmanında Open vSwitch (OVS) yazılım anahtarları kullanılmaktadır. OVS, OpenFlow 1.3 protokolünü destekleyen açık kaynaklı bir sanal anahtardır. Her anahtar, SDN denetleyicisine TCP bağlantısı üzerinden bağlanmakta ve akış tablolarını denetleyiciden almaktadır.

Anahtarların temel özellikleri:
- OpenFlow 1.3 protokol desteği
- Çoklu akış tablosu desteği
- Port istatistikleri ve akış sayaçları
- QoS ve meter desteği (hız sınırlama için)

### 4.2.2. Spine-Leaf Topolojisi

Önerilen topoloji, 2 spine ve 5 leaf anahtardan oluşmaktadır:

| Anahtar Tipi | Sayı | Bağlantı |
|--------------|------|----------|
| Spine        | 2    | Tüm leaf anahtarlara bağlı |
| Leaf         | 5    | Her biri 2 spine'a ve host'lara bağlı |
| Host         | 10   | Her leaf'e 2 host bağlı |

Bu topoloji, herhangi iki host arasında maksimum 3 hop mesafe sağlamakta ve yüksek kullanılabilirlik sunmaktadır.

## 4.3. Kontrol Katmanı Tasarımı

Kontrol katmanı, ağın merkezi beynini oluşturmakta ve tüm yönlendirme kararlarından sorumludur. Bu katman, Ryu SDN denetleyicisi üzerinde çalışan IDS/IPS modülünü içermektedir.

### 4.3.1. Ryu SDN Denetleyicisi

Ryu, Python programlama dilinde geliştirilmiş açık kaynaklı bir SDN denetleyicisidir. Bu çalışmada Ryu tercih edilmesinin nedenleri:

1. **Modüler yapı**: Yeni uygulamaların kolayca eklenmesine olanak tanır
2. **OpenFlow desteği**: 1.0'dan 1.5'e kadar tüm sürümleri destekler
3. **Python uyumluluğu**: Makine öğrenmesi kütüphaneleriyle entegrasyon kolaylığı
4. **Aktif topluluk**: Geniş dokümantasyon ve örnek uygulamalar

### 4.3.2. IDS/IPS Modülü

Geliştirilen IDS/IPS modülü, Ryu denetleyicisi üzerinde bir uygulama olarak çalışmaktadır. Modülün temel bileşenleri:

```python
class SDNIntrusionDetectionSystem(app_manager.RyuApp):
    """
    SDN tabanlı Saldırı Tespit ve Önleme Sistemi
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        # MAC tablosu (öğrenen anahtar işlevselliği)
        self.mac_to_port = {}

        # Özellik çıkarıcı
        self.feature_extractor = FeatureExtractor()

        # Tespit istatistikleri
        self.detection_stats = {
            'total_packets': 0,
            'benign_packets': 0,
            'attack_packets': 0,
            'blocked_flows': 0,
            'quarantined_flows': 0
        }

        # Engellenen ve karantinaya alınan IP'ler
        self.blocked_ips = set()
        self.quarantined_ips = {}
```

#### 4.3.2.1. Paket İşleme Akışı

IDS modülü, OpenFlow Packet-In olaylarını yakalayarak her paketi analiz etmektedir. İşleme akışı Şekil 4.2'de gösterilmiştir:

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────────┐
│  Packet-In  │────▶│  IP Paketi   │────▶│  Özellik    │────▶│  ML Servisi  │
│  Olayı      │     │  Ayrıştırma  │     │  Çıkarımı   │     │  Sorgusu     │
└─────────────┘     └──────────────┘     └─────────────┘     └──────┬───────┘
                                                                    │
                    ┌───────────────────────────────────────────────┘
                    ▼
         ┌──────────────────────────────────────────────────────────┐
         │                      KARAR MOTORU                         │
         │  ┌────────────┐  ┌─────────────┐  ┌───────────────────┐  │
         │  │   İZİN     │  │  KARANTİNA  │  │     ENGELLE       │  │
         │  │ (ALLOW)    │  │ (QUARANTINE)│  │     (DROP)        │  │
         │  │ Güven>0.85 │  │ 0.70<G<0.85 │  │    Güven<0.70     │  │
         │  │ Benign     │  │ Şüpheli     │  │    Saldırı        │  │
         │  └────────────┘  └─────────────┘  └───────────────────┘  │
         └──────────────────────────────────────────────────────────┘

              Şekil 4.2. Paket İşleme ve Karar Verme Akışı
```

#### 4.3.2.2. Akış Kuralı Yönetimi

IDS modülü, tespit sonuçlarına göre OpenFlow akış kuralları oluşturmaktadır:

| Aksiyon | Öncelik | Zaman Aşımı | Açıklama |
|---------|---------|-------------|----------|
| ALLOW | 1 | 30 sn (idle) | Normal trafik için yönlendirme kuralı |
| QUARANTINE | 500 | 300 sn (hard) | Şüpheli trafik controller'a yönlendirilir |
| DROP | 1000 | 3600 sn (hard) | Saldırı trafiği düşürülür |

Engelleme işlemi için oluşturulan OpenFlow kuralı:

```python
def _block_ip(self, datapath, src_ip, duration=3600):
    """Belirli bir IP adresinden gelen trafiği engelle"""
    parser = datapath.ofproto_parser

    # Yüksek öncelikli DROP kuralı
    match = parser.OFPMatch(
        eth_type=ether_types.ETH_TYPE_IP,
        ipv4_src=src_ip
    )
    actions = []  # Boş aksiyon = DROP

    self._add_flow(datapath, priority=1000, match=match,
                   actions=actions, hard_timeout=duration)
```

## 4.4. Makine Öğrenmesi Motoru

Makine öğrenmesi motoru, ağ trafiğinin sınıflandırılmasından sorumlu bileşendir. Bu motor, REST API arayüzü üzerinden IDS modülü ile iletişim kurmaktadır.

### 4.4.1. Özellik Çıkarım Modülü

Gerçek zamanlı özellik çıkarımı, CIC-DDoS2019 veri seti formatına uygun olarak gerçekleştirilmektedir. Harris Hawk Optimization (HHO) algoritması ile seçilen 45 özellik kullanılmaktadır.

#### 4.4.1.1. Akış İstatistikleri

Her ağ akışı için aşağıdaki istatistikler hesaplanmaktadır:

| Kategori | Özellikler |
|----------|------------|
| Paket Sayıları | Total Fwd Packets, Total Backward Packets, Subflow Fwd/Bwd Packets |
| Paket Boyutları | Packet Length Max/Min/Mean/Std, Fwd/Bwd Packet Length Max/Min/Mean |
| Zaman Özellikleri | Flow Duration, Flow IAT Mean/Max/Min, Fwd/Bwd IAT Total/Mean/Std |
| TCP Bayrakları | SYN, ACK, RST, PSH, FIN, URG, CWE Flag Counts |
| Pencere Boyutları | Init Fwd/Bwd Win Bytes |
| Aktif/Boşta | Active/Idle Mean/Max/Min |

#### 4.4.1.2. Özellik Çıkarım Algoritması

```python
class FeatureExtractor:
    def extract_features(self, flow_id) -> List[float]:
        """45 HHO-seçilmiş özelliği çıkar"""
        flow = self.flows[flow_id]

        # Türetilmiş istatistikleri hesapla
        flow_duration = (flow.last_time - flow.start_time) * 1e6  # mikrosaniye
        all_packet_lengths = flow.fwd_packet_lengths + flow.bwd_packet_lengths

        features = [
            float(flow.total_bwd_packets),           # Subflow Bwd Packets
            self._safe_max(flow.fwd_packet_lengths), # Fwd Packet Length Max
            self._safe_mean(flow.idle_times),        # Idle Mean
            # ... (45 özellik)
        ]

        return features
```

### 4.4.2. HHO-BDT Sınıflandırma Modeli

Sınıflandırma için, Bölüm 5'te detaylandırılan HHO-BDT hibrit modeli kullanılmaktadır. Model, Flask tabanlı bir REST API servisi olarak sunulmaktadır.

#### 4.4.2.1. API Endpoint'leri

| Endpoint | Metot | Açıklama |
|----------|-------|----------|
| `/health` | GET | Servis sağlık kontrolü |
| `/predict` | POST | Tek akış tahmini |
| `/predict/batch` | POST | Toplu tahmin |
| `/model/info` | GET | Model bilgisi |

#### 4.4.2.2. Tahmin İsteği ve Yanıtı

**İstek Formatı:**
```json
{
    "features": [/* 45 özellik değeri */],
    "flow_id": "192.168.1.100-10.0.0.1-54321-80-6",
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.1"
}
```

**Yanıt Formatı:**
```json
{
    "flow_id": "192.168.1.100-10.0.0.1-54321-80-6",
    "prediction": 1,
    "attack_type": "DDoS_ATTACK",
    "confidence": 0.9234,
    "action": "DROP",
    "timestamp": "2026-02-17T10:30:00.123456"
}
```

### 4.4.3. Karar Motoru

Karar motoru, ML modelinin çıktısına göre uygun aksiyonu belirlemektedir:

```python
def determine_action(prediction, confidence):
    """Tahmin ve güven değerine göre aksiyon belirle"""

    if prediction == 1:  # Saldırı tespit edildi
        if confidence >= CONFIDENCE_THRESHOLD:  # 0.85
            return 'DROP'      # Kesin saldırı - engelle
        elif confidence >= QUARANTINE_THRESHOLD:  # 0.70
            return 'QUARANTINE'  # Şüpheli - karantinaya al

    return 'ALLOW'  # Zararsız trafik - izin ver
```

## 4.5. Gerçek Zamanlı Tespit Akışı

Sistemin uçtan uca çalışma akışı Şekil 4.3'te gösterilmiştir:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        GERÇEK ZAMANLI TESPİT AKIŞI                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. PAKET YAKALAMA                                                          │
│     ┌───────────┐    OpenFlow     ┌──────────────┐                         │
│     │   OVS     │───Packet-In────▶│  Ryu IDS     │                         │
│     │  Switch   │                 │  Modülü      │                         │
│     └───────────┘                 └──────┬───────┘                         │
│                                          │                                  │
│  2. ÖZELLİK ÇIKARIMI                     ▼                                  │
│                                   ┌──────────────┐                         │
│                                   │   Feature    │                         │
│                                   │  Extractor   │──▶ 45 Özellik           │
│                                   └──────┬───────┘                         │
│                                          │                                  │
│  3. ML TAHMİNİ                           ▼                                  │
│                                   ┌──────────────┐                         │
│                                   │   HHO-BDT    │                         │
│                                   │   Model      │──▶ Tahmin + Güven       │
│                                   └──────┬───────┘                         │
│                                          │                                  │
│  4. AKSİYON                              ▼                                  │
│     ┌─────────────────────────────────────────────────────────┐            │
│     │  Güven ≥ 0.85  │  0.70 ≤ Güven < 0.85  │  Güven < 0.70 │            │
│     │    Saldırı     │       Şüpheli          │    Zararsız   │            │
│     │      ▼         │          ▼             │       ▼       │            │
│     │  ┌───────┐     │    ┌───────────┐       │   ┌───────┐   │            │
│     │  │ DROP  │     │    │QUARANTINE │       │   │ ALLOW │   │            │
│     │  └───────┘     │    └───────────┘       │   └───────┘   │            │
│     └─────────────────────────────────────────────────────────┘            │
│                                                                             │
│  5. AKIŞ KURALI                                                             │
│     ┌───────────┐    OpenFlow     ┌──────────────┐                         │
│     │   OVS     │◀───FlowMod─────│  Ryu IDS     │                         │
│     │  Switch   │                 │  Modülü      │                         │
│     └───────────┘                 └──────────────┘                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

                    Şekil 4.3. Gerçek Zamanlı Tespit Akışı
```

## 4.6. Sistem Entegrasyonu

### 4.6.1. Bileşen İletişimi

Sistem bileşenleri arasındaki iletişim aşağıdaki protokoller üzerinden gerçekleşmektedir:

| Kaynak | Hedef | Protokol | Port |
|--------|-------|----------|------|
| OVS Switches | Ryu Controller | OpenFlow 1.3 | 6653 |
| IDS Module | ML Service | HTTP REST | 5000 |
| Management UI | Ryu Controller | REST API | 8080 |

### 4.6.2. Hata Toleransı

Sistem, ML servisinin geçici olarak erişilemez olması durumunda fail-open politikası uygulamaktadır:

```python
def _query_ml_service(self, features, flow_id, src_ip, dst_ip):
    if not self.ml_service_available:
        if not self._check_ml_service():
            logger.warning("ML servisi erişilemez, trafiğe izin veriliyor")
            return 'ALLOW', 'UNKNOWN', 0.0
    # ...
```

### 4.6.3. Performans Optimizasyonları

1. **Asenkron İstatistik Toplama**: Arka plan thread'leri ile periyodik istatistik sorguları
2. **Akış Önbellekleme**: Sık kullanılan akışlar için yerel önbellek
3. **Batch Tahmin**: Yüksek trafik durumlarında toplu ML sorguları
4. **Zaman Aşımı Yönetimi**: Eski akış kayıtlarının otomatik temizlenmesi

## 4.7. Sonuç

Bu bölümde, yazılım tanımlı kampüs ağlarında makine öğrenmesi tabanlı saldırı tespit ve önleme sisteminin mimarisi detaylı olarak açıklanmıştır. Önerilen mimari:

1. **Modüler tasarım**: Her bileşen bağımsız olarak geliştirilebilir ve test edilebilir
2. **Ölçeklenebilirlik**: Spine-Leaf topolojisi ile yatay ölçekleme desteği
3. **Gerçek zamanlı tespit**: OpenFlow Packet-In mekanizması ile düşük gecikmeli analiz
4. **Esnek müdahale**: Üç kademeli aksiyon mekanizması (İzin/Karantina/Engelle)
5. **Yüksek doğruluk**: HHO-BDT hibrit modeli ile %99.9+ tespit oranı

Bir sonraki bölümde, HHO-BDT hibrit modelinin geliştirilmesi ve eğitimi detaylı olarak açıklanacaktır.
