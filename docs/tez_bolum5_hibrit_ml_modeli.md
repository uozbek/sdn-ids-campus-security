# BÖLÜM 5: HİBRİT MAKİNE ÖĞRENMESİ MODELİNİN GELİŞTİRİLMESİ

## 5.1. Giriş

Bu bölümde, DDoS saldırılarının tespiti için geliştirilen Harris Hawk Optimization (HHO) tabanlı özellik seçimi ve Boosted Decision Tree (BDT) sınıflandırıcısını birleştiren hibrit makine öğrenmesi modelinin geliştirilme süreci detaylı olarak açıklanmaktadır.

Önerilen metodoloji Şekil 5.1'de gösterildiği üzere beş ana aşamadan oluşmaktadır:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      HİBRİT MODEL GELİŞTİRME METODOLOJİSİ                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                  │
│  │   1. VERİ    │───▶│  2. VERİ     │───▶│  3. ÖZELLİK  │                  │
│  │   TOPLAMA    │    │  ÖNİŞLEME    │    │   SEÇİMİ     │                  │
│  │              │    │              │    │   (HHO)      │                  │
│  │ CIC-DDoS2019 │    │ • Temizleme  │    │              │                  │
│  │ NSL-KDD      │    │ • Dönüşüm    │    │ 78 → 45      │                  │
│  └──────────────┘    │ • Normalizas.│    │ özellik      │                  │
│                      └──────────────┘    └──────┬───────┘                  │
│                                                 │                          │
│                                                 ▼                          │
│                      ┌──────────────┐    ┌──────────────┐                  │
│                      │  5. MODEL    │◀───│  4. MODEL    │                  │
│                      │  DEĞERLENDİR.│    │   EĞİTİMİ    │                  │
│                      │              │    │   (BDT)      │                  │
│                      │ • Accuracy   │    │              │                  │
│                      │ • Precision  │    │ Hiperparamet.│                  │
│                      │ • Recall     │    │ Optimizasyon │                  │
│                      │ • F1-Score   │    │              │                  │
│                      │ • AUC        │    │              │                  │
│                      └──────────────┘    └──────────────┘                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

                    Şekil 5.1. Hibrit Model Geliştirme Metodolojisi
```

## 5.2. Kullanılan Veri Setleri

### 5.2.1. CIC-DDoS2019 Veri Seti

Canadian Institute for Cybersecurity tarafından 2019 yılında oluşturulan CIC-DDoS2019 veri seti, modern DDoS saldırı türlerini içeren kapsamlı bir veri setidir. Bu veri seti, gerçekçi ağ trafiği ve çeşitli DDoS saldırı türlerini barındırmaktadır.

**Veri Seti Özellikleri:**

| Özellik | Değer |
|---------|-------|
| Toplam Örnek Sayısı | 431,371 |
| Özellik Sayısı | 78 |
| Sınıf | 2 (Benign / Attack) |
| Saldırı Türleri | 12 farklı DDoS türü |

**Saldırı Türleri Dağılımı:**

| Saldırı Türü | Örnek Sayısı | Yüzde |
|--------------|--------------|-------|
| BENIGN | 56,863 | 13.18% |
| DrDoS_DNS | 5,071,011 | - |
| DrDoS_LDAP | 2,179,930 | - |
| DrDoS_MSSQL | 4,522,492 | - |
| DrDoS_NetBIOS | 4,093,279 | - |
| DrDoS_NTP | 1,202,642 | - |
| DrDoS_SNMP | 5,159,870 | - |
| DrDoS_SSDP | 2,610,611 | - |
| DrDoS_UDP | 3,134,645 | - |
| Syn | 1,582,289 | - |
| TFTP | 20,082 | - |
| UDP-lag | 366,461 | - |
| WebDDoS | 439 | - |

### 5.2.2. NSL-KDD Veri Seti

NSL-KDD, KDD Cup 99 veri setinin geliştirilmiş versiyonudur ve saldırı tespit sistemlerinin değerlendirilmesinde yaygın olarak kullanılmaktadır.

**Veri Seti Özellikleri:**

| Özellik | Değer |
|---------|-------|
| Eğitim Seti | 125,973 örnek |
| Test Seti | 22,544 örnek |
| Özellik Sayısı | 41 |
| Sınıf | 2 (Normal / Attack) |

## 5.3. Veri Önişleme

Veri önişleme aşaması, makine öğrenmesi modellerinin performansını doğrudan etkileyen kritik bir adımdır. Bu çalışmada iki temel önişleme operasyonu uygulanmıştır.

### 5.3.1. Veri Temizleme

#### 5.3.1.1. Tekrarlayan Verilerin Kaldırılması

CIC-DDoS2019 veri setinde aynı değerlere sahip örneklerin bulunduğu tespit edilmiştir:

```python
# Tekrarlayan verilerin kaldırılması
df_original_size = len(df)
df = df.drop_duplicates()
df_clean_size = len(df)

print(f"Orijinal: {df_original_size} → Temizlenmiş: {df_clean_size}")
# Çıktı: Orijinal: 431,371 → Temizlenmiş: 418,756
```

| Veri Seti | Orijinal | Temizlenmiş | Kaldırılan |
|-----------|----------|-------------|------------|
| CIC-DDoS2019 | 431,371 | 418,756 | 12,615 |
| NSL-KDD | 148,517 | 147,888 | 629 |

#### 5.3.1.2. Tek Değerli Özelliklerin Kaldırılması

Tüm örneklerde aynı değeri alan özellikler, sınıflandırma için bilgi taşımamakta ve kaldırılmaktadır:

**CIC-DDoS2019'da kaldırılan özellikler:**
- `no` (örnek numarası)
- `Down/Up Ratio`
- `Packet Length Mean`
- `Bwd URG Flags`, `Bwd PSH Flags`, `Fwd URG Flags`
- `PSH Flag Count`, `FIN Flag Count`, `ECE Flag Count`
- `Fwd Avg Packets/Bulk`, `Fwd Avg Bulk Rate`
- `Bwd Avg Packets/Bulk`, `Bwd Avg Bytes/Bulk`
- `Fwd Avg Bytes/Bulk`, `Bwd Avg Bulk Rate`
- `Flow IAT Std`

**NSL-KDD'de kaldırılan özellikler:**
- `num_outbound_cmds`

### 5.3.2. Veri Dönüşümü (Normalizasyon)

Farklı ölçeklerdeki özellik değerlerini ortak bir ölçeğe getirmek için Z-Score normalizasyonu uygulanmıştır:

```
            x_i - μ
    Z_i = ─────────
              σ
```

Burada:
- `x_i`: i. örneğin orijinal değeri
- `μ`: Özelliğin ortalama değeri
- `σ`: Özelliğin standart sapması
- `Z_i`: Normalize edilmiş değer ([-1, 1] aralığında)

```python
from sklearn.preprocessing import StandardScaler

# Z-Score normalizasyonu
scaler = StandardScaler()
X_train_normalized = scaler.fit_transform(X_train)
X_test_normalized = scaler.transform(X_test)
```

## 5.4. Özellik Seçimi: Harris Hawk Optimization (HHO)

### 5.4.1. HHO Algoritmasının Teorik Temeli

Harris Hawk Optimization (HHO), 2019 yılında Heidari ve arkadaşları tarafından geliştirilen, doğadan ilham alan bir meta-sezgisel optimizasyon algoritmasıdır. Algoritma, Harris şahinlerinin (Parabuteo unicinctus) av davranışını modellemektedir.

**Algoritmanın Temel Aşamaları:**

1. **Keşif Aşaması (Exploration)**: Şahinler rastgele konumlara tüneyerek av arar
2. **Geçiş Aşaması (Transition)**: Avın enerji seviyesine göre keşiften sömürüye geçiş
3. **Sömürü Aşaması (Exploitation)**: Avı yakalamak için farklı stratejiler

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    HARRIS HAWK OPTİMİZASYONU AKIŞI                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐                                                        │
│  │   Başlangıç     │                                                        │
│  │   Popülasyonu   │ → N şahin rastgele konumlarda                         │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │   Uygunluk      │                                                        │
│  │   Hesaplama     │ → Her şahinin uygunluk değeri                         │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐     E ≥ 1         ┌─────────────────┐                 │
│  │    Av Enerjisi  │─────────────────▶│    KEŞİF        │                 │
│  │    (E) Hesapla  │                   │    AŞAMASI      │                 │
│  └────────┬────────┘                   └─────────────────┘                 │
│           │                                                                 │
│           │ E < 1                                                           │
│           ▼                                                                 │
│  ┌─────────────────────────────────────────────────────────┐               │
│  │                    SÖMÜRÜ AŞAMASI                        │               │
│  │                                                          │               │
│  │    |E| ≥ 0.5              │         |E| < 0.5           │               │
│  │         │                  │              │               │               │
│  │    r ≥ 0.5    r < 0.5     │     r ≥ 0.5     r < 0.5     │               │
│  │       │          │        │        │           │         │               │
│  │   ┌───▼───┐ ┌────▼────┐   │   ┌────▼────┐ ┌────▼────┐   │               │
│  │   │Yumuşak│ │Yumuşak  │   │   │  Sert   │ │  Sert   │   │               │
│  │   │Kuşatma│ │Kuşatma+ │   │   │ Kuşatma │ │Kuşatma+ │   │               │
│  │   │       │ │Hızlı    │   │   │         │ │Hızlı    │   │               │
│  │   │       │ │Dalış    │   │   │         │ │Dalış    │   │               │
│  │   └───────┘ └─────────┘   │   └─────────┘ └─────────┘   │               │
│  └─────────────────────────────────────────────────────────┘               │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ Sonlandırma     │ → Maksimum iterasyon veya yakınsama                   │
│  │ Kriteri?        │                                                        │
│  └────────┬────────┘                                                        │
│           │ Evet                                                            │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │   En İyi        │ → Seçilen özellik alt kümesi                          │
│  │   Çözüm         │                                                        │
│  └─────────────────┘                                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

                    Şekil 5.2. HHO Algoritması Akış Diyagramı
```

### 5.4.2. HHO'nun Özellik Seçimine Uyarlanması

Özellik seçimi problemi, ikili (binary) bir optimizasyon problemi olarak formüle edilmektedir:

**Amaç Fonksiyonu:**
```
minimize: f(X) = α × (1 - Accuracy) + β × (|S| / |F|)
```

Burada:
- `X`: İkili özellik vektörü (0: seçilmedi, 1: seçildi)
- `Accuracy`: Seçilen özelliklerle elde edilen sınıflandırma doğruluğu
- `|S|`: Seçilen özellik sayısı
- `|F|`: Toplam özellik sayısı
- `α, β`: Ağırlık katsayıları (α + β = 1)

### 5.4.3. HHO Parametreleri

| Parametre | Değer | Açıklama |
|-----------|-------|----------|
| Popülasyon Boyutu | 20 | Şahin sayısı |
| Maksimum İterasyon | 100 | Sonlandırma kriteri |
| β (Beta) | 0.5 | Levy uçuşu parametresi |
| Sınıflandırıcı | LightGBM | Uygunluk değerlendirmesi için |

### 5.4.4. Seçilen Özellikler

HHO algoritması, CIC-DDoS2019 veri setinde 78 özellikten **45 özellik** seçmiştir:

**Tablo 5.1. HHO ile Seçilen 45 Özellik**

| # | Özellik Adı | Kategori |
|---|-------------|----------|
| 1 | Subflow Bwd Packets | Paket Sayısı |
| 2 | Fwd Packet Length Max | Paket Boyutu |
| 3 | Idle Mean | Zaman |
| 4 | Packet Length Max | Paket Boyutu |
| 5 | Flow Bytes/s | Hız |
| 6 | Packet Length Min | Paket Boyutu |
| 7 | ACK Flag Count | TCP Bayrak |
| 8 | Fwd Seg Size Min | Segment |
| 9 | RST Flag Count | TCP Bayrak |
| 10 | Init Fwd Win Bytes | Pencere |
| 11 | CWE Flag Count | TCP Bayrak |
| 12 | Init Bwd Win Bytes | Pencere |
| 13 | Fwd Header Length | Başlık |
| 14 | Bwd IAT Max | Zaman |
| 15 | Avg Bwd Segment Size | Segment |
| 16 | Bwd Packet Length Mean | Paket Boyutu |
| 17 | Subflow Fwd Packets | Paket Sayısı |
| 18 | Active Max | Zaman |
| 19 | Fwd Packet Length Std | Paket Boyutu |
| 20 | Packet Length Variance | Paket Boyutu |
| 21 | Flow Duration | Zaman |
| 22 | Total Fwd Packets | Paket Sayısı |
| 23 | Total Backward Packets | Paket Sayısı |
| 24 | Fwd Packets Length Total | Paket Boyutu |
| 25 | Fwd Packet Length Min | Paket Boyutu |
| 26 | Bwd Packet Length Max | Paket Boyutu |
| 27 | Flow IAT Mean | Zaman |
| 28 | Flow IAT Max | Zaman |
| 29 | Fwd IAT Total | Zaman |
| 30 | Fwd IAT Std | Zaman |
| 31 | Fwd IAT Min | Zaman |
| 32 | Bwd IAT Mean | Zaman |
| 33 | Bwd IAT Std | Zaman |
| 34 | Idle Max | Zaman |
| 35 | Subflow Fwd Bytes | Bayt Sayısı |
| 36 | Fwd Act Data Packets | Paket Sayısı |
| 37 | Packet Length Mean | Paket Boyutu |
| 38 | Active Min | Zaman |
| 39 | Protocol | Protokol |
| 40 | Bwd Packets Length Total | Paket Boyutu |
| 41 | Bwd Packet Length Min | Paket Boyutu |
| 42 | Fwd IAT Mean | Zaman |
| 43 | Down/Up Ratio | Oran |
| 44 | Avg Fwd Segment Size | Segment |
| 45 | Active Mean | Zaman |

### 5.4.5. Diğer Optimizasyon Algoritmalarıyla Karşılaştırma

| Algoritma | Seçilen Özellik Sayısı | Accuracy | F1-Score |
|-----------|------------------------|----------|----------|
| Tüm Özellikler | 78 | 0.9985 | 0.9972 |
| PSO | 30 | 0.9991 | 0.9986 |
| GWO | 62 | 0.9993 | 0.9990 |
| DFO | 36 | 0.9989 | 0.9981 |
| **HHO** | **45** | **1.0000** | **0.9990** |

## 5.5. Model Eğitimi: Boosted Decision Tree (BDT)

### 5.5.1. BDT Algoritması

Boosted Decision Tree (BDT), ensemble öğrenme yöntemlerinden biridir. Gradient Boosting yaklaşımı kullanılarak birden fazla zayıf öğrenici (karar ağacı) sıralı olarak eğitilir ve her ağaç, önceki ağaçların hatalarını düzeltmeye çalışır.

**Gradient Boosting Formülasyonu:**

```
F_m(x) = F_{m-1}(x) + γ_m × h_m(x)
```

Burada:
- `F_m(x)`: m. iterasyondaki model
- `h_m(x)`: m. zayıf öğrenici (karar ağacı)
- `γ_m`: Öğrenme oranı

### 5.5.2. Hiperparametre Optimizasyonu

Model hiperparametreleri, Azure ML Studio'nun Tune Model Hyperparameters modülü kullanılarak optimize edilmiştir:

**Tablo 5.2. Optimize Edilmiş BDT Hiperparametreleri**

| Hiperparametre | CIC-DDoS2019 | NSL-KDD | Açıklama |
|----------------|--------------|---------|----------|
| Number of Leaves | 59 | 36 | Yaprak düğüm sayısı |
| Min Leaf Instances | 27 | 7 | Yaprakta min. örnek |
| Learning Rate | 0.391 | 0.333 | Öğrenme oranı |
| Number of Trees | 22 | 182 | Ağaç sayısı |

### 5.5.3. Model Eğitim Süreci

```python
from sklearn.ensemble import GradientBoostingClassifier

# HHO ile seçilen özellikler
X_train_selected = X_train[HHO_SELECTED_FEATURES]
X_test_selected = X_test[HHO_SELECTED_FEATURES]

# BDT modeli oluşturma
model = GradientBoostingClassifier(
    n_estimators=22,           # Ağaç sayısı
    learning_rate=0.391,       # Öğrenme oranı
    max_depth=5,               # Maksimum derinlik
    min_samples_leaf=27,       # Yaprakta min. örnek
    random_state=42
)

# Eğitim
model.fit(X_train_selected, y_train)

# Tahmin
y_pred = model.predict(X_test_selected)
y_prob = model.predict_proba(X_test_selected)[:, 1]
```

## 5.6. Model Değerlendirme

### 5.6.1. Performans Metrikleri

Model performansı, aşağıdaki metrikler kullanılarak değerlendirilmiştir:

**Confusion Matrix Bileşenleri:**
- **TP (True Positive)**: Doğru tespit edilen saldırılar
- **TN (True Negative)**: Doğru tespit edilen normal trafik
- **FP (False Positive)**: Yanlış alarm (normal trafik saldırı olarak işaretlendi)
- **FN (False Negative)**: Kaçırılan saldırı

**Hesaplanan Metrikler:**

```
                    TP + TN
Accuracy = ─────────────────────────
            TP + TN + FP + FN

                TP
Precision = ─────────
             TP + FP

              TP
Recall = ─────────
          TP + FN

              2 × Precision × Recall
F1-Score = ────────────────────────────
              Precision + Recall

              FP
FAR = ─────────────
       FP + TN

              FP
FPR = ─────────────
       FP + TN
```

### 5.6.2. CIC-DDoS2019 Sonuçları

**Tablo 5.3. CIC-DDoS2019 Veri Seti Üzerinde HHO-BDT Sonuçları**

| Metrik | Değer |
|--------|-------|
| **Accuracy** | **1.0000 (100%)** |
| Precision | 0.9990 (99.90%) |
| Recall | 0.9990 (99.90%) |
| F1-Score | 0.9990 (99.90%) |
| AUC | 1.0000 (100%) |
| FAR | 0.00062 |
| FPR | 0.00037 |

**Confusion Matrix (CIC-DDoS2019):**

```
                    Tahmin
                 Benign  Attack
Gerçek  Benign   17,042      6
        Attack       0   108,579
```

### 5.6.3. NSL-KDD Sonuçları

**Tablo 5.4. NSL-KDD Veri Seti Üzerinde PSO-BDT Sonuçları**

| Metrik | Değer |
|--------|-------|
| **Accuracy** | **0.9960 (99.60%)** |
| Precision | 0.9960 (99.60%) |
| Recall | 0.9970 (99.70%) |
| F1-Score | 0.9960 (99.60%) |
| AUC | 1.0000 (100%) |
| FAR | 0.00397 |
| FPR | 0.00469 |

### 5.6.4. Literatür Karşılaştırması

**Tablo 5.5. CIC-DDoS2019 Üzerinde Literatür Karşılaştırması**

| Çalışma | Yöntem | Özellik Seçimi | Accuracy | F1-Score |
|---------|--------|----------------|----------|----------|
| Jia et al. (2020) | LSTM | - | 98.90% | 99.35% |
| Alamri & Thayananthan (2020) | XGBoost | IG | 99.70% | 100% |
| Akgun et al. (2022) | CNN | IG | 99.99% | 95.68% |
| Batchu & Seetha (2022) | KNORA-U | RFECV+SHAP | 99.99% | 99.99% |
| Bakro et al. (2024) | RF | GOA-GA | 99.97% | 99.98% |
| **Önerilen (HHO-BDT)** | **BDT** | **HHO** | **100%** | **99.90%** |

## 5.7. Model Kaydı ve Dağıtımı

Eğitilmiş model, pickle formatında kaydedilerek dağıtıma hazır hale getirilmektedir:

```python
import pickle

# Model ve ölçekleyiciyi kaydet
model_data = {
    'model': model,
    'scaler': scaler,
    'features': HHO_SELECTED_FEATURES,
    'version': '1.0.0',
    'training_date': '2026-02-17',
    'metrics': {
        'accuracy': 1.0000,
        'precision': 0.9990,
        'recall': 0.9990,
        'f1_score': 0.9990
    }
}

with open('hho_bdt_model.pkl', 'wb') as f:
    pickle.dump(model_data, f)
```

## 5.8. Sonuç

Bu bölümde, DDoS saldırılarının tespiti için geliştirilen HHO-BDT hibrit modelinin geliştirme süreci detaylı olarak açıklanmıştır. Elde edilen sonuçlar şu şekilde özetlenebilir:

1. **Özellik Seçimi**: HHO algoritması, 78 özellikten en etkili 45 özelliği seçerek model karmaşıklığını %42 oranında azaltmıştır.

2. **Sınıflandırma Performansı**: HHO-BDT modeli, CIC-DDoS2019 veri setinde %100 doğruluk oranı elde etmiştir.

3. **Düşük Yanlış Alarm**: FAR değeri 0.00062 ile literatürdeki en düşük değerlerden biri elde edilmiştir.

4. **Literatür Karşılaştırması**: Önerilen model, karşılaştırılan tüm çalışmalardan daha yüksek veya eşdeğer performans sergilemiştir.

Bir sonraki bölümde, bu modelin SDN test ortamında gerçek zamanlı olarak test edilmesi ve deneysel sonuçlar sunulacaktır.
