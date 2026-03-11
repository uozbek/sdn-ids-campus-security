"""
SDN-IDS System Configuration
Makine Ogrenmesi Tabanli Gercek Zamanli Saldiri Tespit Sistemi
"""

# ML Service Configuration
ML_SERVICE_HOST = "127.0.0.1"
ML_SERVICE_PORT = 5000
ML_SERVICE_URL = f"http://{ML_SERVICE_HOST}:{ML_SERVICE_PORT}"

# SDN Controller Configuration
SDN_CONTROLLER_IP = "172.10.10.10"
SDN_CONTROLLER_PORT = 6653

# Detection Thresholds
CONFIDENCE_THRESHOLD = 0.85  # Minimum confidence for action
QUARANTINE_THRESHOLD = 0.70  # Below this -> quarantine, above -> drop

# Flow Timeout Settings (seconds)
QUARANTINE_TIMEOUT = 300  # 5 minutes quarantine
BLOCK_TIMEOUT = 3600      # 1 hour block for confirmed attacks

# Rate Limiting for Quarantine (packets per second)
QUARANTINE_RATE_LIMIT = 10

# HHO-Selected Features (45 features from the paper)
HHO_SELECTED_FEATURES = [
    'Subflow Bwd Packets', 'Fwd Packet Length Max', 'Idle Mean',
    'Packet Length Max', 'Flow Bytes/s', 'Packet Length Min',
    'ACK Flag Count', 'Fwd Seg Size Min', 'RST Flag Count',
    'Init Fwd Win Bytes', 'CWE Flag Count', 'Init Bwd Win Bytes',
    'Fwd Header Length', 'Bwd IAT Max', 'Avg Bwd Segment Size',
    'Bwd Packet Length Mean', 'Subflow Fwd Packets', 'Active Max',
    'Fwd Packet Length Std', 'Packet Length Variance', 'Flow Duration',
    'Total Fwd Packets', 'Total Backward Packets', 'Fwd Packets Length Total',
    'Fwd Packet Length Min', 'Bwd Packet Length Max', 'Flow IAT Mean',
    'Flow IAT Max', 'Fwd IAT Total', 'Fwd IAT Std', 'Fwd IAT Min',
    'Bwd IAT Mean', 'Bwd IAT Std', 'Idle Max', 'Subflow Fwd Bytes',
    'Fwd Act Data Packets', 'Packet Length Mean', 'Active Min', 'Protocol',
    'Bwd Packets Length Total', 'Bwd Packet Length Min', 'Fwd IAT Mean',
    'Down/Up Ratio', 'Avg Fwd Segment Size', 'Active Mean'
]

# Attack Types
ATTACK_TYPES = {0: 'BENIGN', 1: 'DDoS_ATTACK'}

# Logging
LOG_LEVEL = "INFO"
STATS_INTERVAL = 1.0
FEATURE_WINDOW = 10.0
