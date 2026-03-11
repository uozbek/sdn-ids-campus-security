"""
Demo Model Trainer
HHO-BDT Modeli Egitimi icin Ornek Script

Bu script, CIC-DDoS2019 veri seti ile HHO-BDT modelini egitir.
Gercek kullanim icin veri setini indirip preprocess etmeniz gerekmektedir.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import pickle
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import HHO_SELECTED_FEATURES


def create_demo_dataset(n_samples=10000):
    """
    Create a demo dataset for testing purposes
    In real usage, use CIC-DDoS2019 or NSL-KDD datasets
    """
    np.random.seed(42)

    # Generate benign traffic features
    n_benign = n_samples // 2
    benign_data = {
        'Subflow Bwd Packets': np.random.randint(0, 100, n_benign),
        'Fwd Packet Length Max': np.random.randint(40, 1500, n_benign),
        'Idle Mean': np.random.uniform(0, 1000000, n_benign),
        'Packet Length Max': np.random.randint(40, 1500, n_benign),
        'Flow Bytes/s': np.random.uniform(100, 100000, n_benign),  # Normal range
        'Packet Length Min': np.random.randint(20, 100, n_benign),
        'ACK Flag Count': np.random.randint(0, 50, n_benign),
        'Fwd Seg Size Min': np.random.randint(20, 100, n_benign),
        'RST Flag Count': np.random.randint(0, 5, n_benign),
        'Init Fwd Win Bytes': np.random.randint(1000, 65535, n_benign),
        'CWE Flag Count': np.random.randint(0, 2, n_benign),
        'Init Bwd Win Bytes': np.random.randint(1000, 65535, n_benign),
        'Fwd Header Length': np.random.randint(20, 60, n_benign),
        'Bwd IAT Max': np.random.uniform(0, 1000000, n_benign),
        'label': np.zeros(n_benign)
    }

    # Generate attack traffic features (higher values, more packets)
    n_attack = n_samples - n_benign
    attack_data = {
        'Subflow Bwd Packets': np.random.randint(100, 10000, n_attack),
        'Fwd Packet Length Max': np.random.randint(40, 200, n_attack),  # Smaller packets
        'Idle Mean': np.random.uniform(0, 100, n_attack),  # Less idle
        'Packet Length Max': np.random.randint(40, 200, n_attack),
        'Flow Bytes/s': np.random.uniform(1000000, 100000000, n_attack),  # Very high
        'Packet Length Min': np.random.randint(20, 60, n_attack),
        'ACK Flag Count': np.random.randint(0, 10, n_attack),
        'Fwd Seg Size Min': np.random.randint(20, 60, n_attack),
        'RST Flag Count': np.random.randint(5, 50, n_attack),  # More RST
        'Init Fwd Win Bytes': np.random.randint(100, 1000, n_attack),
        'CWE Flag Count': np.random.randint(0, 1, n_attack),
        'Init Bwd Win Bytes': np.random.randint(100, 1000, n_attack),
        'Fwd Header Length': np.random.randint(20, 40, n_attack),
        'Bwd IAT Max': np.random.uniform(0, 100, n_attack),  # Less IAT
        'label': np.ones(n_attack)
    }

    # Combine datasets
    df_benign = pd.DataFrame(benign_data)
    df_attack = pd.DataFrame(attack_data)
    df = pd.concat([df_benign, df_attack], ignore_index=True)

    # Add remaining features with random values
    for feature in HHO_SELECTED_FEATURES:
        if feature not in df.columns:
            df[feature] = np.random.uniform(0, 1000, n_samples)

    return df


def train_hho_bdt_model(df, feature_columns, label_column='label'):
    """
    Train Boosted Decision Tree model

    This simulates the HHO-BDT model from the paper.
    In real implementation, you would:
    1. Apply HHO for feature selection
    2. Train BDT on selected features
    """
    print("Training HHO-BDT Model...")

    X = df[feature_columns].values
    y = df[label_column].values

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    # Z-Score normalization
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train Gradient Boosting (BDT)
    model = GradientBoostingClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=5,
        min_samples_leaf=20,
        random_state=42
    )

    model.fit(X_train_scaled, y_train)

    # Evaluate
    y_pred = model.predict(X_test_scaled)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print(f"\nModel Performance:")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1-Score:  {f1:.4f}")

    return model, scaler


def save_model(model, scaler, output_path):
    """Save trained model and scaler"""
    model_data = {
        'model': model,
        'scaler': scaler,
        'features': HHO_SELECTED_FEATURES,
        'version': '1.0.0'
    }

    with open(output_path, 'wb') as f:
        pickle.dump(model_data, f)

    print(f"\nModel saved to: {output_path}")


def main():
    """Main training pipeline"""
    print("=" * 60)
    print("HHO-BDT Model Training for SDN-IDS")
    print("=" * 60)

    # Create demo dataset
    print("\n1. Creating demo dataset...")
    df = create_demo_dataset(n_samples=10000)
    print(f"   Dataset size: {len(df)} samples")
    print(f"   Benign: {(df['label']==0).sum()}, Attack: {(df['label']==1).sum()}")

    # Get feature columns (45 HHO-selected features)
    feature_columns = [f for f in HHO_SELECTED_FEATURES if f in df.columns]
    print(f"\n2. Using {len(feature_columns)} features")

    # Train model
    print("\n3. Training model...")
    model, scaler = train_hho_bdt_model(df, feature_columns)

    # Save model
    print("\n4. Saving model...")
    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, 'hho_bdt_model.pkl')
    save_model(model, scaler, output_path)

    print("\n" + "=" * 60)
    print("Training complete!")
    print("=" * 60)


if __name__ == '__main__':
    main()
