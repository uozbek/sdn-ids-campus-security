"""
ML Inference Service - REST API
HHO-BDT Model ile DDoS Saldiri Tespiti

Bu servis, egitilmis makine ogrenmesi modelini yukleyerek
gercek zamanli tahmin yapar ve SDN controller'a sonuc dondurur.
"""

from flask import Flask, request, jsonify
import numpy as np
import pickle
import logging
from datetime import datetime
import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import (
    ML_SERVICE_HOST, ML_SERVICE_PORT,
    HHO_SELECTED_FEATURES, ATTACK_TYPES,
    CONFIDENCE_THRESHOLD
)

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ML_Service')

# Global model variable
model = None
scaler = None

def load_model(model_path='../models/hho_bdt_model.pkl'):
    """Load the trained HHO-BDT model"""
    global model, scaler
    try:
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)
            model = model_data['model']
            scaler = model_data.get('scaler', None)
        logger.info(f"Model loaded successfully from {model_path}")
        return True
    except FileNotFoundError:
        logger.warning(f"Model file not found at {model_path}. Using demo mode.")
        return False
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        return False

def preprocess_features(features):
    """Preprocess and normalize features using Z-Score normalization"""
    feature_array = np.array(features).reshape(1, -1)

    if scaler is not None:
        feature_array = scaler.transform(feature_array)

    return feature_array

def predict_traffic(features):
    """
    Make prediction using the loaded model
    Returns: prediction, confidence, attack_type
    """
    global model

    if model is None:
        # Demo mode - simulate prediction for testing
        logger.warning("Running in demo mode - model not loaded")
        # Simulate based on some feature thresholds
        flow_bytes = features[4] if len(features) > 4 else 0
        if flow_bytes > 1000000:  # High traffic volume
            return 1, 0.92, 'DDoS_ATTACK'
        return 0, 0.98, 'BENIGN'

    try:
        # Preprocess features
        processed = preprocess_features(features)

        # Make prediction
        prediction = model.predict(processed)[0]

        # Get prediction probability/confidence
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(processed)[0]
            confidence = float(max(probabilities))
        else:
            confidence = 0.95  # Default confidence for models without predict_proba

        attack_type = ATTACK_TYPES.get(int(prediction), 'UNKNOWN')

        return int(prediction), confidence, attack_type

    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return 0, 0.0, 'ERROR'


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/predict', methods=['POST'])
def predict():
    """
    Main prediction endpoint

    Expected JSON format:
    {
        "features": [list of 45 feature values],
        "flow_id": "optional flow identifier",
        "src_ip": "source IP",
        "dst_ip": "destination IP"
    }
    """
    try:
        data = request.get_json()

        if not data or 'features' not in data:
            return jsonify({
                'error': 'Missing features in request',
                'required_features': len(HHO_SELECTED_FEATURES)
            }), 400

        features = data['features']
        flow_id = data.get('flow_id', 'unknown')
        src_ip = data.get('src_ip', 'unknown')
        dst_ip = data.get('dst_ip', 'unknown')

        # Validate feature count
        if len(features) != len(HHO_SELECTED_FEATURES):
            return jsonify({
                'error': f'Expected {len(HHO_SELECTED_FEATURES)} features, got {len(features)}',
                'expected_features': HHO_SELECTED_FEATURES
            }), 400

        # Make prediction
        prediction, confidence, attack_type = predict_traffic(features)

        # Determine action based on prediction and confidence
        if prediction == 1 and confidence >= CONFIDENCE_THRESHOLD:
            action = 'DROP'
        elif prediction == 1 and confidence >= 0.70:
            action = 'QUARANTINE'
        else:
            action = 'ALLOW'

        # Log the prediction
        logger.info(
            f"Prediction: flow={flow_id}, src={src_ip}, dst={dst_ip}, "
            f"result={attack_type}, confidence={confidence:.4f}, action={action}"
        )

        response = {
            'flow_id': flow_id,
            'prediction': prediction,
            'attack_type': attack_type,
            'confidence': round(confidence, 4),
            'action': action,
            'timestamp': datetime.now().isoformat()
        }

        return jsonify(response)

    except Exception as e:
        logger.error(f"Error processing request: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/predict/batch', methods=['POST'])
def predict_batch():
    """
    Batch prediction endpoint for multiple flows

    Expected JSON format:
    {
        "flows": [
            {"features": [...], "flow_id": "...", "src_ip": "...", "dst_ip": "..."},
            ...
        ]
    }
    """
    try:
        data = request.get_json()

        if not data or 'flows' not in data:
            return jsonify({'error': 'Missing flows in request'}), 400

        results = []
        for flow_data in data['flows']:
            features = flow_data.get('features', [])
            flow_id = flow_data.get('flow_id', 'unknown')

            if len(features) == len(HHO_SELECTED_FEATURES):
                prediction, confidence, attack_type = predict_traffic(features)

                if prediction == 1 and confidence >= CONFIDENCE_THRESHOLD:
                    action = 'DROP'
                elif prediction == 1 and confidence >= 0.70:
                    action = 'QUARANTINE'
                else:
                    action = 'ALLOW'

                results.append({
                    'flow_id': flow_id,
                    'prediction': prediction,
                    'attack_type': attack_type,
                    'confidence': round(confidence, 4),
                    'action': action
                })

        return jsonify({
            'results': results,
            'total_processed': len(results),
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Batch prediction error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/model/info', methods=['GET'])
def model_info():
    """Get model information"""
    return jsonify({
        'model_type': 'HHO-BDT (Harris Hawk Optimization + Boosted Decision Tree)',
        'feature_count': len(HHO_SELECTED_FEATURES),
        'features': HHO_SELECTED_FEATURES,
        'attack_types': ATTACK_TYPES,
        'model_loaded': model is not None,
        'confidence_threshold': CONFIDENCE_THRESHOLD
    })


@app.route('/statistics', methods=['GET'])
def get_statistics():
    """Get prediction statistics (placeholder for metrics tracking)"""
    # This would be populated with actual statistics in production
    return jsonify({
        'total_predictions': 0,
        'benign_count': 0,
        'attack_count': 0,
        'average_confidence': 0.0,
        'uptime': datetime.now().isoformat()
    })


if __name__ == '__main__':
    # Try to load the model
    model_loaded = load_model()

    if not model_loaded:
        logger.warning("Starting in DEMO mode - predictions will be simulated")

    # Start the Flask server
    logger.info(f"Starting ML Inference Service on {ML_SERVICE_HOST}:{ML_SERVICE_PORT}")
    app.run(
        host=ML_SERVICE_HOST,
        port=ML_SERVICE_PORT,
        debug=False,
        threaded=True
    )
