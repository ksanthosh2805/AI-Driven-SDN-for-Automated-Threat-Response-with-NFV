#!/usr/bin/env python3
"""
AI Model REST API for SDN Controller Integration
Provides real-time anomaly detection via HTTP endpoints
"""
from flask import Flask, request, jsonify
from flask_restful import Resource, Api
import joblib
import numpy as np
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
api = Api(app)

# Global model and preprocessor
model = None
scaler = None
label_encoder = None
model_name = None


def load_model_artifacts():
    """Load trained model and preprocessing artifacts"""
    global model, scaler, label_encoder, model_name

    try:
        model = joblib.load('best_model.pkl')
        scaler = joblib.load('feature_scaler.pkl')
        label_encoder = joblib.load('label_encoder.pkl')

        with open('best_model_name.txt', 'r') as f:
            model_name = f.read().strip()

        logger.info(f"Model loaded: {model_name}")
        return True
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        return False


class PredictAnomaly(Resource):
    """
    Endpoint: /predict
    Method: POST
    Input: JSON with flow features
    Output: JSON with prediction and confidence
    """

    def post(self):
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No data provided'}, 400

            # Extract 11 features
            features = self.extract_features(data)
            logger.info(f"DEBUG features length = {len(features)}, values = {features}")

            # Normalize
            features_normalized = scaler.transform([features])

            # Predict
            prediction = model.predict(features_normalized)[0]

            # Confidence
            confidence = self.get_confidence(features_normalized)

            label = 'BENIGN' if prediction == 0 else 'ATTACK'

            response = {
                'timestamp': datetime.now().isoformat(),
                'prediction': label,
                'prediction_code': int(prediction),
                'confidence': float(confidence),
                'model': model_name,
                'flow_summary': {
                    'src_ip': data.get('src_ip', 'unknown'),
                    'dst_ip': data.get('dst_ip', 'unknown'),
                    'packets': data.get('packets_total', 0),
                    'bytes': data.get('bytes_total', 0)
                }
            }

            logger.info(f"Prediction: {label} (confidence={confidence:.2f}) "
                        f"for {data.get('src_ip')} -> {data.get('dst_ip')}")

            return jsonify(response)

        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {'error': str(e)}, 500

    def extract_features(self, data):
        """Extract and compute features from input data (11 features)"""
        duration_sec       = float(data.get('duration_sec', 0))
        packets_total      = float(data.get('packets_total', 0))
        bytes_total        = float(data.get('bytes_total', 0))
        packets_per_sec    = float(data.get('packets_per_sec', 0))
        bytes_per_sec      = float(data.get('bytes_per_sec', 0))
        avg_packet_size    = float(data.get('avg_packet_size', 0))
        src_port           = float(data.get('src_port', 0))
        dst_port           = float(data.get('dst_port', 0))
        bytes_per_packet   = float(data.get('bytes_per_packet', 0))
        traffic_intensity  = float(data.get('traffic_intensity', 0))
        is_common_port     = float(data.get('is_common_port', 0))

        features = [
            duration_sec,
            packets_total,
            bytes_total,
            packets_per_sec,
            bytes_per_sec,
            avg_packet_size,
            src_port,
            dst_port,
            bytes_per_packet,
            traffic_intensity,
            is_common_port
        ]
        return features

    def get_confidence(self, features):
        """Get prediction confidence score"""
        try:
            if hasattr(model, 'predict_proba'):
                proba = model.predict_proba(features)[0]
                confidence = max(proba)
            elif hasattr(model, 'decision_function'):
                score = model.decision_function(features)[0]
                confidence = 1 / (1 + np.exp(-score))  # Sigmoid
            else:
                confidence = 0.5
            return confidence
        except Exception:
            return 0.5


class BatchPredict(Resource):
    """
    Endpoint: /batch_predict
    Method: POST
    Input: JSON list of flows
    Output: JSON list of predictions
    """

    def post(self):
        try:
            data = request.get_json()
            if not data or 'flows' not in data:
                return {'error': 'No flows provided'}, 400

            flows = data['flows']
            predictions = []

            for flow in flows:
                features = self.extract_features(flow)
                logger.info(f"DEBUG batch features length = {len(features)}, values = {features}")
                features_normalized = scaler.transform([features])

                prediction = model.predict(features_normalized)[0]
                label = 'BENIGN' if prediction == 0 else 'ATTACK'

                predictions.append({
                    'flow_id': flow.get('flow_id', 'unknown'),
                    'src_ip': flow.get('src_ip'),
                    'dst_ip': flow.get('dst_ip'),
                    'prediction': label,
                    'prediction_code': int(prediction)
                })

            return jsonify({
                'total_flows': len(flows),
                'predictions': predictions,
                'timestamp': datetime.now().isoformat()
            })

        except Exception as e:
            logger.error(f"Batch prediction error: {e}")
            return {'error': str(e)}, 500

    def extract_features(self, data):
        """Same 11-feature order as PredictAnomaly"""
        duration_sec       = float(data.get('duration_sec', 0))
        packets_total      = float(data.get('packets_total', 0))
        bytes_total        = float(data.get('bytes_total', 0))
        packets_per_sec    = float(data.get('packets_per_sec', 0))
        bytes_per_sec      = float(data.get('bytes_per_sec', 0))
        avg_packet_size    = float(data.get('avg_packet_size', 0))
        src_port           = float(data.get('src_port', 0))
        dst_port           = float(data.get('dst_port', 0))
        bytes_per_packet   = float(data.get('bytes_per_packet', 0))
        traffic_intensity  = float(data.get('traffic_intensity', 0))
        is_common_port     = float(data.get('is_common_port', 0))

        features = [
            duration_sec,
            packets_total,
            bytes_total,
            packets_per_sec,
            bytes_per_sec,
            avg_packet_size,
            src_port,
            dst_port,
            bytes_per_packet,
            traffic_intensity,
            is_common_port
        ]
        return features


class ModelInfo(Resource):
    def get(self):
        return jsonify({
            'model_name': model_name,
            'model_type': str(type(model).__name__),
            'features_count': len(scaler.mean_) if scaler else 0,
            'status': 'ready',
            'timestamp': datetime.now().isoformat()
        })


class HealthCheck(Resource):
    def get(self):
        return jsonify({
            'status': 'healthy',
            'model_loaded': model is not None,
            'timestamp': datetime.now().isoformat()
        })


# Register endpoints
api.add_resource(PredictAnomaly, '/predict')
api.add_resource(BatchPredict, '/batch_predict')
api.add_resource(ModelInfo, '/info')
api.add_resource(HealthCheck, '/health')


@app.route('/')
def index():
    return """
    <h1>AI Anomaly Detection API</h1>
    <h2>Endpoints:</h2>
    <ul>
        <li><b>POST /predict</b> - Single flow prediction</li>
        <li><b>POST /batch_predict</b> - Batch flow predictions</li>
        <li><b>GET /info</b> - Model information</li>
        <li><b>GET /health</b> - Health check</li>
    </ul>
    """


if __name__ == '__main__':
    print("=" * 70)
    print("AI ANOMALY DETECTION API")
    print("=" * 70)

    if not load_model_artifacts():
        print("ERROR: Could not load model artifacts!")
        print("Make sure you have:")
        print("  - best_model.pkl")
        print("  - feature_scaler.pkl")
        print("  - label_encoder.pkl")
        print("  - best_model_name.txt")
        exit(1)

    print(f"\nModel: {model_name}")
    print("Starting API server on http://0.0.0.0:5000")
    print("=" * 70 + "\n")

    app.run(host='0.0.0.0', port=5000, debug=False)
