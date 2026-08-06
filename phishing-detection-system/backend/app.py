"""
backend/app.py
Flask REST API — loads model.pkl + scaler.pkl, exposes real-time prediction, history,
analytics, auth, and bulk-scan endpoints with structured debug logging and risk levels.
"""

import os
import sys
import time
import pickle
import sqlite3
import datetime
import logging
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, get_jwt_identity, verify_jwt_in_request

from auth import auth_bp, init_auth, register_blocklist_check
from enrichment import enrich

# Configure structured logging for task 6
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

ML_DIR = os.path.join(os.path.dirname(__file__), '..', 'machine-learning')
sys.path.insert(0, ML_DIR)
from feature_extraction import (
    extract_features, features_to_vector, get_detection_signals,
    normalize_url, FEATURE_COLS
)
from trusted_domains import is_trusted_domain

app = Flask(__name__)
CORS(app, origins='*')

app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'phishguard-secure-secret-key-2026')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=30)

jwt = JWTManager(app)
register_blocklist_check(jwt)

DB_PATH = os.path.join(os.path.dirname(__file__), 'phishing_history.db')
init_auth(DB_PATH)
app.register_blueprint(auth_bp)

# ─── 1. Load ML Artifacts & Validation ───────────────────────────────────────

def load_artifact(filename):
    filepath = os.path.join(ML_DIR, filename)
    if not os.path.exists(filepath):
        logging.warning(f"ML artifact missing at {filepath}")
        return None
    try:
        with open(filepath, 'rb') as f:
            obj = pickle.load(f)
            logging.info(f"Loaded ML artifact successfully: {filename}")
            return obj
    except Exception as e:
        logging.error(f"Failed to load ML artifact {filename}: {e}")
        return None

model = load_artifact('model.pkl')
scaler = load_artifact('scaler.pkl')

individual_models = {}
for name in ['random_forest', 'decision_tree', 'logistic_regression', 'svm']:
    m = load_artifact(f'{name}.pkl')
    if m is not None:
        individual_models[name] = m

# ─── SQLite History Setup ───────────────────────────────────────────────────

def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute('''CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT, prediction TEXT, risk_score REAL,
            confidence REAL, scanned_at TEXT)''')
        cols = [r[1] for r in conn.execute('PRAGMA table_info(scan_history)').fetchall()]
        if cols and 'user_id' not in cols:
            conn.execute('ALTER TABLE scan_history ADD COLUMN user_id INTEGER')
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Database initialization error: {e}")

init_db()


def _optional_user_id():
    try:
        verify_jwt_in_request(optional=True)
        return get_jwt_identity()
    except Exception:
        return None


def save_scan(url, prediction, risk_score, confidence, user_id=None):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            'INSERT INTO scan_history (user_id,url,prediction,risk_score,confidence,scanned_at) VALUES (?,?,?,?,?,?)',
            (user_id, url, prediction, risk_score, confidence, datetime.datetime.now(datetime.timezone.utc).isoformat())
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Error saving scan to database: {e}")

# ─── Real-Time ML Prediction Engine ──────────────────────────────────────────

def ml_predict(url: str) -> dict:
    t0 = time.time()
    logging.info(f"--- SCAN REQUEST RECEIVED: {url} ---")

    # 1. URL Normalization
    try:
        norm_url = normalize_url(url)
    except Exception as err:
        logging.warning(f"URL normalization warning for '{url}': {err}")
        norm_url = url.strip()

    # 2. Feature Extraction
    features = extract_features(norm_url)
    signals = get_detection_signals(features)
    trusted = is_trusted_domain(norm_url)

    if trusted:
        signals.insert(0, {
            'signal': 'Trusted Provider Domain',
            'severity': 'safe',
            'description': 'Verified domain of a major trusted platform.'
        })

    # Task 11: Error handling if model is missing
    if model is None or scaler is None:
        elapsed = round((time.time() - t0) * 1000, 2)
        logging.error("Model or scaler not loaded; using safety fallback.")
        return {
            'prediction': 'safe' if trusted else 'suspicious',
            'confidence': 99.0 if trusted else 50.0,
            'risk_score': 2.0 if trusted else 50.0,
            'risk_level': 'Safe' if trusted else 'Medium',
            'signals': signals,
            'features': features,
            'model_comparison': {},
            'method': 'fallback',
            'inference_time_ms': elapsed
        }

    # 3. Feature Vector & Scaling
    feature_vec = features_to_vector(features)
    X = np.array(feature_vec).reshape(1, -1)

    # Verify input shape
    if X.shape[1] != len(FEATURE_COLS):
        raise ValueError(f"Feature dimension mismatch: Expected {len(FEATURE_COLS)}, got {X.shape[1]}")

    X_scaled = scaler.transform(X)

    # 4. Model Inference & Probabilities
    proba = model.predict_proba(X_scaled)[0]
    phishing_prob = float(proba[1])  # 1 = Phishing, 0 = Legitimate
    confidence = float(max(proba)) * 100.0

    # Trusted domain modifier to suppress false positives on OAuth/complex trusted URLs
    if trusted:
        phishing_prob = min(phishing_prob, 0.05)

    # Task 5: Risk Score & Risk Level Mapping
    risk_score = round(phishing_prob * 100.0, 1)

    if risk_score <= 30.0:
        risk_level = 'Safe'
        prediction = 'safe'
    elif risk_score <= 70.0:
        risk_level = 'Medium'
        prediction = 'suspicious'
    else:
        risk_level = 'High'
        prediction = 'phishing'

    # Task 6: Multi-Model Comparison Inference
    model_comparison = {}
    for name, m in individual_models.items():
        try:
            p = m.predict(X_scaled)[0]
            prob = m.predict_proba(X_scaled)[0]
            p_phish = float(prob[1])
            if trusted:
                p_phish = min(p_phish, 0.05)
            model_comparison[name] = {
                'prediction': 'phishing' if (p == 1 and not trusted) else 'safe',
                'confidence': round(float(max(prob)) * 100.0, 1),
                'phishing_probability': round(p_phish * 100.0, 1)
            }
        except Exception as e:
            logging.debug(f"Error in model comparison for {name}: {e}")

    elapsed_ms = round((time.time() - t0) * 1000, 2)

    # Task 6: Comprehensive Debug Logging
    logging.info(f"Normalized URL: {norm_url}")
    logging.info(f"Extracted Features: {features}")
    logging.info(f"Feature Vector ({len(feature_vec)} cols): {feature_vec}")
    logging.info(f"Raw Model Proba (0=Legit, 1=Phish): {proba}")
    logging.info(f"Calculated Risk Score: {risk_score}% | Risk Level: {risk_level} | Verdict: {prediction}")
    logging.info(f"Execution Latency: {elapsed_ms} ms")

    # Task 10: Standardized API response format
    return {
        'prediction': 'Phishing' if prediction == 'phishing' else ('Suspicious' if prediction == 'suspicious' else 'Safe'),
        'confidence': round(confidence, 1),
        'risk_score': risk_score,
        'risk_level': risk_level,
        'signals': signals,
        'features': features,
        'model_comparison': model_comparison,
        'method': 'realtime-ml',
        'inference_time_ms': elapsed_ms
    }

# ─── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None,
        'scaler_loaded': scaler is not None,
        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()
    })


@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(silent=True)
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing "url" field in request body'}), 400

    raw_url = str(data['url']).strip()
    if not raw_url:
        return jsonify({'error': 'URL cannot be empty'}), 400

    try:
        res = ml_predict(raw_url)
        # Compatibility field for extension lowercase status mapping
        res['prediction_code'] = res['prediction'].lower()
        
        # Security enrichment
        extra = enrich(raw_url, res['features'], res['signals'], res['prediction'].lower(), res['risk_score'])
        res.update(extra)
        res['url'] = raw_url
        res['scanned_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()

        user_id = _optional_user_id()
        save_scan(raw_url, res['prediction'], res['risk_score'], res['confidence'], user_id)
        return jsonify(res), 200

    except ValueError as ve:
        logging.warning(f"Validation error for input '{raw_url}': {ve}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logging.error(f"Prediction exception for URL '{raw_url}': {e}", exc_info=True)
        return jsonify({'error': 'Internal prediction processing error', 'details': str(e)}), 500


@app.route('/history', methods=['GET'])
def history():
    limit = request.args.get('limit', 50, type=int)
    result_filter = request.args.get('result')
    search = request.args.get('search')
    user_id = _optional_user_id()

    query = 'SELECT id,url,prediction,risk_score,confidence,scanned_at FROM scan_history WHERE 1=1'
    params = []
    if user_id:
        query += ' AND user_id = ?'
        params.append(user_id)
    if result_filter:
        query += ' AND LOWER(prediction) = LOWER(?)'
        params.append(result_filter)
    if search:
        query += ' AND url LIKE ?'
        params.append(f'%{search}%')
    query += ' ORDER BY id DESC LIMIT ?'
    params.append(limit)

    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return jsonify([
            {'id': r[0], 'url': r[1], 'prediction': r[2], 'risk_score': r[3], 'confidence': r[4], 'scanned_at': r[5]}
            for r in rows
        ])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/statistics', methods=['GET'])
def statistics():
    user_id = _optional_user_id()
    try:
        conn = sqlite3.connect(DB_PATH)
        base = 'FROM scan_history WHERE 1=1'
        params = []
        if user_id:
            base += ' AND user_id = ?'
            params.append(user_id)

        total = conn.execute(f'SELECT COUNT(*) {base}', params).fetchone()[0]
        phishing = conn.execute(f"SELECT COUNT(*) {base} AND (LOWER(prediction)='phishing' OR LOWER(prediction)='high')", params).fetchone()[0]
        suspicious = conn.execute(f"SELECT COUNT(*) {base} AND (LOWER(prediction)='suspicious' OR LOWER(prediction)='medium')", params).fetchone()[0]
        conn.close()
        return jsonify({
            'total': total, 'phishing': phishing,
            'suspicious': suspicious, 'safe': total - phishing - suspicious
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/report-false-positive', methods=['POST'])
def report_false_positive():
    data = request.get_json(silent=True) or {}
    url = data.get('url', '')
    logging.info(f"[REPORT] False positive reported for: {url}")
    return jsonify({'status': 'received', 'message': 'Thank you for your report.', 'success': True})


if __name__ == '__main__':
    print("[INFO] Starting PhishGuard API on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=True)
