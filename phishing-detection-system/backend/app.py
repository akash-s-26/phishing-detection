"""
backend/app.py
Flask REST API — loads model.pkl + scaler.pkl, exposes 6 endpoints.
This is what the Chrome extension and dashboard both talk to.
"""

import os
import sys
import pickle
import sqlite3
import datetime
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS

ML_DIR = os.path.join(os.path.dirname(__file__), '..', 'machine-learning')
sys.path.insert(0, ML_DIR)
from feature_extraction import extract_features, features_to_vector, get_detection_signals

app = Flask(__name__)
CORS(app, origins='*')  # extension + dashboard both need cross-origin access

DB_PATH = os.path.join(os.path.dirname(__file__), 'phishing_history.db')

# ─── Load ML artifacts once at startup (not per-request) ─────────────────────

def load(fname):
    with open(os.path.join(ML_DIR, fname), 'rb') as f:
        return pickle.load(f)

try:
    model = load('model.pkl')
    scaler = load('scaler.pkl')
    print("[INFO] Model and scaler loaded successfully")
except Exception as e:
    print(f"[WARN] Could not load ML artifacts: {e}")
    model, scaler = None, None

individual_models = {}
for name in ['random_forest', 'logistic_regression', 'decision_tree', 'svm']:
    try:
        individual_models[name] = load(f'{name}.pkl')
    except Exception:
        pass

# ─── SQLite setup ──────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT, prediction TEXT, risk_score REAL,
        confidence REAL, scanned_at TEXT)''')
    conn.commit()
    conn.close()

init_db()


def save_scan(url, prediction, risk_score, confidence):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        'INSERT INTO scan_history (url,prediction,risk_score,confidence,scanned_at) VALUES (?,?,?,?,?)',
        (url, prediction, risk_score, confidence, datetime.datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

# ─── Prediction logic ───────────────────────────────────────────────────────────

def ml_predict(url: str) -> dict:
    features = extract_features(url)
    signals = get_detection_signals(features)

    if model is None or scaler is None:
        return {
            'prediction': 'safe', 'risk_score': 0, 'confidence': 0,
            'features': features, 'signals': signals, 'method': 'no-model'
        }

    X = np.array(features_to_vector(features)).reshape(1, -1)
    X_scaled = scaler.transform(X)
    proba = model.predict_proba(X_scaled)[0]
    phishing_prob = float(proba[1])
    confidence = float(max(proba))

    if phishing_prob >= 0.65:
        prediction = 'phishing'
    elif phishing_prob >= 0.35:
        prediction = 'suspicious'
    else:
        prediction = 'safe'

    model_comparison = {}
    for name, m in individual_models.items():
        try:
            p = m.predict(X_scaled)[0]
            prob = m.predict_proba(X_scaled)[0]
            model_comparison[name] = {
                'prediction': 'phishing' if p == 1 else 'safe',
                'confidence': round(float(max(prob)) * 100, 1)
            }
        except Exception:
            pass

    return {
        'prediction': prediction,
        'risk_score': round(phishing_prob * 100, 1),
        'confidence': round(confidence * 100, 1),
        'features': features,
        'signals': signals,
        'model_comparison': model_comparison,
        'method': 'ml'
    }

# ─── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    """Extension + dashboard both poll this to show online/offline status."""
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None,
        'timestamp': datetime.datetime.utcnow().isoformat()
    })


@app.route('/predict', methods=['POST'])
def predict():
    """Main endpoint — the extension calls this on every page navigation."""
    data = request.get_json(silent=True)
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing "url" field in request body'}), 400

    url = data['url'].strip()
    if not url:
        return jsonify({'error': 'URL cannot be empty'}), 400

    try:
        result = ml_predict(url)
        result['url'] = url
        result['scanned_at'] = datetime.datetime.utcnow().isoformat()
        save_scan(url, result['prediction'], result['risk_score'], result['confidence'])
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/history', methods=['GET'])
def history():
    limit = request.args.get('limit', 20, type=int)
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        'SELECT url,prediction,risk_score,confidence,scanned_at FROM scan_history ORDER BY id DESC LIMIT ?',
        (limit,)
    ).fetchall()
    conn.close()
    return jsonify([
        {'url': r[0], 'prediction': r[1], 'risk_score': r[2], 'confidence': r[3], 'scanned_at': r[4]}
        for r in rows
    ])


@app.route('/statistics', methods=['GET'])
def statistics():
    conn = sqlite3.connect(DB_PATH)
    total = conn.execute('SELECT COUNT(*) FROM scan_history').fetchone()[0]
    phishing = conn.execute("SELECT COUNT(*) FROM scan_history WHERE prediction='phishing'").fetchone()[0]
    suspicious = conn.execute("SELECT COUNT(*) FROM scan_history WHERE prediction='suspicious'").fetchone()[0]
    conn.close()
    return jsonify({
        'total': total, 'phishing': phishing,
        'suspicious': suspicious, 'safe': total - phishing - suspicious
    })


@app.route('/bulk-predict', methods=['POST'])
def bulk_predict():
    data = request.get_json(silent=True)
    if not data or 'urls' not in data:
        return jsonify({'error': 'Missing "urls" field'}), 400
    results = []
    for url in data['urls'][:50]:
        try:
            r = ml_predict(url.strip())
            r['url'] = url
            results.append(r)
        except Exception as e:
            results.append({'url': url, 'error': str(e)})
    return jsonify({'results': results})


@app.route('/report-false-positive', methods=['POST'])
def report_false_positive():
    """Called by the extension's 'Report False Positive' button."""
    data = request.get_json(silent=True) or {}
    url = data.get('url', '')
    print(f"[REPORT] False positive reported for: {url}")
    return jsonify({'status': 'received', 'message': 'Thank you for your report.'})


if __name__ == '__main__':
    print("[INFO] Starting Phishing Detection API on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=True)
