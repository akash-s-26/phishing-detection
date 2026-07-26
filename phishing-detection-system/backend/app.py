"""
backend/app.py
Flask REST API — loads model.pkl + scaler.pkl, exposes prediction, history,
analytics, auth, and bulk-scan endpoints. Consumed by the PhishShield React
frontend, the Chrome extension, and the dashboard.
"""

import os
import sys
import pickle
import sqlite3
import datetime
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, get_jwt_identity, verify_jwt_in_request

from auth import auth_bp, init_auth, register_blocklist_check
from enrichment import enrich

ML_DIR = os.path.join(os.path.dirname(__file__), '..', 'machine-learning')
sys.path.insert(0, ML_DIR)
from feature_extraction import extract_features, features_to_vector, get_detection_signals
from trusted_domains import is_trusted_domain

app = Flask(__name__)
CORS(app, origins='*', supports_credentials=True)

app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'change-this-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=30)

jwt = JWTManager(app)
register_blocklist_check(jwt)

DB_PATH = os.path.join(os.path.dirname(__file__), 'phishing_history.db')
init_auth(DB_PATH)
app.register_blueprint(auth_bp)

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
        user_id INTEGER,
        url TEXT, prediction TEXT, risk_score REAL,
        confidence REAL, scanned_at TEXT)''')
    conn.commit()
    conn.close()

init_db()


def _optional_user_id():
    """Scans work whether logged in or not; attach a user_id when a valid token is present."""
    try:
        verify_jwt_in_request(optional=True)
        return get_jwt_identity()
    except Exception:
        return None


def save_scan(url, prediction, risk_score, confidence, user_id=None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        'INSERT INTO scan_history (user_id,url,prediction,risk_score,confidence,scanned_at) VALUES (?,?,?,?,?,?)',
        (user_id, url, prediction, risk_score, confidence, datetime.datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

# ─── Prediction logic ───────────────────────────────────────────────────────────

def ml_predict(url: str) -> dict:
    features = extract_features(url)

    # Trusted-provider short-circuit: structurally complex but entirely
    # legitimate URLs (Google/Microsoft/Apple OAuth sign-in flows, GitHub,
    # etc.) can score as high-risk on pure structural features alone
    # (length, special-char count, query-param count). Rather than let a
    # long, real accounts.google.com sign-in URL get flagged as phishing,
    # verify the domain against a small trusted allowlist first.
    if is_trusted_domain(url):
        return {
            'prediction': 'safe',
            'risk_score': 2.0,
            'confidence': 99.0,
            'features': features,
            'signals': [{
                'signal': 'Trusted Provider Domain',
                'severity': 'safe',
                'description': 'This domain belongs to a verified, well-known provider — structural URL complexity (common in OAuth/SSO login flows) is expected and not treated as risk.'
            }],
            'model_comparison': {},
            'method': 'trusted-allowlist'
        }

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
    """Main endpoint — scan a single URL. Enriches the ML verdict with
    SSL, WHOIS/domain-age, redirect-chain, and blacklist checks."""
    data = request.get_json(silent=True)
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing "url" field in request body'}), 400

    url = data['url'].strip()
    if not url:
        return jsonify({'error': 'URL cannot be empty'}), 400

    try:
        result = ml_predict(url)
        extra = enrich(url, result['features'], result['signals'], result['prediction'], result['risk_score'])
        result.update(extra)
        result['url'] = url
        result['scanned_at'] = datetime.datetime.utcnow().isoformat()

        user_id = _optional_user_id()
        save_scan(url, result['prediction'], result['risk_score'], result['confidence'], user_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/history', methods=['GET'])
def history():
    """Scan history. Filterable by result, date range, and a URL keyword search.
    If a valid JWT is provided, results are scoped to that user; otherwise global."""
    limit = request.args.get('limit', 50, type=int)
    result_filter = request.args.get('result')
    search = request.args.get('search')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    user_id = _optional_user_id()

    query = 'SELECT id,url,prediction,risk_score,confidence,scanned_at FROM scan_history WHERE 1=1'
    params = []
    if user_id:
        query += ' AND user_id = ?'
        params.append(user_id)
    if result_filter:
        query += ' AND prediction = ?'
        params.append(result_filter)
    if search:
        query += ' AND url LIKE ?'
        params.append(f'%{search}%')
    if date_from:
        query += ' AND scanned_at >= ?'
        params.append(date_from)
    if date_to:
        query += ' AND scanned_at <= ?'
        params.append(date_to)
    query += ' ORDER BY id DESC LIMIT ?'
    params.append(limit)

    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify([
        {'id': r[0], 'url': r[1], 'prediction': r[2], 'risk_score': r[3], 'confidence': r[4], 'scanned_at': r[5]}
        for r in rows
    ])


@app.route('/statistics', methods=['GET'])
def statistics():
    user_id = _optional_user_id()
    conn = sqlite3.connect(DB_PATH)
    base = 'FROM scan_history WHERE 1=1'
    params = []
    if user_id:
        base += ' AND user_id = ?'
        params.append(user_id)

    total = conn.execute(f'SELECT COUNT(*) {base}', params).fetchone()[0]
    phishing = conn.execute(f"SELECT COUNT(*) {base} AND prediction='phishing'", params).fetchone()[0]
    suspicious = conn.execute(f"SELECT COUNT(*) {base} AND prediction='suspicious'", params).fetchone()[0]
    conn.close()
    return jsonify({
        'total': total, 'phishing': phishing,
        'suspicious': suspicious, 'safe': total - phishing - suspicious
    })


@app.route('/analytics', methods=['GET'])
def analytics():
    """Daily/weekly trends + threat distribution for the Analytics page."""
    user_id = _optional_user_id()
    conn = sqlite3.connect(DB_PATH)
    base = 'FROM scan_history WHERE 1=1'
    params = []
    if user_id:
        base += ' AND user_id = ?'
        params.append(user_id)

    rows = conn.execute(
        f'SELECT prediction, scanned_at {base} ORDER BY scanned_at ASC', params
    ).fetchall()
    conn.close()

    daily = {}
    for prediction, scanned_at in rows:
        day = scanned_at[:10]
        daily.setdefault(day, {'date': day, 'safe': 0, 'suspicious': 0, 'phishing': 0})
        daily[day][prediction] = daily[day].get(prediction, 0) + 1

    daily_series = list(daily.values())[-30:]

    total = len(rows)
    phishing_count = sum(1 for p, _ in rows if p == 'phishing')
    suspicious_count = sum(1 for p, _ in rows if p == 'suspicious')
    safe_count = total - phishing_count - suspicious_count

    weekly = {}
    for prediction, scanned_at in rows:
        try:
            dt = datetime.datetime.fromisoformat(scanned_at)
            week_key = f'{dt.isocalendar()[0]}-W{dt.isocalendar()[1]:02d}'
        except Exception:
            continue
        weekly.setdefault(week_key, 0)
        weekly[week_key] += 1
    weekly_series = [{'week': k, 'scans': v} for k, v in sorted(weekly.items())][-12:]

    detection_accuracy = None
    metrics_path = os.path.join(ML_DIR, 'model_metrics.json')
    if os.path.exists(metrics_path):
        import json
        with open(metrics_path) as f:
            metrics = json.load(f)
        best_model_name = metrics.get('best_model')
        for entry in metrics.get('results', []):
            if entry.get('model') == best_model_name:
                detection_accuracy = entry.get('accuracy')
                break
        if detection_accuracy is None and metrics.get('results'):
            detection_accuracy = metrics['results'][0].get('accuracy')

    return jsonify({
        'daily_scans': daily_series,
        'weekly_scans': weekly_series,
        'detection_accuracy': detection_accuracy,
        'threat_distribution': {'safe': safe_count, 'suspicious': suspicious_count, 'phishing': phishing_count},
        'safe_vs_phishing_ratio': round(safe_count / phishing_count, 2) if phishing_count else None,
        'total_scans': total,
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
    print("[INFO] Starting PhishShield API on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=True)
