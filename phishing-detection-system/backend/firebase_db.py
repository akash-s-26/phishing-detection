import os
import json
import logging
import datetime
from typing import Optional, Tuple, Dict, Any, List

_db = None
_firebase_initialized = False

def init_firebase():
    global _db, _firebase_initialized
    if _firebase_initialized:
        return _db, True

    try:
        import firebase_admin
        from firebase_admin import credentials, firestore

        cred = None
        service_account_json = os.environ.get('FIREBASE_SERVICE_ACCOUNT_JSON')
        credentials_path = os.environ.get('FIREBASE_CREDENTIALS_PATH', os.path.join(os.path.dirname(__file__), 'firebase-service-account.json'))

        if service_account_json:
            try:
                cred_dict = json.loads(service_account_json)
                cred = credentials.Certificate(cred_dict)
                logging.info("[FIREBASE] Initializing Firebase Admin SDK from environment JSON...")
            except Exception as e:
                logging.error(f"[FIREBASE] Failed to parse FIREBASE_SERVICE_ACCOUNT_JSON: {e}")

        if not cred and os.path.exists(credentials_path):
            try:
                cred = credentials.Certificate(credentials_path)
                logging.info(f"[FIREBASE] Initializing Firebase Admin SDK from file: {credentials_path}...")
            except Exception as e:
                logging.error(f"[FIREBASE] Failed to load credentials from {credentials_path}: {e}")

        if cred:
            if not firebase_admin._apps:
                firebase_admin.initialize_app(cred)
            _db = firestore.client()
            _firebase_initialized = True
            logging.info("✓ [FIREBASE] Firebase Cloud Firestore successfully initialized and connected!")
            return _db, True
        else:
            logging.info("[FIREBASE] No service account key provided. Firebase operates in dual-mode alongside SQLite.")
            return None, False

    except ImportError:
        logging.warning("[FIREBASE] firebase_admin package not installed. Operating with SQLite persistence.")
        return None, False
    except Exception as e:
        logging.error(f"[FIREBASE] Error initializing Firebase Admin SDK: {e}")
        return None, False

def save_scan_firebase(scan_data: Dict[str, Any]) -> bool:
    db, active = init_firebase()
    if not active or db is None:
        return False
    try:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        doc_data = {
            'url': scan_data.get('url', ''),
            'domain': scan_data.get('domain', ''),
            'prediction': scan_data.get('prediction', 'SAFE'),
            'risk_score': float(scan_data.get('risk_score', 0)),
            'confidence': float(scan_data.get('confidence', 99.0)),
            'reason': scan_data.get('reason', ''),
            'model_prediction': scan_data.get('model_prediction', 'DL-CNN-BiLSTM'),
            'source': scan_data.get('source', 'Chrome Extension'),
            'user_id': scan_data.get('user_id'),
            'scanned_at': scan_data.get('scanned_at', now_iso),
            'timestamp': firestore_timestamp()
        }
        db.collection('scan_history').add(doc_data)
        logging.info(f"✓ [FIREBASE] Saved scan for {doc_data['url']} to Cloud Firestore 'scan_history' collection.")
        return True
    except Exception as e:
        logging.error(f"[FIREBASE] Failed to save scan to Firestore: {e}")
        return False

def fetch_history_firebase(limit: int = 50, result_filter: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
    db, active = init_firebase()
    if not active or db is None:
        return []
    try:
        query = db.collection('scan_history').order_by('scanned_at', direction=firestore_descending()).limit(limit)
        docs = query.stream()
        results = []
        for doc in docs:
            d = doc.to_dict()
            d['id'] = doc.id
            pred = str(d.get('prediction', '')).lower()

            if result_filter and result_filter.lower() != 'all' and pred != result_filter.lower():
                continue
            if search and (search.lower() not in d.get('url', '').lower() and search.lower() not in d.get('domain', '').lower()):
                continue

            results.append(d)
        return results
    except Exception as e:
        logging.error(f"[FIREBASE] Error querying scan_history from Firestore: {e}")
        return []

def firestore_timestamp():
    try:
        from firebase_admin import firestore
        return firestore.SERVER_TIMESTAMP
    except Exception:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

def firestore_descending():
    try:
        from firebase_admin import firestore
        return firestore.Query.DESCENDING
    except Exception:
        return 'DESCENDING'
