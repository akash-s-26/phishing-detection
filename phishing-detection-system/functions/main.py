import os
import sys

# Ensure backend modules and PyTorch models are accessible
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(BASE_DIR, '..', 'backend'))
sys.path.insert(0, BACKEND_DIR)

from firebase_functions import https_fn
from firebase_admin import initialize_app, firestore

try:
    initialize_app()
except Exception:
    pass

from app import app as flask_app

@https_fn.on_request(cors=https_fn.CorsOptions(origins=["*"], methods=["GET", "POST", "OPTIONS"]))
def api(req: https_fn.Request) -> https_fn.Response:
    """
    PhishGuard AI — Firebase Cloud Functions Serverless API Entrypoint
    Wraps the PyTorch Deep Learning Flask backend into a high-performance,
    auto-scaling serverless Cloud Function.
    """
    with flask_app.request_context(req.environ):
        return flask_app.full_dispatch_request()
