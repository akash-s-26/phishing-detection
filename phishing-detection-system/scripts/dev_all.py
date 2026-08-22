import os
import sys
import time
import subprocess
import urllib.request

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
VENV_PYTHON = os.path.join(BASE_DIR, '..', '.venv', 'Scripts', 'python.exe')
if not os.path.exists(VENV_PYTHON):
    VENV_PYTHON = sys.executable

BACKEND_SCRIPT = os.path.join(BASE_DIR, 'backend', 'app.py')
FRONTEND_DIR = os.path.join(BASE_DIR, 'frontend')

processes = []

def start_backend():
    print("[SERVICE] Starting PyTorch Flask Backend API on http://localhost:5000...")
    p = subprocess.Popen([VENV_PYTHON, BACKEND_SCRIPT], cwd=BASE_DIR)
    processes.append(p)
    return p

def start_frontend():
    print("[SERVICE] Starting Vite React Frontend Dev Server on http://localhost:5173...")
    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    p = subprocess.Popen([npm_cmd, "run", "dev"], cwd=FRONTEND_DIR)
    processes.append(p)
    return p

def print_status_banner():
    time.sleep(3)
    print("\n" + "=" * 60)
    print("PHISHGUARD AI COMPLETE SERVER STATUS")
    print("=" * 60)
    print("  Frontend (Netlify)  : https://phishing-detection-ai.netlify.app/")
    print("  Frontend (Local)    : http://localhost:5173")
    print("  Backend API         : http://localhost:5000")
    print("  ML Engine           : 100% Pure PyTorch BiLSTM + 1D-CNN")
    print("  Database            : Persistent SQLite Storage (phishing_history.db)")
    print("  Health Check        : http://localhost:5000/health")
    print("  Chrome Extension    : Manifest V3 v2.0.0 (Unpacked)")
    print("=" * 60 + "\n")

    while True:
        time.sleep(5)
        try:
            res = urllib.request.urlopen("http://localhost:5000/health", timeout=2)
            if res.getcode() != 200:
                print("[WARNING] Backend health check returned status code:", res.getcode())
        except Exception as e:
            print("[ALERT] Backend health check failed:", e)

if __name__ == "__main__":
    try:
        start_backend()
        start_frontend()
        print_status_banner()
    except KeyboardInterrupt:
        print("\n[STOPPING] Terminating PhishGuard AI services...")
        for p in processes:
            try:
                p.terminate()
            except Exception:
                pass
        sys.exit(0)
