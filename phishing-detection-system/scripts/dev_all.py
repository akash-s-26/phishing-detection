import os
import sys
import time
import subprocess
import threading
import urllib.request

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
VENV_PYTHON = os.path.join(BASE_DIR, '..', '.venv', 'Scripts', 'python.exe')
if not os.path.exists(VENV_PYTHON):
    VENV_PYTHON = sys.executable

BACKEND_SCRIPT = os.path.join(BASE_DIR, 'backend', 'app.py')
FRONTEND_DIR = os.path.join(BASE_DIR, 'frontend')

processes = []

def start_backend():
    print("[SERVICE] Starting PyTorch Flask Backend on http://localhost:5000...")
    p = subprocess.Popen([VENV_PYTHON, BACKEND_SCRIPT], cwd=BASE_DIR)
    processes.append(p)
    return p

def start_frontend():
    print("[SERVICE] Starting Vite React Frontend on http://localhost:5173...")
    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    p = subprocess.Popen([npm_cmd, "run", "dev"], cwd=FRONTEND_DIR)
    processes.append(p)
    return p

def monitor_services():
    time.sleep(3)
    print("\n" + "=" * 60)
    print("PHISHGUARD AI COMPLETE DEEP LEARNING SYSTEM RUNNING")
    print("=" * 60)
    print("  [FRONTEND]   http://localhost:5173  (Dashboard & Web UI)")
    print("  [BACKEND]    http://localhost:5000  (PyTorch Inference API)")
    print("  [HEALTH]     http://localhost:5000/health  (Health Check)")
    print("  [EXTENSION]  v2.0.0 (Unpacked in chrome-extension/)")
    print("  [DATABASE]   SQLite Persistent History active")
    print("=" * 60 + "\n")

    while True:
        time.sleep(5)
        # Check backend health
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
        monitor_services()
    except KeyboardInterrupt:
        print("\n[STOPPING] Terminating all PhishGuard AI services...")
        for p in processes:
            try:
                p.terminate()
            except Exception:
                pass
        sys.exit(0)
