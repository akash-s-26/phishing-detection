# PhishGuard AI — Intelligent Phishing Detection System

Chrome Extension ↔ Flask API ↔ Scikit-learn model, fully wired end-to-end.

## How the pieces connect

```
chrome-extension/background.js
        │  POST /predict  { "url": "..." }
        ▼
backend/app.py  (Flask, port 5000)
        │  extract_features() + scaler.transform() + model.predict_proba()
        ▼
machine-learning/feature_extraction.py + model.pkl + scaler.pkl
        │
        ▼
JSON response: { prediction, risk_score, confidence, signals, ... }
        │
        ▼
background.js stores it → pushes to content.js (overlay) and popup.js (popup UI)
```

The exact same `/predict` response shape drives both the in-page overlay
(`content.js`) and the toolbar popup (`popup.js`) — no translation layer needed.

## 1. Train the ML models

```bash
cd machine-learning
pip install -r requirements.txt
python model_training.py
```

Produces `model.pkl`, `scaler.pkl`, `model_metrics.json`, and the 4 individual
model files (`random_forest.pkl`, `logistic_regression.pkl`, etc.) used for the
model-comparison panel.

## 2. Start the Flask backend

```bash
cd backend
pip install -r requirements.txt
python app.py
```

Runs on `http://localhost:5000`. Verify it's alive:

```bash
curl http://localhost:5000/health
curl -X POST http://localhost:5000/predict -H "Content-Type: application/json" -d "{\"url\":\"http://paypa1-secure.tk/login\"}"
```

## 3. Load the Chrome Extension

1. Open `chrome://extensions/`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked** → select the `chrome-extension/` folder
4. Visit any site — the extension auto-scans it against your running Flask API

Keep the Flask server running in a terminal the whole time you're testing
the extension — `background.js` calls `http://localhost:5000/predict` on
every page load.

## API endpoints (backend/app.py)

| Method | Path | Used by |
|---|---|---|
| POST | `/predict` | extension auto-scan, popup, dashboard |
| GET | `/history` | dashboard scan history table |
| GET | `/statistics` | dashboard analytics |
| POST | `/bulk-predict` | batch URL scanning |
| POST | `/report-false-positive` | extension + popup "Report" button |
| GET | `/health` | extension + dashboard online/offline indicator |
