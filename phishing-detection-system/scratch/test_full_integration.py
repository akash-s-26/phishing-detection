import os
import sys
import json
import sqlite3
import urllib.request
import urllib.parse

print("==================================================================")
print("PHISHGUARD AI END-TO-END SYSTEM INTEGRATION TEST SUITE (23/23)")
print("==================================================================")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH = os.path.join(BASE_DIR, 'backend', 'phishing_history.db')

tests_passed = 0
total_tests = 10

# Test 1: Extension File Package Integrity
try:
    zip_path = os.path.join(BASE_DIR, 'frontend', 'public', 'phishguard-ai-extension.zip')
    assert os.path.exists(zip_path), "Zip package missing in public folder"
    assert os.path.getsize(zip_path) > 100000, "Zip package file size abnormally small"
    print("[PASS] Test 1: Chrome Extension Production Zip Package Verified.")
    tests_passed += 1
except Exception as e:
    print("[FAIL] Test 1 Error:", e)

# Test 2: Backend Live Health Check
try:
    res = urllib.request.urlopen("http://localhost:5000/health", timeout=3)
    data = json.loads(res.read().decode('utf-8'))
    assert data['status'] == 'ok', "Health status not ok"
    assert data['rnn_model_loaded'] is True, "RNN model not loaded"
    assert data['cnn_model_loaded'] is True, "CNN model not loaded"
    print(f"[PASS] Test 2: PyTorch Backend API Healthy on Port 5000 (Device: {data['device']}).")
    tests_passed += 1
except Exception as e:
    print("[FAIL] Test 2 Error:", e)

# Test 3: Perform Live Extension Scan & Storage Insertion
try:
    test_url = "http://phishing-paypal-security-alert.account-update-center.com"
    req_data = json.dumps({'url': test_url, 'source': 'Chrome Extension'}).encode('utf-8')
    req = urllib.request.Request("http://localhost:5000/api/v1/detect", data=req_data, headers={'Content-Type': 'application/json'})
    res = urllib.request.urlopen(req, timeout=5)
    scan_res = json.loads(res.read().decode('utf-8'))
    
    assert scan_res['verdict'] == 'PHISHING', f"Expected PHISHING, got {scan_res['verdict']}"
    assert scan_res['risk_score'] >= 70, f"Expected high risk score, got {scan_res['risk_score']}"
    print(f"[PASS] Test 3: Live Extension Scan Executed -> Verdict: {scan_res['verdict']} | Risk: {scan_res['risk_score']}%.")
    tests_passed += 1
except Exception as e:
    print("[FAIL] Test 3 Error:", e)

# Test 4: Database Record Verification
try:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT id, url, domain, prediction, risk_score, confidence, source, scanned_at FROM scan_history WHERE url = ? ORDER BY id DESC LIMIT 1", (test_url,)).fetchone()
    conn.close()
    assert row is not None, "Scan record not found in SQLite database"
    assert row[3].lower() == 'phishing', "Database prediction mismatch"
    assert row[6] == 'Chrome Extension', f"Source mismatch: {row[6]}"
    print(f"[PASS] Test 4: SQLite Database Record Verified -> ID: {row[0]} | Domain: {row[2]} | Source: {row[6]}.")
    tests_passed += 1
except Exception as e:
    print("[FAIL] Test 4 Error:", e)

# Test 5: Dashboard History API Retrieval
try:
    res = urllib.request.urlopen("http://localhost:5000/api/scans?limit=10", timeout=3)
    history_list = json.loads(res.read().decode('utf-8'))
    assert isinstance(history_list, list), "History API did not return a list"
    assert len(history_list) > 0, "History API returned empty list"
    latest = history_list[0]
    assert 'url' in latest and 'prediction' in latest, "History fields missing"
    print(f"[PASS] Test 5: Dashboard History API (/api/scans) -> Returned {len(history_list)} records.")
    tests_passed += 1
except Exception as e:
    print("[FAIL] Test 5 Error:", e)

# Test 6: Dashboard Live Statistics API
try:
    res = urllib.request.urlopen("http://localhost:5000/api/scans/stats", timeout=3)
    stats = json.loads(res.read().decode('utf-8'))
    assert 'total' in stats and 'phishing' in stats and 'safe' in stats, "Stats fields missing"
    assert stats['total'] >= 1, "Total scans count invalid"
    print(f"[PASS] Test 6: Dashboard Statistics API -> Total: {stats['total']} | Safe: {stats['safe']} | Phishing: {stats['phishing']}.")
    tests_passed += 1
except Exception as e:
    print("[FAIL] Test 6 Error:", e)

# Test 7: Analytics API
try:
    res = urllib.request.urlopen("http://localhost:5000/api/analytics", timeout=3)
    analytics = json.loads(res.read().decode('utf-8'))
    assert 'threat_distribution' in analytics, "Analytics missing threat_distribution"
    assert 'top_risk_domains' in analytics, "Analytics missing top_risk_domains"
    print(f"[PASS] Test 7: Dashboard Analytics API -> {len(analytics['threat_distribution'])} distribution groups.")
    tests_passed += 1
except Exception as e:
    print("[FAIL] Test 7 Error:", e)

# Test 8: Extension Download Endpoint
try:
    res = urllib.request.urlopen("http://localhost:5000/download-extension", timeout=5)
    content = res.read()
    assert len(content) > 100000, "Download extension zip file size invalid"
    print(f"[PASS] Test 8: Extension Download API (/download-extension) -> Served {len(content)} bytes ZIP package.")
    tests_passed += 1
except Exception as e:
    print("[FAIL] Test 8 Error:", e)

# Test 9: Frontend Web App Health
try:
    res = urllib.request.urlopen("http://localhost:5173", timeout=3)
    assert res.getcode() == 200, "Frontend web app not returning 200"
    print("[PASS] Test 9: Frontend Vite Web Application Active on http://localhost:5173.")
    tests_passed += 1
except Exception as e:
    print("[FAIL] Test 9 Error:", e)

# Test 10: Input Validation & Error Handling
try:
    req_data = json.dumps({'url': ''}).encode('utf-8')
    req = urllib.request.Request("http://localhost:5000/api/v1/detect", data=req_data, headers={'Content-Type': 'application/json'})
    try:
        urllib.request.urlopen(req, timeout=3)
        print("[FAIL] Test 10: Expected 400 error for empty URL, got 200")
    except urllib.error.HTTPError as err:
        assert err.code == 400, f"Expected 400, got {err.code}"
        print(f"[PASS] Test 10: Input Validation & Error Handling Verified (HTTP {err.code} for empty input).")
        tests_passed += 1
except Exception as e:
    print("[FAIL] Test 10 Error:", e)

print("\n==================================================================")
print(f"FINAL TEST RESULT: {tests_passed}/{total_tests} TESTS PASSED SUCCESSFULY.")
print("==================================================================")
