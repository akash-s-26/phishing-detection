"""
machine-learning/test_suite.py
Executes real-time prediction test suite against the Flask API endpoint
and outputs formatted Markdown table.
"""

import requests
import json

test_urls = [
    ('Legitimate', 'https://google.com'),
    ('Legitimate', 'https://github.com'),
    ('Legitimate', 'https://openai.com'),
    ('Legitimate', 'https://microsoft.com'),
    ('Legitimate', 'https://amazon.in'),
    ('Phishing', 'http://paypa1-login-secure.xyz/verify-account'),
    ('Phishing', 'http://account-verification-support.top/login.php'),
    ('Phishing', 'http://free-gift-card-claim.info/win'),
    ('Phishing', 'http://192.168.1.1/paypal/login')
]

def main():
    print("| Target Category | Tested URL | Verdict | Confidence | Risk Score | Risk Level | Latency |")
    print("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
    for category, url in test_urls:
        try:
            r = requests.post('http://127.0.0.1:5000/predict', json={'url': url}, timeout=10)
            res = r.json()
            pred = res.get('prediction', 'Unknown')
            conf = f"{res.get('confidence', 0)}%"
            score = f"{res.get('risk_score', 0)}%"
            level = res.get('risk_level', 'Unknown')
            time_ms = f"{res.get('inference_time_ms', 0)} ms"
            print(f"| {category} | `{url}` | **{pred}** | {conf} | {score} | {level} | {time_ms} |")
        except Exception as e:
            print(f"| {category} | `{url}` | **Error** | N/A | N/A | N/A | {e} |")

if __name__ == '__main__':
    main()
