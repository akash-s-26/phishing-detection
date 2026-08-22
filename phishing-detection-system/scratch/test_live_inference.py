"""
scratch/test_live_inference.py
Runs live end-to-end Deep Learning inference tests across multiple URL categories
and prints formatted diagnostic test outputs matching prompt requirement #26.
"""

import os
import sys
import json
import time

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(base_dir, 'backend'))

import app

def run_test(url: str, label: str):
    scan_id = f"test_scan_{int(time.time()*1000)}_{os.urandom(3).hex()}"
    res = app.dl_predict(url, scan_id=scan_id)
    m = res.get('model', {})

    print("=" * 50)
    print("PHISHGUARD AI LIVE DEEP LEARNING TEST")
    print("=" * 50)
    print(f"Category: {label}")
    print(f"URL: {res['url']}")
    print(f"Scan ID: {res['scan_id']}")
    print(f"Cache: {res.get('cache', 'DISABLED')}")
    print(f"Trusted Domain Bypass: {res.get('trusted_domain_bypass', 'DISABLED')}")
    print(f"RNN Executed: {'YES' if m.get('rnn_executed') else 'NO'}")
    print(f"1D CNN Executed: {'YES' if m.get('cnn_executed') else 'NO'}")
    print(f"GAN Component Executed: {'YES' if m.get('gan_executed') else 'NO'}")
    print(f"Model Version: {m.get('version', 'RNN-GAN-DL-v2.0')}")
    print(f"Inference Time: {res['inference_time_ms']} ms")
    print(f"RNN Probability: {m.get('rnn_probability', 0.0)}")
    print(f"CNN Probability: {m.get('cnn_probability', 0.0)}")
    print(f"Phishing Probability: {m.get('ensemble_probability', 0.0)}")
    print(f"Confidence: {res['confidence']}%")
    print(f"Risk Score: {res['risk_score']}/100")
    print(f"Verdict: {res['verdict']}")
    print("=" * 50 + "\n")
    return res

if __name__ == '__main__':
    tests = [
        ('https://google.com', 'Legitimate Homepage'),
        ('https://www.overleaf.com/project/6a7e97b1a40d282da2c755e6', 'Overleaf Project URL (NO Whitelist)'),
        ('https://github.com/torvalds/linux/commit/e3be4737de25272a2444d', 'GitHub Commit URL (NO Whitelist)'),
        ('http://paypa1-verify-account.tk/login', 'Phishing Target 1'),
        ('http://appleid-apple.com.login-verify.xyz/signin', 'Phishing Target 2')
    ]

    for url, label in tests:
        run_test(url, label)
