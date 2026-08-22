"""
scratch/test_normalization.py
Diagnoses Deep Learning feature extraction, normalization, and sequence predictions.
"""

import os
import sys
import numpy as np
import pandas as pd
import torch

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(base_dir, 'training'))
sys.path.insert(0, os.path.join(base_dir, 'machine-learning'))

from feature_extraction import extract_features

def normalize_features_15(f: dict) -> list:
    return [
        min(float(f.get('url_length', 0)) / 200.0, 1.0),
        float(f.get('has_https', 0)),
        min(float(f.get('num_subdomains', 0)) / 5.0, 1.0),
        float(f.get('has_ip_address', 0)),
        min(float(f.get('num_special_chars', 0)) / 20.0, 1.0),
        float(f.get('has_at_symbol', 0)),
        float(f.get('has_double_slash', 0)),
        min(float(f.get('num_dots', 0)) / 10.0, 1.0),
        min(float(f.get('url_depth', 0)) / 10.0, 1.0),
        float(f.get('suspicious_tld', 0)),
        min(float(f.get('domain_length', 0)) / 50.0, 1.0),
        float(f.get('has_hyphen_domain', 0)),
        min(float(f.get('brand_keyword_count', 0)) / 5.0, 1.0),
        float(f.get('digit_ratio_domain', 0.0)),
        min(float(f.get('num_query_params', 0)) / 10.0, 1.0)
    ]

if __name__ == '__main__':
    test_urls = [
        'https://google.com',
        'https://www.overleaf.com/project/6a7e97b1a40d282da2c755e6',
        'https://github.com/torvalds/linux/commit/e3be4737de25272a2444d',
        'https://wikipedia.org/wiki/Deep_learning',
        'http://paypa1-verify-account.tk/login',
        'http://appleid-apple.com.login-verify.xyz/signin',
        'http://192.168.1.1/admin/login.php'
    ]

    for url in test_urls:
        feats = extract_features(url)
        vec = normalize_features_15(feats)
        print(f"URL: {url}")
        print(f"  Length: {feats['url_length']} | Has HTTPS: {feats['has_https']} | Suspicious TLD: {feats['suspicious_tld']}")
        print(f"  Normalized Vector (15 cols): {vec}\n")
