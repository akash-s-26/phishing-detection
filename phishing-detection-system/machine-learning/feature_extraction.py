"""
machine-learning/feature_extraction.py
Extracts 15 URL features for phishing detection + human-readable signals.
"""

import re
import urllib.parse

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.info',
    '.top', '.club', '.online', '.site', '.live', '.stream', '.download'
}

BRAND_KEYWORDS = [
    'paypal', 'amazon', 'google', 'facebook', 'apple', 'microsoft',
    'netflix', 'ebay', 'bank', 'secure', 'login', 'verify',
    'account', 'update', 'confirm', 'password', 'billing'
]

FEATURE_COLS = [
    'url_length', 'has_https', 'num_subdomains', 'has_ip_address',
    'num_special_chars', 'has_at_symbol', 'has_double_slash',
    'num_dots', 'url_depth', 'suspicious_tld', 'domain_length'
]


def extract_features(url: str) -> dict:
    """Extract a dict of 15 numeric/binary features from a raw URL string."""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        p = urllib.parse.urlparse(url)
    except Exception:
        return _defaults()

    domain = p.netloc or ''
    path = p.path or ''
    query = p.query or ''
    parts = domain.split('.')
    tld = '.' + parts[-1].lower() if parts else ''
    url_lc = url.lower()

    return {
        'url_length': len(url),
        'has_https': 1 if p.scheme == 'https' else 0,
        'num_subdomains': max(0, len(parts) - 2),
        'has_ip_address': 1 if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain) else 0,
        'num_special_chars': len(re.findall(r'[@!$%^&*()\[\]{}|;:\'",<>?]', url)),
        'has_at_symbol': 1 if '@' in url else 0,
        'has_double_slash': 1 if '//' in path else 0,
        'num_dots': url.count('.'),
        'url_depth': len([x for x in path.split('/') if x]),
        'suspicious_tld': 1 if tld in SUSPICIOUS_TLDS else 0,
        'domain_length': len(domain.replace('www.', '')),
        'has_hyphen_domain': 1 if '-' in domain else 0,
        'brand_keyword_count': sum(1 for kw in BRAND_KEYWORDS if kw in url_lc),
        'digit_ratio_domain': round(
            sum(c.isdigit() for c in domain) / len(domain) if domain else 0, 3
        ),
        'num_query_params': len(urllib.parse.parse_qs(query)),
    }


def features_to_vector(f: dict) -> list:
    """Order features exactly as the model was trained on."""
    return [f.get(k, 0) for k in FEATURE_COLS]


def get_detection_signals(f: dict) -> list:
    """
    Turn raw features into human-readable signals for the UI
    (dashboard + Chrome extension both consume this same shape).
    """
    signals = []

    if not f.get('has_https'):
        signals.append({
            'signal': 'No HTTPS',
            'severity': 'high',
            'description': 'Connection is not encrypted — data can be intercepted.'
        })
    if f.get('has_ip_address'):
        signals.append({
            'signal': 'IP Address as Domain',
            'severity': 'critical',
            'description': 'URL uses a raw IP address instead of a domain name.'
        })
    if f.get('suspicious_tld'):
        signals.append({
            'signal': 'Suspicious TLD',
            'severity': 'high',
            'description': 'Domain uses a TLD (.tk/.ml/.xyz etc.) frequently linked to phishing.'
        })
    if f.get('has_at_symbol'):
        signals.append({
            'signal': '@ Symbol Detected',
            'severity': 'critical',
            'description': 'The @ symbol can redirect the browser to a hidden destination.'
        })
    if f.get('has_double_slash'):
        signals.append({
            'signal': 'Redirection Detected',
            'severity': 'high',
            'description': 'Double slash in the path suggests a URL redirection trick.'
        })
    if f.get('url_length', 0) > 75:
        signals.append({
            'signal': 'Excessively Long URL',
            'severity': 'medium',
            'description': f'URL is {f["url_length"]} characters — unusually long URLs can hide malicious content.'
        })
    if f.get('num_subdomains', 0) > 2:
        signals.append({
            'signal': 'Multiple Subdomains',
            'severity': 'medium',
            'description': f'{f["num_subdomains"]} subdomains detected — a common brand-impersonation trick.'
        })
    if f.get('has_hyphen_domain'):
        signals.append({
            'signal': 'Hyphenated Domain',
            'severity': 'low',
            'description': 'Hyphens in the domain are commonly used to mimic real brand names.'
        })
    if f.get('brand_keyword_count', 0) >= 2:
        signals.append({
            'signal': 'Brand Impersonation Keywords',
            'severity': 'high',
            'description': f'{f["brand_keyword_count"]} brand/security keywords found in the URL.'
        })
    if f.get('digit_ratio_domain', 0) > 0.3:
        signals.append({
            'signal': 'High Digit Ratio in Domain',
            'severity': 'medium',
            'description': 'Domain has an unusually high proportion of digits.'
        })

    if not signals:
        signals.append({
            'signal': 'No Suspicious Signals',
            'severity': 'safe',
            'description': 'No known phishing indicators were detected in this URL.'
        })

    return signals


def _defaults() -> dict:
    return {
        'url_length': 100, 'has_https': 0, 'num_subdomains': 3,
        'has_ip_address': 1, 'suspicious_tld': 1, 'has_at_symbol': 1,
        'has_double_slash': 1, 'num_dots': 5, 'url_depth': 4,
        'num_special_chars': 5, 'domain_length': 30, 'has_hyphen_domain': 1,
        'brand_keyword_count': 3, 'digit_ratio_domain': 0.5, 'num_query_params': 3
    }


if __name__ == '__main__':
    tests = [
        'https://www.google.com',
        'http://paypa1-secure.tk/login',
        'http://192.168.1.1/admin',
    ]
    for url in tests:
        f = extract_features(url)
        print(f"{url[:42]:<42} https={f['has_https']} ip={f['has_ip_address']} tld={f['suspicious_tld']}")
