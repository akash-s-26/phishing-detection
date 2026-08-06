"""
machine-learning/feature_extraction.py
Extracts 15 standardized URL features for phishing detection + human-readable signals.
Includes robust URL normalization, IDNA unicode handling, URL shortener detection, and URL validation.
"""

import re
import urllib.parse

SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'tiny.cc', 'cutt.ly', 'rb.gy'
}

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.info',
    '.top', '.club', '.online', '.site', '.live', '.stream', '.download',
    '.work', '.date', '.party', '.racing', '.accountant'
}

BRAND_KEYWORDS = [
    'paypal', 'amazon', 'google', 'facebook', 'apple', 'microsoft',
    'netflix', 'ebay', 'bank', 'secure', 'login', 'verify',
    'account', 'update', 'confirm', 'password', 'billing', 'support',
    'signin', 'security', 'wallet', 'crypto', 'service'
]

FEATURE_COLS = [
    'url_length',
    'has_https',
    'num_subdomains',
    'has_ip_address',
    'num_special_chars',
    'has_at_symbol',
    'has_double_slash',
    'num_dots',
    'url_depth',
    'suspicious_tld',
    'domain_length',
    'has_hyphen_domain',
    'brand_keyword_count',
    'digit_ratio_domain',
    'num_query_params'
]


def normalize_url(raw_url: str) -> str:
    """
    Normalizes input URL:
    - Trims whitespace & quotes
    - Adds http:// scheme if missing
    - Encodes IDN/Unicode domains to punycode (ASCII)
    - Lowercases scheme and hostname
    - Validates URL structure
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("URL must be a non-empty string")

    url = raw_url.strip().strip("'\"`")
    if not url:
        raise ValueError("URL cannot be empty")

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        raise ValueError(f"Invalid URL structure: {e}")

    hostname = parsed.netloc.split(':')[0].split('@')[-1]
    if not hostname:
        raise ValueError("URL contains no valid domain or host")

    # Handle Punycode/IDN Unicode conversion
    try:
        hostname_ascii = hostname.encode('idna').decode('ascii')
    except Exception:
        hostname_ascii = hostname

    scheme = parsed.scheme.lower()
    path = parsed.path
    query = ('?' + parsed.query) if parsed.query else ''
    fragment = ('#' + parsed.fragment) if parsed.fragment else ''

    # Reconstruct normalized URL
    normalized = f"{scheme}://{hostname_ascii.lower()}{path}{query}{fragment}"
    return normalized


def extract_features(url: str) -> dict:
    """
    Extract a dict of 15 numeric/binary features from a raw URL string.
    Ensures safe handling and safe fallback defaults on invalid inputs.
    """
    try:
        norm_url = normalize_url(url)
        p = urllib.parse.urlparse(norm_url)
    except Exception:
        norm_url = url.strip() if isinstance(url, str) else ''
        try:
            p = urllib.parse.urlparse(norm_url if norm_url.startswith(('http://', 'https://')) else 'http://' + norm_url)
        except Exception:
            return _defaults()

    domain = p.netloc or ''
    hostname = domain.split(':')[0].split('@')[-1]
    path = p.path or ''
    query = p.query or ''
    parts = hostname.split('.')
    tld = '.' + parts[-1].lower() if parts else ''
    url_lc = norm_url.lower()

    # Check for IP address (IPv4 or IPv6)
    is_ip = 1 if (
        re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname) or
        re.match(r'^[0-9a-fA-F:]+$', hostname) and ':' in hostname
    ) else 0

    clean_domain = hostname.replace('www.', '')

    return {
        'url_length': len(norm_url),
        'has_https': 1 if p.scheme == 'https' else 0,
        'num_subdomains': max(0, len(parts) - 2),
        'has_ip_address': is_ip,
        'num_special_chars': len(re.findall(r'[@!$%^&*()\[\]{}|;:\'",<>?]', norm_url)),
        'has_at_symbol': 1 if '@' in norm_url else 0,
        'has_double_slash': 1 if '//' in path else 0,
        'num_dots': norm_url.count('.'),
        'url_depth': len([x for x in path.split('/') if x]),
        'suspicious_tld': 1 if (tld in SUSPICIOUS_TLDS or clean_domain in SHORTENER_DOMAINS) else 0,
        'domain_length': len(clean_domain),
        'has_hyphen_domain': 1 if '-' in hostname else 0,
        'brand_keyword_count': sum(1 for kw in BRAND_KEYWORDS if kw in url_lc),
        'digit_ratio_domain': round(
            sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0, 3
        ),
        'num_query_params': len(urllib.parse.parse_qs(query)),
    }


def features_to_vector(f: dict) -> list:
    """Order features exactly as the model was trained on."""
    return [float(f.get(k, 0.0)) for k in FEATURE_COLS]


def get_detection_signals(f: dict) -> list:
    """
    Turn raw features into human-readable signals for the UI.
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
            'description': 'URL uses a raw IP address instead of a registered domain name.'
        })
    if f.get('suspicious_tld'):
        signals.append({
            'signal': 'Suspicious TLD or Shortener',
            'severity': 'high',
            'description': 'Domain uses a TLD or URL shortener frequently associated with phishing.'
        })
    if f.get('has_at_symbol'):
        signals.append({
            'signal': '@ Symbol Detected',
            'severity': 'critical',
            'description': 'The @ symbol can redirect the browser to a hidden destination.'
        })
    if f.get('has_double_slash'):
        signals.append({
            'signal': 'Redirection Trick',
            'severity': 'high',
            'description': 'Double slash in the path suggests a URL redirection pattern.'
        })
    if f.get('url_length', 0) > 120:
        signals.append({
            'signal': 'Excessively Long URL',
            'severity': 'medium',
            'description': f'URL is {f["url_length"]} characters long.'
        })
    if f.get('num_subdomains', 0) >= 2:
        signals.append({
            'signal': 'Multiple Subdomains',
            'severity': 'medium',
            'description': f'{f["num_subdomains"]} subdomains detected — common in brand impersonation.'
        })
    if f.get('has_hyphen_domain'):
        signals.append({
            'signal': 'Hyphenated Domain',
            'severity': 'low',
            'description': 'Hyphens in the domain are frequently used to spoof legitimate brand names.'
        })
    if f.get('brand_keyword_count', 0) >= 1:
        signals.append({
            'signal': 'Brand Keywords Found',
            'severity': 'high',
            'description': f'{f["brand_keyword_count"]} brand/security keywords detected in the URL.'
        })
    if f.get('digit_ratio_domain', 0) > 0.25:
        signals.append({
            'signal': 'High Digit Ratio in Domain',
            'severity': 'medium',
            'description': 'Domain contains an unusually high proportion of numbers.'
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
        'url_length': 20, 'has_https': 1, 'num_subdomains': 0,
        'has_ip_address': 0, 'suspicious_tld': 0, 'has_at_symbol': 0,
        'has_double_slash': 0, 'num_dots': 1, 'url_depth': 0,
        'num_special_chars': 0, 'domain_length': 10, 'has_hyphen_domain': 0,
        'brand_keyword_count': 0, 'digit_ratio_domain': 0.0, 'num_query_params': 0
    }


if __name__ == '__main__':
    tests = [
        'https://google.com',
        'http://paypa1-secure.tk/login/verify?ref=1',
        'http://192.168.1.1/admin',
        'http://xn--pypal-4va.com/login',
    ]
    for test_url in tests:
        norm = normalize_url(test_url)
        feats = extract_features(test_url)
        vec = features_to_vector(feats)
        print(f"URL: {test_url}")
        print(f"  Normalized: {norm}")
        print(f"  Vector ({len(vec)} cols): {vec}\n")
