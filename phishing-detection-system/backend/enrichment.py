"""
backend/enrichment.py
Real-world signal gathering to back the fields the frontend expects:
SSL status, domain age (via WHOIS), redirect count, blacklist status,
and a rule-based natural-language explanation of the verdict.

Every check degrades gracefully — if a network lookup fails or times out,
we return a clearly-marked 'unknown' value instead of throwing, since a
single slow WHOIS/DNS lookup should never take the whole /predict call down.
"""

import ssl
import socket
import datetime
import urllib.parse

import requests

try:
    import whois as whois_lib
except ImportError:
    whois_lib = None

REQUEST_TIMEOUT = 4
KNOWN_BLACKLISTED_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq'}


def _hostname(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return urllib.parse.urlparse(url).hostname or ''


def check_ssl(url: str) -> dict:
    """Attempt a real TLS handshake against the host on port 443."""
    host = _hostname(url)
    if not host:
        return {'valid': False, 'detail': 'unknown'}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter')
                return {'valid': True, 'expires': not_after}
    except Exception as e:
        return {'valid': False, 'detail': str(e)[:120]}


def check_domain_age(url: str) -> dict:
    """WHOIS lookup for creation date. Returns human string + raw days."""
    host = _hostname(url)
    if not host or whois_lib is None:
        return {'label': 'Unknown', 'days': None}
    try:
        w = whois_lib.whois(host)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return {'label': 'Unknown', 'days': None}
        if isinstance(created, str):
            return {'label': 'Unknown', 'days': None}
        days = (datetime.datetime.utcnow() - created.replace(tzinfo=None)).days
        if days < 30:
            label = f'{days} days'
        elif days < 365:
            label = f'{days // 30} months'
        else:
            label = f'{days // 365} years'
        return {'label': label, 'days': days}
    except Exception:
        return {'label': 'Unknown', 'days': None}


def check_whois_info(url: str) -> dict:
    host = _hostname(url)
    if not host or whois_lib is None:
        return {'registrar': 'Unknown', 'country': 'Unknown'}
    try:
        w = whois_lib.whois(host)
        registrar = w.registrar or 'Unknown'
        country = w.country or 'Unknown'
        return {'registrar': str(registrar), 'country': str(country)}
    except Exception:
        return {'registrar': 'Unknown', 'country': 'Unknown'}


def check_redirects(url: str) -> dict:
    """Follows the redirect chain and returns the hop count + final URL."""
    full_url = url if url.startswith(('http://', 'https://')) else 'http://' + url
    try:
        resp = requests.get(
            full_url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
            headers={'User-Agent': 'PhishShield-Scanner/1.0'}
        )
        return {'count': len(resp.history), 'final_url': resp.url}
    except Exception:
        return {'count': 0, 'final_url': full_url}


def check_blacklist(url: str, features: dict) -> bool:
    """
    Lightweight heuristic blacklist check (no paid threat-intel API key configured).
    Flags a domain as blacklisted when multiple independent high-risk signals stack up.
    Swap this out for a Google Safe Browsing / VirusTotal API call if you have a key.
    """
    host = _hostname(url).lower()
    if any(host.endswith(tld) for tld in KNOWN_BLACKLISTED_TLDS):
        return True
    risk_hits = sum([
        bool(features.get('has_ip_address')),
        bool(features.get('has_at_symbol')),
        features.get('brand_keyword_count', 0) >= 2,
        bool(features.get('suspicious_tld')),
    ])
    return risk_hits >= 3


def build_explanation(prediction: str, risk_score: float, signals: list,
                       domain_age: dict, ssl_info: dict, redirects: dict,
                       blacklisted: bool) -> str:
    """Rule-based natural-language explanation stitched from the strongest signals."""
    reasons = []

    if blacklisted:
        reasons.append('the domain matches known blacklist patterns')
    if not ssl_info.get('valid'):
        reasons.append('the connection is not secured with a valid SSL certificate')
    if domain_age.get('days') is not None and domain_age['days'] < 180:
        reasons.append(f"the domain was registered recently ({domain_age['label']} ago)")
    if redirects.get('count', 0) >= 2:
        reasons.append(f"the URL passes through {redirects['count']} redirects before landing")

    high_severity = [s['signal'].lower() for s in signals if s.get('severity') in ('high', 'critical')]
    reasons.extend(high_severity[:2])

    if prediction == 'safe' and not reasons:
        return 'No significant phishing indicators were found — the URL, certificate, and domain history all look consistent with a legitimate site.'
    if not reasons:
        reasons.append(f'the model assigned a risk score of {risk_score}% based on structural URL features')

    verdict_word = {'phishing': 'Classified as phishing', 'suspicious': 'Flagged as suspicious', 'safe': 'Classified as safe'}
    prefix = verdict_word.get(prediction, 'Classified')
    return f"{prefix} because {', and '.join(reasons)}."


def enrich(url: str, features: dict, signals: list, prediction: str, risk_score: float) -> dict:
    """Run all enrichment checks and assemble the extra fields the frontend needs."""
    ssl_info = check_ssl(url)
    domain_age = check_domain_age(url)
    whois_info = check_whois_info(url)
    redirects = check_redirects(url)
    blacklisted = check_blacklist(url, features)
    reason = build_explanation(prediction, risk_score, signals, domain_age, ssl_info, redirects, blacklisted)

    return {
        'ssl': ssl_info.get('valid', False),
        'ssl_detail': ssl_info,
        'domain_age': domain_age.get('label', 'Unknown'),
        'redirects': redirects.get('count', 0),
        'blacklisted': blacklisted,
        'whois': whois_info,
        'reason': reason,
    }
