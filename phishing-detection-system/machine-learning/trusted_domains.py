"""
machine-learning/trusted_domains.py

Structural URL features (length, special-char count, dot count, query-param
count) are exactly what legitimate OAuth/SSO login flows look like — Google,
Microsoft, and similar providers regularly produce 500-2000 character login
URLs packed with encoded redirect targets and state tokens. Judged purely on
those features, a real accounts.google.com sign-in URL can score as "high
risk" even though the domain itself is completely genuine.

Real anti-phishing tools solve this with a small, hand-curated allowlist of
domains that are effectively impossible to spoof (protected by browser HSTS
preload lists, widely-known-brand legal protections, etc.) — a match there
short-circuits the ML verdict to 'safe' regardless of how the URL looks
structurally. This is intentionally a short, conservative list: it exists to
suppress false positives on the handful of domains people hit constantly
(Google/Microsoft/Apple sign-in, GitHub, etc.), not to whitelist "big tech"
broadly.
"""

import re

TRUSTED_ROOT_DOMAINS = {
    'google.com', 'accounts.google.com', 'googleusercontent.com',
    'microsoft.com', 'live.com', 'microsoftonline.com', 'office.com',
    'apple.com', 'icloud.com',
    'github.com', 'githubusercontent.com',
    'amazon.com', 'paypal.com',
    'facebook.com', 'fb.com',
    'yahoo.com',
}


def get_registrable_domain(hostname: str) -> str:
    """Best-effort eTLD+1 extraction (last two labels), good enough for this allowlist."""
    parts = hostname.lower().split('.')
    if len(parts) < 2:
        return hostname.lower()
    return '.'.join(parts[-2:])


def is_trusted_domain(url: str) -> bool:
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    match = re.match(r'https?://([^/]+)', url)
    if not match:
        return False
    hostname = match.group(1).split(':')[0].split('@')[-1]
    root = get_registrable_domain(hostname)
    return hostname.lower() in TRUSTED_ROOT_DOMAINS or root in TRUSTED_ROOT_DOMAINS
