"""
machine-learning/trusted_domains.py
Verified Domain Calibration & False-Positive Suppression Allowlist for PhishGuard AI.
"""

import re

TRUSTED_ROOT_DOMAINS = {
    'google.com', 'accounts.google.com', 'firebase.google.com', 'cloud.google.com',
    'firebase.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com',
    'microsoft.com', 'live.com', 'microsoftonline.com', 'office.com', 'azure.com',
    'apple.com', 'icloud.com',
    'github.com', 'github.io', 'githubusercontent.com',
    'netlify.app', 'netlify.com', 'vercel.app', 'render.com', 'railway.app', 'koyeb.app',
    'amazon.com', 'aws.amazon.com', 'paypal.com',
    'facebook.com', 'fb.com', 'instagram.com',
    'yahoo.com',
    'claude.ai', 'anthropic.com',
    'openai.com', 'chatgpt.com', 'ollama.com', 'huggingface.co',
    'stackoverflow.com', 'wikipedia.org',
    'twitter.com', 'x.com', 'linkedin.com', 'youtube.com', 'reddit.com',
    'notion.so', 'notion.site', 'figma.com', 'slack.com', 'discord.com', 'zoom.us'
}

def get_registrable_domain(hostname: str) -> str:
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
    hostname = match.group(1).split(':')[0].split('@')[-1].lower()
    root = get_registrable_domain(hostname)
    
    # Check exact hostname match, root domain match, or subdomain ending match
    if hostname in TRUSTED_ROOT_DOMAINS or root in TRUSTED_ROOT_DOMAINS:
        return True
    return any(hostname.endswith('.' + d) for d in TRUSTED_ROOT_DOMAINS)
