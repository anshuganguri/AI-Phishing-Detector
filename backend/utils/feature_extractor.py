# utils/feature_extractor.py
# Extracts handcrafted features from URLs for ML classification

import re
import urllib.parse
from urllib.parse import urlparse


# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update',
    'confirm', 'banking', 'password', 'credential', 'alert',
    'suspend', 'unlock', 'recover', 'validate', 'authorize',
    'paypal', 'amazon', 'google', 'facebook', 'apple', 'microsoft',
    'netflix', 'ebay', 'bank', 'credit', 'free', 'winner', 'prize',
    'claim', 'reward', 'urgent', 'immediate', 'click', 'here'
]


def extract_features(url: str) -> dict:
    """
    Extract a rich set of numerical features from a given URL.
    Returns a dictionary of feature_name -> value.
    """
    features = {}

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        path = parsed.path or ''
        full_url = url.lower()

        # ── Basic length features ──────────────────────────────────────
        features['url_length'] = len(url)
        features['hostname_length'] = len(hostname)
        features['path_length'] = len(path)

        # ── Dot / separator counts ─────────────────────────────────────
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_ampersands'] = url.count('&')
        features['num_equals'] = url.count('=')
        features['num_percent'] = url.count('%')

        # ── Special character presence (binary flags) ──────────────────
        features['has_at_symbol'] = int('@' in url)
        features['has_double_slash'] = int('//' in parsed.path)
        features['has_ip_address'] = int(bool(
            re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname)
        ))

        # ── Protocol / HTTPS ───────────────────────────────────────────
        features['is_https'] = int(parsed.scheme == 'https')

        # ── Digit statistics ───────────────────────────────────────────
        digit_count = sum(c.isdigit() for c in url)
        features['digit_count'] = digit_count
        features['digit_ratio'] = digit_count / max(len(url), 1)

        # ── Subdomain analysis ─────────────────────────────────────────
        # Count subdomains (parts in hostname beyond the registered domain)
        hostname_parts = hostname.split('.')
        features['subdomain_count'] = max(len(hostname_parts) - 2, 0)
        features['has_subdomain'] = int(features['subdomain_count'] > 0)

        # ── Suspicious keyword presence ────────────────────────────────
        features['suspicious_keyword_count'] = sum(
            kw in full_url for kw in SUSPICIOUS_KEYWORDS
        )
        features['has_suspicious_keyword'] = int(
            features['suspicious_keyword_count'] > 0
        )

        # ── Typosquatting / obfuscation signals ───────────────────────
        # Common letter-to-digit substitutions: a->4, e->3, i->1, o->0, l->1
        features['has_digit_substitution'] = int(bool(
            re.search(r'(paypa[l1]|g[o0]{2}gle|amaz[o0]n|faceb[o0]{2}k'
                      r'|microso[f]{1,2}t|appl[e3]|netfl[i1]x)', full_url)
        ))

        # ── URL entropy (rough measure of randomness) ──────────────────
        from collections import Counter
        import math
        freq = Counter(url)
        total = len(url)
        entropy = -sum((c / total) * math.log2(c / total) for c in freq.values())
        features['url_entropy'] = round(entropy, 4)

        # ── TLD suspicion ──────────────────────────────────────────────
        suspicious_tlds = {'.xyz', '.info', '.net', '.biz', '.club',
                           '.top', '.online', '.site', '.live', '.pw'}
        tld = '.' + hostname.split('.')[-1] if '.' in hostname else ''
        features['has_suspicious_tld'] = int(tld in suspicious_tlds)

        # ── Query string length ────────────────────────────────────────
        features['query_length'] = len(parsed.query)
        features['num_query_params'] = len(parsed.query.split('&')) if parsed.query else 0

        # ── Token / brand count in hostname ───────────────────────────
        brand_keywords = ['paypal', 'amazon', 'google', 'facebook', 'apple',
                          'microsoft', 'netflix', 'ebay', 'bank', 'secure']
        features['brand_in_hostname'] = int(
            any(brand in hostname.lower() for brand in brand_keywords)
        )
        features['brand_in_path'] = int(
            any(brand in path.lower() for brand in brand_keywords)
        )

    except Exception:
        # Return safe defaults on parse error
        features = {k: 0 for k in _feature_names()}

    return features


def _feature_names() -> list:
    """Return the ordered list of feature names (must match extract_features output)."""
    return [
        'url_length', 'hostname_length', 'path_length',
        'num_dots', 'num_hyphens', 'num_underscores',
        'num_slashes', 'num_question_marks', 'num_ampersands',
        'num_equals', 'num_percent', 'has_at_symbol',
        'has_double_slash', 'has_ip_address', 'is_https',
        'digit_count', 'digit_ratio', 'subdomain_count',
        'has_subdomain', 'suspicious_keyword_count',
        'has_suspicious_keyword', 'has_digit_substitution',
        'url_entropy', 'has_suspicious_tld', 'query_length',
        'num_query_params', 'brand_in_hostname', 'brand_in_path',
    ]


def features_to_list(url: str) -> list:
    """Return features as an ordered list (for numpy/sklearn)."""
    feat_dict = extract_features(url)
    return [feat_dict.get(name, 0) for name in _feature_names()]


def get_feature_names() -> list:
    return _feature_names()
