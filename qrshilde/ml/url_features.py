import re
from urllib.parse import urlparse


KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank", "paypal", "google",
    "microsoft", "apple", "confirm", "password", "signin", "free", "bonus"
]

SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "buff.ly", "cutt.ly"}


def _safe_urlparse(u: str):
    try:
        u2 = u if "://" in u else "http://" + u
        return urlparse(u2)
    except Exception:
        return None


def extract_url_features(u: str):
    """
    Returns: (features_list, feature_names_list)
    Robust against weird/invalid URLs.
    """
    u = (u or "").strip()

    feature_names = [
        "url_len",
        "host_len",
        "path_len",
        "tld_len",
        "digit_count",
        "special_count",
        "at_count",
        "dot_count",
        "dash_count",
        "underscore_count",
        "question_count",
        "equal_count",
        "amp_count",
        "percent_count",
        "ip_like",
        "ratio_digits",
        "has_https",
        "has_shortener",
        "keyword_hits",
    ]

    url_len = len(u)
    host = ""
    path = ""
    tld = ""

    parsed = _safe_urlparse(u)
    if parsed:
        # hostname avoids userinfo/port pollution (netloc can include ":8080" etc.)
        host = (parsed.hostname or "")
        path = parsed.path or ""
        if "." in host:
            tld = host.split(".")[-1]
    else:
        host_guess = u.split("/")[0]
        host = host_guess[:255]
        if "." in host:
            tld = host.split(".")[-1]

    host_len = len(host)
    path_len = len(path)
    tld_len = len(tld)

    digit_count = sum(ch.isdigit() for ch in u)
    special_count = sum((not ch.isalnum()) for ch in u)

    at_count = u.count("@")
    dot_count = u.count(".")
    dash_count = u.count("-")
    underscore_count = u.count("_")
    question_count = u.count("?")
    equal_count = u.count("=")
    amp_count = u.count("&")
    percent_count = u.count("%")

    ip_like = 1 if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", u) or ("[" in u and "]" in u and ":" in u) else 0
    ratio_digits = (digit_count / url_len) if url_len > 0 else 0.0
    has_https = 1 if u.lower().startswith("https://") else 0

    host_lower = host.lower()
    has_shortener = 1 if host_lower in SHORTENERS else 0

    u_lower = u.lower()
    keyword_hits = sum(1 for k in KEYWORDS if k in u_lower)

    features = [
        url_len,
        host_len,
        path_len,
        tld_len,
        digit_count,
        special_count,
        at_count,
        dot_count,
        dash_count,
        underscore_count,
        question_count,
        equal_count,
        amp_count,
        percent_count,
        ip_like,
        ratio_digits,
        has_https,
        has_shortener,
        keyword_hits,
    ]

    return features, feature_names