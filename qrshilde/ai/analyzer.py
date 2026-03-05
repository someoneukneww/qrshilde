import datetime
import os
import re
import socket
import uuid
from urllib.parse import urlparse

from qrshilde.src.tools.malicious_pattern_detector import scan_for_patterns
from qrshilde.src.tools.wifi_auto_connect_detector import detect_wifi_threats
from qrshilde.src.tools.payload_type import detect_payload_type
from qrshilde.src.ml.url_model import predict_url, model_exists
from qrshilde.src.ai.report_generator import build_markdown_report

# -----------------------------
# Config (Rules + ML ONLY)
# -----------------------------
ALLOWLIST_DOMAINS = {
    "google.com",
    "github.com",
    "microsoft.com",
    "paypal.com",
}

RESERVED_DOMAINS = {
    "example.com",
    "example.net",
    "example.org",
    "localhost",
    "127.0.0.1",
}

SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "buff.ly", "cutt.ly",
    "ow.ly", "rebrand.ly", "lnk.bio", "shorturl.at"
}

LURE_WORDS = [
    "login", "verify", "update", "secure", "account", "password", "otp", "bank",
    "confirm", "billing", "invoice", "pay", "wallet", "support"
]


# -----------------------------
# Helpers
# -----------------------------
def _get_domain(url: str) -> str | None:
    try:
        u = (url or "").strip()
        if "://" not in u:
            u = "http://" + u
        parsed = urlparse(u)
        host = (parsed.hostname or "").lower().strip(".")
        if not host:
            return None
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return None


def _domain_in_set(domain: str, s: set[str]) -> bool:
    d = (domain or "").lower().strip(".")
    for base in s:
        b = (base or "").lower().strip(".")
        if d == b or d.endswith("." + b):
            return True
    return False


def _dns_resolves(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False


def _url_is_http(url: str) -> bool:
    u = (url or "").strip().lower()
    return u.startswith("http://")


def _looks_like_ip(url: str) -> bool:
    return bool(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", url or ""))


def _lure_hits(text: str) -> list[str]:
    t = (text or "").lower()
    return [w for w in LURE_WORDS if w in t]


def _extract_url_from_vcard(payload: str) -> str | None:
    m = re.search(r"(?im)^\s*URL\s*:\s*(.+?)\s*$", payload or "")
    if m:
        return m.group(1).strip()
    m2 = re.search(r"(https?://[^\s]+)", payload or "", flags=re.IGNORECASE)
    return m2.group(1).strip() if m2 else None


def _extract_first_url_anywhere(payload: str) -> str | None:
    m = re.search(r"(https?://[^\s]+)", payload or "", flags=re.IGNORECASE)
    if m:
        return m.group(1).strip()
    # also allow www.*
    m2 = re.search(r"\b(www\.[^\s]+)", payload or "", flags=re.IGNORECASE)
    return m2.group(1).strip() if m2 else None


def _sms_threats(payload: str) -> list[str]:
    p = (payload or "").strip()
    up = p.upper()
    threats = []
    if up.startswith(("SMSTO:", "SMS:")):
        threats.append("SMS QR: May trigger composing/sending an SMS (social engineering risk).")
        if any(k in p.lower() for k in ["bank", "otp", "verify", "urgent", "money", "transfer", "payment"]):
            threats.append("SMS Heuristic: smishing keywords detected (otp/bank/urgent/verify/...)")
    return threats


def _tel_threats(payload: str) -> list[str]:
    p = (payload or "").strip().lower()
    threats = []
    if p.startswith("tel:"):
        threats.append("TEL QR: Can initiate a phone call—common for scam call redirection.")
    return threats


def _email_threats(payload: str) -> list[str]:
    p = (payload or "").strip()
    up = p.upper()
    threats = []
    if p.lower().startswith("mailto:") or up.startswith("MATMSG:"):
        threats.append("EMAIL QR: May prefill an email (phishing/social engineering risk).")
        if any(k in p.lower() for k in ["password", "otp", "verify", "urgent", "invoice", "payment", "bank"]):
            threats.append("Email Heuristic: phishing keywords detected (otp/bank/urgent/verify/...)")
    return threats


def _vcard_threats(payload: str) -> list[str]:
    up = (payload or "").upper()
    threats = []
    if up.startswith("BEGIN:VCARD") or "VCARD" in up:
        threats.append("VCARD QR: Can import contact data—may hide malicious URLs in fields.")
        if "URL:" in up or "HTTP" in up:
            threats.append("VCARD contains URL fields—verify before opening embedded links.")
    return threats


def _verdict_band(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


# -----------------------------
# Main Analyzer (RULES + ML ONLY)
# -----------------------------
async def analyze_qr_payload(payload: str, report_id: str | None = None) -> dict:
    payload = (payload or "").strip()

    findings: list[str] = []
    benign: list[str] = []
    risk_score = 0

    if not report_id or not str(report_id).strip():
        report_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]

    # 0) Type
    ptype = detect_payload_type(payload)
    findings.append(f"Payload type: {ptype}")

    # 1) General Pattern Scan (regex rules)
    pattern_issues = scan_for_patterns(payload)
    if pattern_issues:
        findings.extend(pattern_issues)
        risk_score += 40
    else:
        benign.append("No obvious injection patterns found (basic regex scan).")

    # 2) Payload-specific rules
    extracted_url: str | None = None

    if ptype == "wifi":
        wifi_issues = detect_wifi_threats(payload)
        if wifi_issues:
            findings.extend(wifi_issues)
            risk_score += 40
        else:
            benign.append("Wi-Fi payload: no obvious Wi-Fi misconfig threats detected.")

    elif ptype == "sms":
        sms_issues = _sms_threats(payload)
        if sms_issues:
            findings.extend(sms_issues)
            risk_score += 45

    elif ptype == "tel":
        tel_issues = _tel_threats(payload)
        if tel_issues:
            findings.extend(tel_issues)
            risk_score += 20

    elif ptype == "email":
        email_issues = _email_threats(payload)
        if email_issues:
            findings.extend(email_issues)
            risk_score += 25

    elif ptype == "vcard":
        v_issues = _vcard_threats(payload)
        if v_issues:
            findings.extend(v_issues)
            risk_score += 20
        extracted_url = _extract_url_from_vcard(payload)

    elif ptype == "url":
        extracted_url = payload

    else:
        extracted_url = _extract_first_url_anywhere(payload)

    # 3) URL Rules + ML (only if we have a URL)
    url_analysis = None
    if extracted_url:
        url = extracted_url.strip()
        url_findings: list[str] = []
        url_benign: list[str] = []
        url_risk = 0

        domain = _get_domain(url)
        if not domain:
            url_findings.append("URL parsing failed (domain not detected).")
            url_risk += 25
        else:
            if _domain_in_set(domain, RESERVED_DOMAINS):
                url_findings.append("URL points to reserved/local domain (test/localhost) - verify intent.")
                url_risk += 10

            if _domain_in_set(domain, ALLOWLIST_DOMAINS):
                url_benign.append("Domain is in allowlist (still verify path and parameters).")

            if domain in SHORTENERS:
                url_findings.append("URL shortener detected (hides final destination).")
                url_risk += 25

            if "xn--" in domain:
                url_findings.append("Punycode domain detected (possible IDN homograph risk).")
                url_risk += 20

            if domain.count("-") >= 3:
                url_findings.append("Many dashes in domain (often seen in phishing domains).")
                url_risk += 10

            if not _dns_resolves(domain) and not _domain_in_set(domain, RESERVED_DOMAINS):
                url_findings.append("Domain does not resolve in DNS (suspicious or dead domain).")
                url_risk += 15
            else:
                url_benign.append("Domain resolves in DNS.")

        if _url_is_http(url):
            url_findings.append("URL uses HTTP (not HTTPS) — vulnerable to MITM / downgrade.")
            url_risk += 10
        else:
            url_benign.append("Uses HTTPS or non-HTTP scheme.")

        if _looks_like_ip(url):
            url_findings.append("IP address used in URL (common in phishing/malware).")
            url_risk += 15

        hits = _lure_hits(url)
        if hits:
            url_findings.append(f"Lure keywords detected in URL: {', '.join(hits)}")
            url_risk += 10

        # ML prediction (if model exists)
        ml_result = None
        if model_exists():
            try:
                ml_result = predict_url(url)
                if ml_result.get("label") == "phishing":
                    url_findings.append(
                        f"ML flagged URL as phishing (p={ml_result.get('phishing_probability'):.3f}, "
                        f"thr={ml_result.get('threshold'):.3f})."
                    )
                    url_risk += 35
                else:
                    url_benign.append(
                        f"ML labeled URL as benign (p={ml_result.get('phishing_probability'):.3f})."
                    )
            except Exception as e:
                url_findings.append(f"ML prediction failed: {e}")
                url_risk += 10
        else:
            url_benign.append("ML model not found (url_model.pkl missing) — skipped ML check.")

        url_risk = min(100, url_risk)
        url_analysis = {
            "url": url,
            "domain": domain,
            "risk_score": url_risk,
            "findings": url_findings,
            "benign": url_benign,
            "ml": ml_result,
        }

        findings.extend([f"[URL] {x}" for x in url_findings])
        benign.extend([f"[URL] {x}" for x in url_benign])
        risk_score += min(40, url_risk // 2)  # merge into overall score nicely

    risk_score = max(0, min(100, risk_score))
    verdict = _verdict_band(risk_score)

    result = {
        "report_id": report_id,
        "payload": payload,
        "payload_type": ptype,
        "risk_score": risk_score,
        "verdict": verdict,
        "findings": findings,
        "benign": benign,
        "url_analysis": url_analysis,
    }

    result["report_md"] = build_markdown_report(result)
    return result