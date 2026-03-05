def detect_payload_type(payload: str) -> str:
    p = (payload or "").strip()

    if p.startswith(("http://", "https://", "www.")):
        return "url"

    up = p.upper()

    if up.startswith("WIFI:"):
        return "wifi"

    if up.startswith(("SMSTO:", "SMS:")):
        return "sms"

    if p.lower().startswith("tel:"):
        return "tel"

    if p.lower().startswith("mailto:"):
        return "email"

    if up.startswith("MATMSG:"):
        return "email"

    if up.startswith("BEGIN:VCARD") or "VCARD" in up:
        return "vcard"

    if p.lower().startswith(("intent://", "market://")):
        return "deeplink"

    return "text"