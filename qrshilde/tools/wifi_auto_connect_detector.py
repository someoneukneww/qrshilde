import re


def detect_wifi_threats(payload: str):
    threats = []

    if not (payload or "").startswith("WIFI:"):
        return []

    encryption_match = re.search(r"T:([^;]+)", payload)
    encryption = encryption_match.group(1) if encryption_match else "unknown"

    enc_lower = (encryption or "").lower()

    if enc_lower in ("nopass", ""):
        threats.append("Unsecured Wi-Fi Network (No Password) - High Risk.")

    if (encryption or "").upper() == "WEP":
        threats.append("Weak Encryption (WEP) - Easily Hacked.")

    # Case-insensitive check for hidden network flag
    if "h:true" in (payload or "").lower():
        threats.append("Hidden Network - Often used in 'Evil Twin' attacks.")

    return threats