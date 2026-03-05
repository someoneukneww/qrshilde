import re

def scan_for_patterns(text: str):
    """
    فحص النص بحثاً عن أنماط الهجمات المعروفة باستخدام Regex
    """
    flags = []
    
    patterns = {
        "SQL Injection": [
            r"(?i)WAITFOR DELAY", 
            r"(?i)UNION SELECT", 
            r"OR 1=1"
        ],
        "XSS (Cross-Site Scripting)": [
            r"<script>", 
            r"javascript:", 
            r"onerror=", 
            r"onload="
        ],
        "Command Injection": [
            r";\s*rm\s+-rf", 
            r"\|\s*bash", 
            r"cmd\.exe"
        ],
        "Sensitive Data": [
            r"BEGIN PRIVATE KEY",
            r"(?i)password="
        ]
    }

    for attack_type, regex_list in patterns.items():
        for pattern in regex_list:
            if re.search(pattern, text):
                flags.append(f"Detected {attack_type} pattern: '{pattern}'")
                break 

    return flags
