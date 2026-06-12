"""
length_check.py - Flags abnormally long URLs (> 75 characters).
"""

THRESHOLD = 75


def check_url_length(url: str) -> dict:
    length = len(url)
    if length > THRESHOLD:
        return {"flagged": True,  "message": f"URL is too long ({length} chars)",     "severity": "SUSPICIOUS"}
    return  {"flagged": False, "message": f"URL length is normal ({length} chars)",  "severity": "OK"}
