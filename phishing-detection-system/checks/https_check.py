"""
https_check.py - Checks whether the URL uses HTTPS or insecure HTTP.
"""

from urllib.parse import urlparse


def check_https(url: str) -> dict:
    try:
        scheme = urlparse(url).scheme.lower()
        if scheme == "https":
            return {"flagged": False, "message": "HTTPS detected (secure)",          "severity": "OK"}
        return  {"flagged": True,  "message": "No HTTPS detected (insecure)",       "severity": "SUSPICIOUS"}
    except Exception:
        return  {"flagged": True,  "message": "Could not determine URL scheme",     "severity": "SUSPICIOUS"}
