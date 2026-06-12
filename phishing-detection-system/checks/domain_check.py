"""
domain_check.py - Detects suspicious/lookalike (typosquatting) domains.
"""

import re
from urllib.parse import urlparse

BRANDS = [
    "paypal", "apple", "google", "amazon", "facebook", "microsoft",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "chase",
    "bankofamerica", "wellsfargo", "ebay", "steam", "discord",
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "confirm", "password", "support", "alert", "recover",
]


def check_suspicious_domain(url: str) -> dict:
    try:
        hostname = (urlparse(url).hostname or "").lower()

        # Heuristic 1: digits mixed into a brand name (e.g. paypa1)
        for brand in BRANDS:
            if brand in hostname and re.search(r"\d", hostname):
                return {"flagged": True,
                        "message": f"Possible lookalike domain detected ({hostname})",
                        "severity": "SUSPICIOUS"}

        # Heuristic 2: brand name + suspicious keyword together
        for brand in BRANDS:
            if brand in hostname:
                for kw in SUSPICIOUS_KEYWORDS:
                    if kw in hostname:
                        return {"flagged": True,
                                "message": f"Suspicious domain – '{brand}' + '{kw}' ({hostname})",
                                "severity": "SUSPICIOUS"}

        return {"flagged": False, "message": "No suspicious domain patterns detected", "severity": "OK"}
    except Exception:
        return {"flagged": False, "message": "Could not analyse domain", "severity": "OK"}
