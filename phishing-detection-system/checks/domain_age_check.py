"""
domain_age_check.py - Checks if a domain was registered very recently.

Uses WHOIS lookup via the 'python-whois' library.
Newly registered domains (< 30 days old) are a strong phishing signal.
Returns OK if whois lookup fails so it never blocks legitimate sites silently.
"""

import datetime
from urllib.parse import urlparse

try:
    import whois as _whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

NEW_DOMAIN_DAYS = 30   # flag if registered within this many days


def check_domain_age(url: str) -> dict:
    if not WHOIS_AVAILABLE:
        return {
            "flagged":  False,
            "message":  "WHOIS library not installed (skipped)",
            "severity": "OK",
        }

    try:
        hostname = (urlparse(url).hostname or "").lower().removeprefix("www.")
        if not hostname:
            return {"flagged": False, "message": "Could not extract hostname", "severity": "OK"}

        w = _whois.whois(hostname)
        creation = w.creation_date

        # python-whois sometimes returns a list
        if isinstance(creation, list):
            creation = creation[0]

        if creation is None:
            return {
                "flagged":  False,
                "message":  "Domain age unknown (WHOIS returned no date)",
                "severity": "OK",
            }

        if isinstance(creation, str):
            # attempt basic parse
            creation = datetime.datetime.fromisoformat(creation[:10])

        age_days = (datetime.datetime.utcnow() - creation).days

        if age_days < NEW_DOMAIN_DAYS:
            return {
                "flagged":  True,
                "message":  f"Domain is only {age_days} day(s) old – very new",
                "severity": "SUSPICIOUS",
            }

        return {
            "flagged":  False,
            "message":  f"Domain age is {age_days} days (established)",
            "severity": "OK",
        }

    except Exception:
        return {
            "flagged":  False,
            "message":  "WHOIS lookup failed (skipped)",
            "severity": "OK",
        }
