"""
ip_check.py - Detects if a URL uses a raw IP address instead of a domain name.
"""

import re
from urllib.parse import urlparse

IPV4_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def check_ip_url(url: str) -> dict:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if IPV4_PATTERN.match(hostname):
            return {"flagged": True,  "message": "IP-based URL detected",       "severity": "DANGEROUS"}
        return  {"flagged": False, "message": "No IP-based URL detected",    "severity": "OK"}
    except Exception:
        return  {"flagged": False, "message": "Could not parse hostname",     "severity": "OK"}
