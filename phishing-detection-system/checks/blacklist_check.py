"""
blacklist_check.py - Checks URL domain against a local blacklist file.
"""

import os
from urllib.parse import urlparse

DEFAULT_BLACKLIST = os.path.join(os.path.dirname(__file__), "..", "data", "blacklist.txt")


def load_blacklist(path: str = DEFAULT_BLACKLIST) -> set:
    domains = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    domains.add(line)
    except FileNotFoundError:
        pass
    return domains


def check_blacklist(url: str, path: str = DEFAULT_BLACKLIST) -> dict:
    try:
        hostname = (urlparse(url).hostname or "").lower().removeprefix("www.")
        if hostname in load_blacklist(path):
            return {"flagged": True,  "message": f"Domain found in blacklist ({hostname})",  "severity": "DANGEROUS"}
        return  {"flagged": False, "message": "Domain not found in blacklist",                "severity": "OK"}
    except Exception:
        return  {"flagged": False, "message": "Could not perform blacklist check",            "severity": "OK"}
