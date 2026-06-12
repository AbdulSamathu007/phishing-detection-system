"""
shortener_check.py - Detects known URL shortening services.
"""

from urllib.parse import urlparse

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "short.link", "tiny.cc",
    "rb.gy", "cutt.ly", "shorturl.at", "bl.ink", "clck.ru",
}


def check_shortener(url: str) -> dict:
    try:
        hostname = (urlparse(url).hostname or "").lower().removeprefix("www.")
        if hostname in SHORTENERS:
            return {"flagged": True,  "message": f"URL shortener detected ({hostname})",  "severity": "SUSPICIOUS"}
        return  {"flagged": False, "message": "No URL shortener detected",                "severity": "OK"}
    except Exception:
        return  {"flagged": False, "message": "Could not check for URL shortener",        "severity": "OK"}
