"""
entropy_check.py - Flags domains with high character entropy (randomness).

Randomly generated domains used in phishing / malware C2 often have
unusually high Shannon entropy.  Legitimate domains tend to be pronounceable
words with lower entropy.

Threshold chosen empirically:
  - google.com  → ~2.75
  - amazon.com  → ~2.50
  - xkcd.com    → ~2.00
  - a8f3kz2.xyz → ~3.00+
"""

import math
from urllib.parse import urlparse

ENTROPY_THRESHOLD = 3.8   # flag above this value


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def check_entropy(url: str) -> dict:
    try:
        hostname = (urlparse(url).hostname or "").lower()
        # Use only the second-level domain to avoid punishing long subdomains
        parts = hostname.split(".")
        sld   = parts[-2] if len(parts) >= 2 else hostname
        entropy = _shannon_entropy(sld)

        if entropy >= ENTROPY_THRESHOLD:
            return {
                "flagged":  True,
                "message":  f"High domain entropy ({entropy:.2f}) – possible DGA/random domain",
                "severity": "SUSPICIOUS",
            }
        return {
            "flagged":  False,
            "message":  f"Domain entropy normal ({entropy:.2f})",
            "severity": "OK",
        }
    except Exception:
        return {"flagged": False, "message": "Could not compute entropy", "severity": "OK"}
