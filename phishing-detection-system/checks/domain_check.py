"""
domain_check.py - Detects suspicious / lookalike (typosquatting) domains.

Heuristics applied (in order):
  1. DNS resolution failure  → domain does not exist (fake)
  2. Risky TLD               → .xyz, .tk, .ml, .ga, .cf, .top …
  3. Homoglyph / leet-speak  → paypa1 normalises to paypal but SLD ≠ brand
  4. Brand + keyword combo   → paypal-secure-login.com
  5. Brand in SLD + digits   → paypal123.com  (but not paypal.com itself)
  6. Subdomain spoofing       → paypal.evil.com
  7. Excessive subdomains    → a.b.c.d.evil.com
  8. Hyphen abuse            → pay-pal-secure-login.com
  9. Punycode / IDN          → xn-- homograph domains
 10. Brand directly embedded (only when SLD ≠ brand, to avoid false positives
     on legitimate domains like google.com, paypal.com, etc.)
"""

import re
import socket
from urllib.parse import urlparse

# ── Trusted TLDs for well-known brands (whitelist check) ─────────────────────
TRUSTED_TLDS = {".com", ".net", ".org", ".io", ".co", ".gov", ".edu"}

# ── Exact legitimate brand→domain mappings  (sld → {allowed tlds}) ───────────
# If hostname is EXACTLY <brand><tld> from this dict, skip brand checks.
LEGITIMATE = {
    "google":       {".com", ".net", ".org", ".co"},
    "paypal":       {".com", ".net"},
    "apple":        {".com", ".net"},
    "amazon":       {".com", ".co"},
    "facebook":     {".com", ".net"},
    "microsoft":    {".com", ".net"},
    "netflix":      {".com", ".net"},
    "instagram":    {".com"},
    "twitter":      {".com"},
    "linkedin":     {".com"},
    "dropbox":      {".com"},
    "chase":        {".com"},
    "bankofamerica":{".com"},
    "wellsfargo":   {".com"},
    "ebay":         {".com", ".co"},
    "steam":        {".com"},
    "discord":      {".com", ".gg"},
    "yahoo":        {".com", ".net"},
    "coinbase":     {".com"},
    "binance":      {".com"},
    "robinhood":    {".com"},
    "tiktok":       {".com"},
    "snapchat":     {".com"},
    "whatsapp":     {".com", ".net"},
    "telegram":     {".org", ".me"},
    "roblox":       {".com"},
    "dhl":          {".com", ".de"},
    "fedex":        {".com", ".net"},
    "ups":          {".com"},
    "usps":         {".com", ".gov"},
    "irs":          {".gov"},
    "citibank":     {".com"},
    "barclays":     {".com", ".co"},
    "hsbc":         {".com", ".co"},
    "icloud":       {".com"},
    "outlook":      {".com"},
}

BRANDS = list(LEGITIMATE.keys()) + [
    "office365", "gov", "coinbase", "crypto", "wallet",
]

# ── Keywords that suggest credential-harvesting pages ────────────────────────
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "secure", "account",
    "update", "banking", "confirm", "password", "support", "alert",
    "recover", "validate", "authenticate", "credential", "wallet",
    "billing", "payment", "refund", "invoice", "tracking", "delivery",
    "security", "access", "unlock", "suspended", "limited", "urgent",
]

# ── Risky TLDs ────────────────────────────────────────────────────────────────
RISKY_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".work",
    ".click", ".loan", ".date", ".stream", ".download", ".racing",
    ".review", ".bid", ".trade", ".accountant", ".science", ".faith",
    ".party", ".cricket", ".win", ".space", ".online", ".site",
    ".website", ".tech", ".buzz", ".club", ".info", ".biz",
}

# ── Homoglyph normalisation map (single-char keys only for str.maketrans) ─────
HOMOGLYPHS = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "6": "g", "7": "t", "8": "b", "9": "g", "@": "a",
    "!": "i", "|": "l", "$": "s",
})


def _normalise(text: str) -> str:
    """Replace leet/homoglyph chars so 'paypa1' → 'paypal'."""
    text = text.replace("vv", "w")
    return text.translate(HOMOGLYPHS)


def _extract_parts(hostname: str):
    """Return (subdomain_labels, sld, tld) for a hostname string."""
    parts = hostname.split(".")
    if len(parts) < 2:
        return [], hostname, ""
    tld  = "." + parts[-1]
    sld  = parts[-2]
    subs = parts[:-2]
    return subs, sld, tld


def _is_legitimate(sld: str, tld: str) -> bool:
    """Return True if sld+tld is an exact legitimate brand domain."""
    allowed_tlds = LEGITIMATE.get(sld)
    return allowed_tlds is not None and tld in allowed_tlds


def check_suspicious_domain(url: str) -> dict:
    try:
        raw_hostname = (urlparse(url).hostname or "").lower()
        if not raw_hostname:
            return {"flagged": False, "message": "Could not extract hostname", "severity": "OK"}

        # Strip leading www.
        hostname = raw_hostname.removeprefix("www.")
        subs, sld, tld = _extract_parts(hostname)
        normalised_sld = _normalise(sld)

        # ── 1. DNS resolution check ──────────────────────────────────────────
        try:
            socket.setdefaulttimeout(3)
            socket.gethostbyname(raw_hostname)
            dns_ok = True
        except (socket.gaierror, socket.timeout, OSError):
            dns_ok = False

        if not dns_ok:
            return {
                "flagged":  True,
                "message":  f"Domain does not resolve – likely fake ({hostname})",
                "severity": "DANGEROUS",
            }

        # ── Whitelist: exact legitimate brand domains ────────────────────────
        if _is_legitimate(sld, tld) and not subs:
            return {
                "flagged":  False,
                "message":  "No suspicious domain patterns detected",
                "severity": "OK",
            }

        # ── 2. Risky TLD ─────────────────────────────────────────────────────
        if tld in RISKY_TLDS:
            return {
                "flagged":  True,
                "message":  f"High-risk TLD detected ({tld}) in {hostname}",
                "severity": "SUSPICIOUS",
            }

        # ── 3. Homoglyph / leet-speak brand impersonation ────────────────────
        # Normalised SLD matches a brand but the raw SLD does NOT
        for brand in LEGITIMATE:
            if brand == normalised_sld and brand != sld:
                return {
                    "flagged":  True,
                    "message":  f"Homoglyph/leet impersonation of '{brand}' detected ({hostname})",
                    "severity": "DANGEROUS",
                }

        # ── 4. Brand + suspicious keyword combo in full hostname ──────────────
        for brand in BRANDS:
            brand_present = (brand in normalised_sld or brand in _normalise(hostname))
            if brand_present:
                for kw in SUSPICIOUS_KEYWORDS:
                    if kw in hostname:
                        return {
                            "flagged":  True,
                            "message":  f"Brand '{brand}' + keyword '{kw}' in domain ({hostname})",
                            "severity": "DANGEROUS",
                        }

        # ── 5. Brand in SLD with digits mixed in ─────────────────────────────
        for brand in LEGITIMATE:
            if brand in normalised_sld and re.search(r"\d", sld):
                return {
                    "flagged":  True,
                    "message":  f"Possible lookalike domain detected ({hostname})",
                    "severity": "DANGEROUS",
                }

        # ── 6. Subdomain spoofing ─────────────────────────────────────────────
        # e.g. paypal.evil.com  → paypal is a subdomain, SLD is 'evil'
        sub_str = ".".join(subs).lower()
        for brand in LEGITIMATE:
            if brand in _normalise(sub_str) and not _is_legitimate(sld, tld):
                return {
                    "flagged":  True,
                    "message":  f"Brand '{brand}' used as subdomain spoof ({hostname})",
                    "severity": "DANGEROUS",
                }

        # ── 7. Excessive subdomains ───────────────────────────────────────────
        if len(subs) >= 4:
            return {
                "flagged":  True,
                "message":  f"Excessive subdomains ({len(subs)}) in {hostname}",
                "severity": "SUSPICIOUS",
            }

        # ── 8. Hyphen abuse in SLD ────────────────────────────────────────────
        if sld.count("-") >= 3:
            return {
                "flagged":  True,
                "message":  f"Excessive hyphens in domain ({hostname})",
                "severity": "SUSPICIOUS",
            }

        # ── 9. Punycode / IDN ─────────────────────────────────────────────────
        if hostname.startswith("xn--") or ".xn--" in hostname:
            return {
                "flagged":  True,
                "message":  f"Internationalised domain (possible homograph attack) ({hostname})",
                "severity": "SUSPICIOUS",
            }

        # ── 10. Brand name embedded in SLD (not an exact match) ──────────────
        for brand in LEGITIMATE:
            if brand in normalised_sld and normalised_sld != brand:
                return {
                    "flagged":  True,
                    "message":  f"Brand '{brand}' embedded in domain SLD ({hostname})",
                    "severity": "SUSPICIOUS",
                }

        return {
            "flagged":  False,
            "message":  "No suspicious domain patterns detected",
            "severity": "OK",
        }

    except Exception as exc:
        return {"flagged": False, "message": f"Could not analyse domain ({exc})", "severity": "OK"}
