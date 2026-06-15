"""
blacklist_check.py - Checks URL domain against a local blacklist file.
Also checks against a hardcoded extended list of known phishing domains.
"""

import os
from urllib.parse import urlparse

DEFAULT_BLACKLIST = os.path.join(os.path.dirname(__file__), "..", "data", "blacklist.txt")

# Extended hardcoded known-bad domains (supplements the file)
KNOWN_BAD = {
    "paypal-secure-login.com", "paypa1.com", "appleid-verify.com",
    "secure-bankofamerica.com", "amazon-security-alert.com",
    "facebook-login-verify.com", "google-account-recovery.net",
    "microsoft-support-alert.com", "netflix-billing-update.com",
    "instagram-verify-account.com", "known-phishing-site.com",
    "login-paypal.com", "secure-login-amazon.com",
    "bankofamerica-verify.net", "wellsfargo-secure.com",
    "chase-alert-security.com", "irs-tax-refund.com",
    "dhl-package-tracking.net", "fedex-delivery-alert.com",
    "crypto-wallet-verify.com", "binance-secure-login.net",
    "coinbase-alert.com", "steam-free-items.com",
    "roblox-free-robux.com", "paypa1-login.com",
    "accounts-google.com", "apple-id-unlock.com",
    "amazon-prime-cancel.com", "netflix-account-hold.com",
    "microsoft-refund.com", "paypal-resolution-center.com",
    "signin-amazon.com", "fb-login-secure.com",
    "verify-your-paypal.com", "update-billing-netflix.com",
    "support-apple-id.com", "google-warning-alert.com",
    "secure-chase-bank.com", "wellsfargo-alert.com",
    "irs-gov-refund.com", "usps-delivery-fail.com",
    "fedex-missed-delivery.com", "dhl-tracking-update.com",
}


def load_blacklist(path: str = DEFAULT_BLACKLIST) -> set:
    domains = set(KNOWN_BAD)
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
        blacklist = load_blacklist(path)
        if hostname in blacklist:
            return {
                "flagged":  True,
                "message":  f"Domain found in blacklist ({hostname})",
                "severity": "DANGEROUS",
            }
        # Also check if any blacklisted domain is a suffix of the hostname
        # e.g. evil.paypal-secure-login.com should still match
        for bad in blacklist:
            if hostname.endswith("." + bad) or hostname == bad:
                return {
                    "flagged":  True,
                    "message":  f"Domain matches blacklisted entry '{bad}'",
                    "severity": "DANGEROUS",
                }
        return {"flagged": False, "message": "Domain not found in blacklist", "severity": "OK"}
    except Exception:
        return {"flagged": False, "message": "Could not perform blacklist check", "severity": "OK"}
