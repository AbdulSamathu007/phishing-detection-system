"""
main.py - Phishing Detection System
Usage: python main.py --url <URL>

Detection checks
────────────────
  1. IP-Based URL          – raw IP address instead of domain name
  2. HTTPS Check           – HTTP (insecure) vs HTTPS
  3. URL Length            – abnormally long URLs
  4. URL Shortener         – known shortening services
  5. Blacklist Check       – known phishing domains
  6. Suspicious Domain     – homoglyphs, typosquatting, subdomain spoof,
                             risky TLD, DNS resolution failure
  7. Domain Entropy        – random/DGA-generated domain names
  8. Domain Age (optional) – newly registered domains (requires python-whois)
"""

import argparse
import sys
from urllib.parse import urlparse

from colorama import init, Fore, Style

from checks.ip_check          import check_ip_url
from checks.length_check      import check_url_length
from checks.https_check       import check_https
from checks.shortener_check   import check_shortener
from checks.blacklist_check   import check_blacklist
from checks.domain_check      import check_suspicious_domain
from checks.entropy_check     import check_entropy
from checks.domain_age_check  import check_domain_age

init(autoreset=True)

# ── Risk weights per severity ──────────────────────────────────────────────────
SCORE = {"OK": 0, "SUSPICIOUS": 1, "DANGEROUS": 3}

# ── Helpers ────────────────────────────────────────────────────────────────────

def is_valid_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def print_banner():
    print()
    print(Fore.CYAN + Style.BRIGHT + "  ╔══════════════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT + "  ║        PHISHING  DETECTION  SYSTEM           ║")
    print(Fore.CYAN + Style.BRIGHT + "  ╚══════════════════════════════════════════════╝")
    print()


def colour_for(severity: str):
    return {
        "OK":        Fore.GREEN,
        "SUSPICIOUS": Fore.YELLOW,
        "DANGEROUS":  Fore.RED,
    }.get(severity, Fore.WHITE)


def print_row(label: str, result: dict):
    sev  = result["severity"]
    msg  = result["message"]
    col  = colour_for(sev)

    icons = {"OK": "[✓]", "SUSPICIOUS": "[!]", "DANGEROUS": "[✗]"}
    icon  = col + icons.get(sev, "[?]") + Style.RESET_ALL

    arrow = col + f"→ {sev}" + Style.RESET_ALL
    label_col = col + f"{label:<20}" + Style.RESET_ALL

    print(f"  {icon}  {label_col}  {col}{msg:<52}{Style.RESET_ALL}  {arrow}")


def print_verdict(score: int):
    print()
    print("  " + "─" * 68)
    if score == 0:
        colour  = Fore.GREEN
        verdict = "✅  SAFE"
        note    = "No phishing indicators found. Looks clean."
    elif score <= 3:
        colour  = Fore.YELLOW
        verdict = "⚠️   SUSPICIOUS"
        note    = "Some indicators present. Proceed with caution."
    else:
        colour  = Fore.RED
        verdict = "🚨  DANGEROUS"
        note    = "Multiple phishing indicators detected. Do NOT visit this URL."

    print(f"  Final Verdict : {colour}{Style.BRIGHT}{verdict}{Style.RESET_ALL}   (risk score: {score})")
    print(f"  {colour}{note}{Style.RESET_ALL}")
    print("  " + "─" * 68)
    print()


def print_details(checks_with_labels):
    """Print a summary of only the flagged checks."""
    flagged = [(lbl, r) for lbl, r in checks_with_labels if r.get("flagged")]
    if not flagged:
        return
    print(f"  {Fore.YELLOW}Flagged indicators:{Style.RESET_ALL}")
    for lbl, r in flagged:
        col = colour_for(r["severity"])
        print(f"    {col}• {lbl}: {r['message']}{Style.RESET_ALL}")
    print()


# ── Core logic ─────────────────────────────────────────────────────────────────

def analyse(url: str):
    print_banner()
    print(f"  Scanning  : {Fore.CYAN}{url}{Style.RESET_ALL}")
    print("  " + "─" * 68)
    print()

    labels_and_checks = [
        ("IP-Based URL",      check_ip_url(url)),
        ("HTTPS Check",       check_https(url)),
        ("URL Length",        check_url_length(url)),
        ("URL Shortener",     check_shortener(url)),
        ("Blacklist",         check_blacklist(url)),
        ("Domain Analysis",   check_suspicious_domain(url)),
        ("Domain Entropy",    check_entropy(url)),
        ("Domain Age",        check_domain_age(url)),
    ]

    total = 0
    for label, result in labels_and_checks:
        print_row(label, result)
        total += SCORE[result["severity"]]

    print()
    print_details(labels_and_checks)
    print_verdict(total)


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="phishing-detector",
        description="Analyse a URL for phishing indicators.",
    )
    parser.add_argument(
        "--url", required=True, metavar="URL",
        help="URL to analyse, e.g.  https://example.com",
    )
    args = parser.parse_args()
    url  = args.url.strip()

    if not is_valid_url(url):
        print()
        print(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} '{url}' is not a valid URL.")
        print(f"  {Fore.YELLOW}Tip   :{Style.RESET_ALL} URL must start with http:// or https://")
        print()
        sys.exit(1)

    analyse(url)


if __name__ == "__main__":
    main()
