"""
main.py - Phishing Detection System
Usage: python main.py --url <URL>
"""

import argparse
import sys
from urllib.parse import urlparse

from colorama import init, Fore, Style

from checks.ip_check       import check_ip_url
from checks.length_check   import check_url_length
from checks.https_check    import check_https
from checks.shortener_check import check_shortener
from checks.blacklist_check import check_blacklist
from checks.domain_check   import check_suspicious_domain

init(autoreset=True)

# ── Score weights ──────────────────────────────────────────────────────────────
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
    print(Fore.CYAN + Style.BRIGHT + "  ╔══════════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT + "  ║       PHISHING DETECTION SYSTEM          ║")
    print(Fore.CYAN + Style.BRIGHT + "  ╚══════════════════════════════════════════╝" + Style.RESET_ALL)
    print()


def print_row(label: str, result: dict):
    sev = result["severity"]
    msg = result["message"]

    if sev == "OK":
        icon  = Fore.GREEN  + "[✓]"
        arrow = Fore.GREEN  + "→ OK"
        line  = Fore.GREEN
    elif sev == "SUSPICIOUS":
        icon  = Fore.YELLOW + "[!]"
        arrow = Fore.YELLOW + "→ SUSPICIOUS"
        line  = Fore.YELLOW
    else:
        icon  = Fore.RED    + "[✗]"
        arrow = Fore.RED    + "→ DANGEROUS"
        line  = Fore.RED

    print(f"  {icon}  {line}{msg:<48}{Style.RESET_ALL}  {arrow}{Style.RESET_ALL}")


def print_verdict(score: int):
    print()
    print("  " + "─" * 58)
    if score == 0:
        colour  = Fore.GREEN
        verdict = "SAFE"
        note    = "No phishing indicators found. Looks clean."
    elif score <= 3:
        colour  = Fore.YELLOW
        verdict = "SUSPICIOUS"
        note    = "Some indicators found. Proceed with caution."
    else:
        colour  = Fore.RED
        verdict = "DANGEROUS"
        note    = "Multiple indicators found. Do NOT visit this URL."

    print(f"  Final Verdict : {colour}{Style.BRIGHT}{verdict}{Style.RESET_ALL}   (risk score: {score})")
    print(f"  {colour}{note}{Style.RESET_ALL}")
    print("  " + "─" * 58)
    print()


# ── Core logic ─────────────────────────────────────────────────────────────────

def analyse(url: str):
    print_banner()
    print(f"  Scanning  : {Fore.CYAN}{url}{Style.RESET_ALL}")
    print("  " + "─" * 58)
    print()

    checks = [
        check_ip_url(url),
        check_https(url),
        check_url_length(url),
        check_shortener(url),
        check_blacklist(url),
        check_suspicious_domain(url),
    ]

    labels = [
        "IP-Based URL",
        "HTTPS Check",
        "URL Length",
        "URL Shortener",
        "Blacklist Check",
        "Suspicious Domain",
    ]

    total = 0
    for label, result in zip(labels, checks):
        print_row(label, result)
        total += SCORE[result["severity"]]

    print_verdict(total)


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="phishing-detector",
        description="Analyse a URL for phishing indicators.",
    )
    parser.add_argument("--url", required=True, metavar="URL",
                        help="URL to analyse  e.g. https://example.com")
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
