# Phishing Detection System

A command-line tool that analyses URLs for phishing indicators and returns a clear risk verdict.

## Setup

```bash
cd phishing-detection-system
pip install -r requirements.txt
```

## Usage

```bash
python main.py --url <URL>
```

## Example Outputs

**Dangerous URL (IP-based + blacklisted)**
```
$ python main.py --url http://192.168.1.1/login

  ╔══════════════════════════════════════════╗
  ║       PHISHING DETECTION SYSTEM          ║
  ╚══════════════════════════════════════════╝

  Scanning  : http://192.168.1.1/login
  ──────────────────────────────────────────────────────────

  [✗]  IP-based URL detected                             → DANGEROUS
  [!]  No HTTPS detected (insecure)                      → SUSPICIOUS
  [✓]  URL length is normal (26 chars)                   → OK
  [✓]  No URL shortener detected                         → OK
  [✓]  Domain not found in blacklist                     → OK
  [✓]  No suspicious domain patterns detected            → OK

  ──────────────────────────────────────────────────────────
  Final Verdict : DANGEROUS   (risk score: 4)
  Multiple indicators found. Do NOT visit this URL.
  ──────────────────────────────────────────────────────────
```

**Safe URL**
```
$ python main.py --url https://google.com

  Final Verdict : SAFE   (risk score: 0)
  No phishing indicators found. Looks clean.
```

**Invalid URL**
```
$ python main.py --url not_a_url

  [ERROR] 'not_a_url' is not a valid URL.
  Tip   : URL must start with http:// or https://
```

## Run Tests

```bash
python -m pytest tests/ -v
# or
python -m unittest discover tests/
```

## Checks Performed

| Check | Flags When |
|---|---|
| IP-Based URL | URL uses a raw IP address |
| HTTPS Check | URL uses HTTP instead of HTTPS |
| URL Length | URL is longer than 75 characters |
| URL Shortener | Domain is a known shortener (bit.ly, tinyurl, etc.) |
| Blacklist Check | Domain is in `data/blacklist.txt` |
| Suspicious Domain | Lookalike/typosquat brand domains detected |

## Scoring

| Severity | Score |
|---|---|
| OK | 0 |
| SUSPICIOUS | 1 |
| DANGEROUS | 3 |

- Score 0 → **SAFE**
- Score 1–3 → **SUSPICIOUS**
- Score 4+ → **DANGEROUS**

## Add to Blacklist

Edit `data/blacklist.txt` and add one domain per line:
```
malicious-site.com
fake-paypal.net
```
