# Web Vulnerability Scanner 🔍
**An educational Python tool for intermediate cybersecurity students.**

---

## What This Tool Does
Scans a target web application for 5 vulnerability categories:

| Module       | Vulnerability                | OWASP Category              |
|--------------|------------------------------|-----------------------------|
| `headers`    | Missing security headers     | A05: Security Misconfiguration |
| `sqli`       | SQL Injection                | A03: Injection              |
| `xss`        | Reflected XSS                | A03: Injection              |
| `redirect`   | Open Redirect                | A10: SSRF / Redirect        |
| `traversal`  | Directory/Path Traversal     | A01: Broken Access Control  |

---

## Setup

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# Run all modules against a target
python scanner.py "http://testphp.vulnweb.com/listproducts.php?cat=1"

# Run only specific modules
python scanner.py "http://target.com/page?id=1" --modules sqli xss

# Verbose mode (see every request)
python scanner.py "http://target.com/page?id=1" -v

# Headers-only scan
python scanner.py "http://target.com" --modules headers
```

---

## Safe Practice Targets
**Only scan targets you own or have explicit permission to test.**

Great legal practice targets:
- **DVWA** (Damn Vulnerable Web Application): http://www.dvwa.co.uk/
- **WebGoat** (OWASP): https://owasp.org/www-project-webgoat/
- **Vulnweb** (Acunetix demo): http://testphp.vulnweb.com
- **HackTheBox / TryHackMe** lab machines

---

## Project Structure

```
web_vuln_scanner/
├── scanner.py              ← Entry point (run this)
├── requirements.txt
├── modules/
│   ├── headers.py          ← Security header checks
│   ├── sql_injection.py    ← SQLi detection
│   ├── xss.py              ← Reflected XSS detection
│   ├── open_redirect.py    ← Open redirect detection
│   └── dir_traversal.py    ← Path traversal detection
└── utils/
    ├── http_client.py      ← Shared HTTP session
    └── report.py           ← Findings + JSON report output
```

---

## What You'll Learn From Each Module

### `headers.py`
- What HTTP security headers do (HSTS, CSP, X-Frame-Options, etc.)
- How missing headers enable clickjacking, MITM, MIME sniffing
- How to defend: setting headers in Apache/Nginx/Express

### `sql_injection.py`
- How SQL injection payloads break out of string context
- Error-based vs. blind SQLi detection techniques
- Why parameterized queries / prepared statements are the fix

### `xss.py`
- Reflected vs. Stored vs. DOM-based XSS
- Why browsers execute injected `<script>` tags
- How output encoding (HTML escaping) prevents XSS

### `open_redirect.py`
- How open redirects enable phishing on trusted domains
- Common redirect parameter names (`url`, `next`, `redirect`, etc.)
- Fix: whitelisting allowed destinations

### `dir_traversal.py`
- How `../` sequences traverse out of the web root
- Reading system files like `/etc/passwd` via web apps
- Encoding tricks (`%2F`, `%252F`) to bypass naive filters

---

## Extending the Tool (Ideas for Further Learning)
- Add **blind SQLi** detection (time-based: `SLEEP(5)`)
- Add **CSRF token detection** (check for forms without tokens)
- Add **subdomain enumeration** module
- Add an **HTML report** output option
- Add **authentication support** (cookie/header injection for logged-in scanning)
- Add a **Burp Suite-like proxy** mode to intercept requests

---

## Ethical & Legal Notice
This tool is for **educational use only**.
Only run it against:
1. Systems you own
2. Systems you have explicit written permission to test
3. Intentionally vulnerable lab environments

Unauthorized scanning is illegal in most jurisdictions.
