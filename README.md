# WebScan-Lite

A lightweight, non-intrusive Python CLI tool for automated website security-misconfiguration assessment. Findings are mapped to the OWASP Top 10 (2021), ranked by severity, and scored 0-100.

Built as my project for the Certified Ethical Hacking (CEH) training at Boston Institute of Analytics (BIA), June 2026 batch.

> **Disclaimer:** For authorized testing and educational use only. Run it only against systems you own or have written permission to test. Scanning third-party sites without authorization may violate the law (for example, India's IT Act, 2000).

## Why this project

Manually checking security headers, transport-layer settings, version disclosure, and exposed files is repetitive and easy to get wrong. WebScan-Lite automates these checks to give a repeatable, evidence-based security baseline before a release.

## Features

- Single-file Python CLI; the only dependency is `requests`
- 8 check modules, each finding mapped to an OWASP Top 10 (2021) category
- Severity-ranked report (Critical / High / Medium / Low / Info) with evidence and a suggested fix
- 0-100 security score with an A-D grade
- JSON export for record keeping and CI/CD use
- Non-intrusive by design: no exploit payloads, request delay between probes, and an `--authorized` flag so the tool will not run without an explicit authorization confirmation

## Detection modules

| # | Module | What it checks | OWASP 2021 |
|---|--------|----------------|------------|
| 1 | HTTPS Enforcement | Site served over plain HTTP; HTTP to HTTPS redirect | A02 Cryptographic Failures |
| 2 | TLS Health | Certificate verification, expiry, TLS 1.0/1.1 | A02 Cryptographic Failures |
| 3 | Security Headers | CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy | A05 / A02 |
| 4 | Version Disclosure | Server, X-Powered-By, X-AspNet-Version, X-Generator | A05 Security Misconfiguration |
| 5 | Cookie Hardening | Secure, HttpOnly, SameSite flags | A07 Authentication Failures |
| 6 | HTTP Methods | PUT, DELETE, TRACE, CONNECT, PATCH advertised | A05 Security Misconfiguration |
| 7 | Sensitive Files | `.env`, `.git/HEAD`, backups, DB dumps (uses a soft-404 baseline) | A01 Broken Access Control |
| 8 | Directory Listing | Auto-index enabled on the root page | A05 Security Misconfiguration |

## Architecture

```
[ CLI / Config ] -> [ HTTP Session ] -> [ 8 Check Modules ] -> [ Scoring Engine ] -> [ Console + JSON Report ]
```

## Installation

```bash
git clone https://github.com/<your-username>/webscan-lite.git
cd webscan-lite
pip install -r requirements.txt
```

Requires Python 3.8 or later.

## Usage

```bash
python webscan_lite.py http://localhost:3000 --authorized --json report.json
```

| Flag | Description |
|------|-------------|
| `target` | Target URL (a missing scheme defaults to https) |
| `--authorized` | Confirms you are authorized to test the target. Without it, the tool asks for confirmation and aborts unless you type `yes` |
| `--timeout N` | Request timeout in seconds (default 10) |
| `--delay N` | Delay between sensitive-file probes in seconds (default 0.3) |
| `--insecure` | Skip TLS certificate verification (lab use only) |
| `--json FILE` | Write the full report as JSON |

## Scoring

The score starts at 100. Each finding deducts points by severity: Critical 25, High 15, Medium 8, Low 3, Info 0.

Grades: **A** 85 and above, **B** 70 and above, **C** 50 and above, **D** below 50.

## Proof of concept

Target: [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), a deliberately vulnerable application, self-hosted in Docker. Scanned from Kali Linux (WSL 2).

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
python webscan_lite.py http://localhost:3000 --authorized --json report.json
```

Result: **56/100 (Grade C)** with 2 High, 1 Medium, and 2 Low findings, including:

- Site served over plain HTTP (High)
- Missing Content-Security-Policy header (High)
- Missing Strict-Transport-Security header (Medium)
- Missing Referrer-Policy header (Low)

Screenshots are in [`screenshots/`](screenshots/) and the full output is in [`sample_report.json`](sample_report.json).

## Recommended fixes (from the report)

- Serve all traffic over HTTPS and redirect HTTP to HTTPS
- Add `Content-Security-Policy`, `Strict-Transport-Security`, `Referrer-Policy`, and `Permissions-Policy` headers
- Hide version information (Nginx `server_tokens off;`, Apache `ServerTokens Prod`)
- Disable TRACE (Apache `TraceEnable off`)
- Run WebScan-Lite in CI/CD and fail the build if the score drops below 80

## Limitations

- Checks configuration and exposure only. It does **not** test for SQL injection, XSS, authentication bypass, or business-logic flaws; those need manual testing (for example, with Burp Suite).
- The TLS check runs only when the target is served over HTTPS, so it is skipped for `http://localhost`.
- Findings should be verified manually before they are reported.

## Roadmap

- More detection modules
- CI/CD integration with a score threshold gate
- HTML report output

## Documentation

The full project report is in [`docs/`](docs/).

## Author

**Prem Shelavale**
LinkedIn: [linkedin.com/in/prem-shelavale](https://www.linkedin.com/in/prem-shelavale)

## License

MIT
