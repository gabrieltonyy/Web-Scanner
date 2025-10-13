# Web Vulnerability Scanner & Reporter

A Python-based tool focused on OWASP Top 10 coverage: crawls targets, performs passive and selected active checks, integrates with ZAP/Burp, and generates a professional report (HTML → PDF). Safe-by-default with scope controls, rate limits, SSRF guards, and redaction.

Only scan assets you own or are explicitly authorized to test.

## Status
- Milestones M0–M1 implemented (foundations, crawler, passive checks, PoC). See `job-plan.md` and `test-plan.md`.

## Features (current)
- Async crawler (httpx) with per-host/global concurrency, robots.txt, sitemap, basic link/form discovery
- Passive checks: security headers, cookie flags (Secure/HttpOnly/SameSite), TLS version
- Findings model (Pydantic) with severity, confidence, fingerprint, structured evidence
- Dedupe/merge across sources
- HTML report template with pluggable PDF engine (WeasyPrint or wkhtmltopdf)
- Config loader (YAML) with env interpolation and safety defaults

## Quick Start
1) Setup
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Optionally choose a PDF engine
# pip install weasyprint  # requires system cairo/pango
```
2) Try the test plan (no CLI yet)
```bash
# Follow step-by-step checks
cat test-plan.md
```
3) Example config
```bash
cat configs/example.yml
```

## Project Structure
```
reporting/
  engines.py              # PDF engines (WeasyPrint/wkhtmltopdf)
  templates/report.html   # HTML report template
scanner/
  config.py               # Config schema + loader
  models.py               # Pydantic models (Finding, HTTP request/response, Evidence)
  severity.py             # Severity/confidence mapping and CI policy
  safety.py               # Redaction + SSRF helpers
  utils.py                # Fingerprinting + dedupe
  crawler.py              # Async crawler
  checks/
    headers.py            # Security headers
    cookies.py            # Cookie flags
    tls.py                # TLS version
configs/
  example.yml             # Example configuration
```

## Configuration
- See `configs/example.yml` for scope, safety, reporting engine, and integrations.
- Environment variables are interpolated (e.g., `${ZAP_API_KEY}`).

## Reporting
- Renders HTML via Jinja2 and converts to PDF using the configured engine (WeasyPrint or wkhtmltopdf).
- Findings include severity/confidence, evidence, PoC snippets, and remediation.

## Safety
- Safe mode enabled by default; destructive payloads are disabled unless explicitly allowed.
- Redacts secrets (tokens, passwords, cookies) in logs/artifacts.
- SSRF protections block link-local, RFC1918/4193 ranges, and metadata endpoints.

## Contributing
- Keep changes small and focused; align with `Web-Scanner.md` and `job-plan.md`.
- Update `requirements.txt` as dependencies change.
- Update `test-plan.md` with validation steps after each set.

## License
- MIT
