# Web-Scanner

A Python-based web vulnerability scanner and reporter, focused on OWASP Top 10 coverage. It crawls a target, runs passive and active checks, can pull in alerts from OWASP ZAP, and produces a professional HTML/PDF report with severity-ranked findings, evidence, and remediation guidance.

> **Only scan assets you own or have explicit written authorization to test.** Running active checks (SQLi/XSS payloads, form fuzzing) against systems you don't have permission for is illegal in most jurisdictions.

---

## Status

Core scan pipeline (crawl → passive checks → active checks → dedupe → report) runs end-to-end via the CLI. Some safety and auth features described below are **declared in config but not yet fully enforced in code** — see [Known Limitations](#known-limitations). Development is tracked phase-by-phase in [`job-plan.md`](job-plan.md); the original design doc is [`Web-Scanner.md`](Web-Scanner.md).

## Features

**Crawling**
- Async crawler (`httpx`) with global + per-host concurrency and rate limiting
- `robots.txt` and `sitemap.xml` aware
- Link and form discovery via BeautifulSoup
- Scope allow/deny by URL prefix

**Passive checks**
- Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Cookie flags (`Secure`, `HttpOnly`, `SameSite`)
- TLS version (flags TLS 1.0/1.1 as obsolete)

**Active checks**
- Reflected XSS (context-aware marker injection)
- SQL injection (error-based pattern matching across common DB engines)
- CSRF (POST forms missing anti-CSRF tokens)

**Findings & reporting**
- Structured findings model (Pydantic): severity, confidence, evidence, fingerprint, PoC, remediation, CWE/OWASP refs
- Fingerprint-based dedupe/merge across sources (core checks + ZAP)
- HTML report via Jinja2, rendered to PDF via WeasyPrint or wkhtmltopdf
- JSON artifacts (`findings.json`, `crawl.json`) per scan run for CI or further processing

**Integrations**
- OWASP ZAP: pulls existing alerts via the ZAP API and merges them into findings (read-only; doesn't yet drive ZAP's active scan)
- Burp Suite: adapter scaffolded, not yet implemented

**CLI**
- `scanner scan -c config.yml` with `--fail-on` severity gating for CI use (non-zero exit code on threshold match)

## Known Limitations

Being upfront about gaps rather than letting the config imply capabilities that aren't there yet:

- **SSRF protection is defined but not enforced.** `scanner/safety.py` has the blocklist logic, but the crawler and active checks don't call it yet — targets that redirect to internal/metadata IPs won't currently be blocked. Tracked in `job-plan.md` Phase 0.
- **`safety.safe_mode` isn't read anywhere yet.** There's currently no way to actually disable active payloads via config.
- **Redaction isn't applied to stored artifacts.** `redact_text()` exists but isn't called when `findings.json` is written, so response headers (including cookies) can be persisted unredacted.
- **No authentication support yet.** `auth` config (cookies/basic/bearer/login script) is defined in the schema but not applied to the scan client — only unauthenticated pages can currently be tested.
- **No test suite yet.**

None of this is meant to gate you from using the tool for early-stage recon on assets you're authorized to test — just know that "safe mode," "SSRF guards," and "auth" aren't load-bearing yet. Full plan and priority order for closing these gaps is in [`job-plan.md`](job-plan.md).

## Quick Start

1. **Setup**
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   # Optional PDF engine (pick one):
   pip install weasyprint   # requires system cairo/pango
   # or install the wkhtmltopdf binary via your OS package manager
   ```

2. **Configure a scan** — copy and edit the example config
   ```bash
   cp configs/example.yml configs/mytarget.yml
   # edit targets, scope, checks, safety, report metadata
   ```

3. **Run it**
   ```bash
   python -m cli.main scan -c configs/mytarget.yml
   ```
   Useful flags:
   ```bash
   python -m cli.main scan -c configs/mytarget.yml --fail-on High
   ```

4. **Check the output** — artifacts land in `artifacts/<timestamp>/`:
   - `crawl.json` — discovered URLs
   - `findings.json` — structured findings
   - `report.html` / `report.pdf` — the rendered report

## Project Structure

```
cli/
  main.py                 # CLI entrypoint (scanner scan -c config.yml)
scanner/
  orchestrator.py         # Ties crawl → checks → dedupe → report together
  crawler.py              # Async crawler
  config.py               # Config schema + YAML loader (env interpolation)
  models.py                # Pydantic models: Finding, HTTPRequest/Response, Evidence
  severity.py              # Severity/confidence ranking, CI fail-on policy, ZAP mapping
  safety.py                 # Redaction patterns + SSRF blocklist helpers
  poc.py                    # curl/requests PoC snippet generation
  utils.py                  # Fingerprinting + finding dedupe/merge
  checks/
    headers.py              # Missing security headers
    cookies.py               # Cookie flag checks
    tls.py                    # TLS version check
    xss.py                     # Reflected XSS
    sqli.py                     # Error-based SQL injection
    csrf.py                      # Missing CSRF tokens on POST forms
integrations/
  zap_adapter.py            # Pull alerts from a running ZAP instance
  burp_adapter.py            # Stub for Burp Suite integration
reporting/
  engines.py                 # PDF rendering (WeasyPrint/wkhtmltopdf)
  templates/report.html      # Report template
configs/
  example.yml                # Example configuration
job-plan.md                   # Priority-ordered improvement roadmap
Web-Scanner.md                 # Original design/architecture doc
```

## Configuration

All scan behavior is driven by a single YAML file — see [`configs/example.yml`](configs/example.yml) for the full reference, covering:

- `targets` / `scope` — seed URLs and include/exclude prefixes
- `auth` — cookies, basic, bearer, or a login script (see [Known Limitations](#known-limitations))
- `crawler` — concurrency, rate limits, robots.txt behavior
- `checks` — toggle individual check categories (`sqli`, `xss`, `csrf`, `misconfig`, `access_control`)
- `safety` — safe mode, redaction, SSRF blocklists
- `integrations` — ZAP/Burp connection details
- `report` — output path, PDF engine, client/assessor metadata for the report cover page
- `ci` — `fail_on` severity threshold for pipeline gating

Environment variables are interpolated with `${VAR_NAME}` syntax (e.g. `${ZAP_API_KEY}`).

## Reporting

Findings render to HTML via Jinja2, then to PDF via your configured engine. Each finding includes severity/confidence, endpoint, affected parameter, evidence, a generated PoC (curl/requests snippet), impact, and remediation guidance. The report also includes a summary table of findings by severity and category.

## Roadmap

See [`job-plan.md`](job-plan.md) for the full priority-ordered plan: safety enforcement (SSRF/safe-mode/redaction), authentication support, bug fixes, a test suite, additional checks (access control, blind SQLi), and eventually a Flask UI with background jobs and live progress.

## Contributing

- Keep changes small and focused; align with `Web-Scanner.md` (design) and `job-plan.md` (current priorities).
- Update `requirements.txt` as dependencies change.
- Add/update tests alongside behavior changes once the test suite lands (Phase 3 of `job-plan.md`).

## License

MIT — see [`LICENSE`](LICENSE).