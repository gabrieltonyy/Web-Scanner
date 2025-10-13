# Web Vulnerability Scanner & Reporter — Implementation Plan

A Python-based tool that automates OWASP Top 10 scanning against web applications. Performs reconnaissance, identifies common vulnerabilities (SQLi, XSS, CSRF, etc.), and generates a professional PDF report with findings and remediation guidance.

Only scan assets you own or have explicit authorization to test.

## Goals & Scope
- Automate reconnaissance, crawling, and targeted security checks focused on OWASP Top 10 categories.
- Classify findings by severity (Critical / High / Medium / Low) using consistent criteria.
- Produce reproducible PoCs and clear remediation guidance per finding.
- Export a professional PDF report with executive summary, methodology, findings, and appendix.
- Provide both a CLI and a simple Flask-based UI for running scans and viewing reports.

## Tech Stack
- Python 3.11+
- Libraries: `httpx` (async) or `requests`, `beautifulsoup4`, `pydantic` (or dataclasses), `PyYAML`, `tqdm`, `tenacity` (retry/backoff)
- Reporting: `Jinja2` (HTML templates) + `WeasyPrint` or `wkhtmltopdf` for HTML→PDF; `reportlab` optional for charts only
- Web/UI: `Flask`, optional `Redis` + `RQ` (or Celery) for background jobs
- Integrations: OWASP ZAP API (`python-owasp-zap-v2.4`), Burp Suite API (optional)
- Optional helpers: `urllib3`, `dnspython`, `cryptography` (TLS inspection)

## High-Level Architecture
- Core packages
  - `scanner/` — orchestration, crawling, checks, findings model, severity/confidence mapping
  - `integrations/` — ZAP and Burp adapters (start/stop, policy, scan, fetch alerts)
  - `reporting/` — HTML templates + PDF engine (WeasyPrint/wkhtmltopdf or ReportLab charts), export of artifacts (JSON/CSV)
  - `web/` — Flask UI for launching scans, viewing status, and downloading reports
  - `jobs/` — background job runner (RQ/Celery), resumable scan state, progress events
  - `cli/` — CLI entrypoint for config-driven runs
- Data flow
  1) Load config and target scope
  2) Recon + crawl → URL/endpoint inventory
  3) Passive checks (headers, cookies) → findings
  4) Active checks per category (SQLi/XSS/etc.) → findings
  5) Integrations (ZAP/Burp) → import alerts as findings
  6) Classify/severity-map → generate PoCs + remediation
  7) Persist artifacts → render PDF

## Core Modules & Responsibilities
- Orchestrator
  - Manage scan stages, timeouts, concurrency (global and per-host), scope filtering, and retries with backoff.
  - Async-friendly core using `httpx` where feasible; thread/process workers acceptable fallback.
  - Respect robots.txt and rate-limits (configurable, `Retry-After` aware), with explicit overrides.
  - Enforce safe mode by default; support resumable scans and partial reruns.
- Target Discovery & Crawling
  - Seed URLs from config; optionally parse sitemap.xml and robots.txt.
  - Crawl HTML forms/links with `httpx + BeautifulSoup` (content-type aware), optionally async.
  - Per-host concurrency + rate limiting; honor scope allowlist/denylist.
  - Optionally delegate spidering to ZAP for dynamic discovery.
- Passive Recon & Baseline Checks
  - HTTP/S headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
  - TLS/crypto footprint (if HTTPS): protocol versions, HSTS presence.
  - Cookie flags: `Secure`, `HttpOnly`, `SameSite`.
- Active Vulnerability Checks (selected OWASP Top 10)
  - Injection (SQLi): parameter fuzzing with error/time-based heuristics; optional sqlmap handoff.
  - XSS (reflected): context-aware payloads; reflection and filtering checks.
  - CSRF: state-changing endpoints without CSRF token or with GET semantics.
  - Authentication/Session: weak password patterns (optionally), session fixation hints, default creds (opt-in), JWT alg/missing claims checks (if applicable).
  - Security Misconfiguration: default pages, directory listing, debug banners, version exposure.
  - Sensitive Data/Transport: mixed content, non-TLS forms, weak headers.
  - Access Control (heuristic): simple IDOR probes for numeric IDs (opt-in, safe mode).
  - Deserialization/SSRF: flag patterns, leave deep exploitation to manual or ZAP.
- PoC Generation
  - Repro steps (curl/requests snippet), payload used, and structured evidence (type, value, match_context, response excerpt, timing deltas, error signatures).
  - Include safety notes for payloads to avoid data loss; redact secrets in PoCs.

## Integrations
- OWASP ZAP
  - Start/connect to ZAP daemon; set API key; configure context/scope; spider and active scan.
  - Pull alerts; map to local categories, severities and confidence; deduplicate with core findings via fingerprint.
- Burp Suite (optional)
  - If Burp API is available: import sitemap/issue list; map severity and confidence; merge provenance.

## Dedupe & Fingerprinting
- Normalize and deduplicate findings by key: `(target, endpoint, method, category, param, fingerprint)`.
- Compute `fingerprint` from stable inputs (e.g., `hash(category|endpoint|param|evidence.signature)`), and track `source` + `source_id` per integration.
- Merge duplicate findings by raising severity/confidence conservatively and unioning references/sources.

## Findings Data Model (Pydantic or dataclass)
```python
from typing import Literal, Optional, List, Dict
from pydantic import BaseModel, Field

Severity = Literal["Critical", "High", "Medium", "Low"]
Confidence = Literal["High", "Medium", "Low"]

class HTTPRequest(BaseModel):
    method: str
    url: str
    headers: Dict[str, str] = {}
    body: Optional[str] = None
    redacted: bool = True  # secrets removed according to policy

class HTTPResponse(BaseModel):
    status: int
    headers: Dict[str, str] = {}
    body_excerpt: Optional[str] = None  # small safe excerpt only

class Evidence(BaseModel):
    type: Literal["reflection", "error", "timing", "header", "pattern", "other"]
    value: str  # e.g., reflected string, error snippet, delta ms
    match_context: Optional[str] = None  # where/how it matched
    signature: Optional[str] = None      # stable signature for fingerprinting
    screenshot_path: Optional[str] = None

class Affects(BaseModel):
    location: Literal["path", "query", "body", "header", "cookie", "other"]
    param: Optional[str] = None

class Finding(BaseModel):
    id: str
    fingerprint: str
    target: str
    endpoint: str
    method: str
    category: str  # e.g., Injection, XSS, CSRF
    title: str
    severity: Severity
    confidence: Confidence = "Medium"
    affects: Affects
    request: HTTPRequest
    response: Optional[HTTPResponse] = None
    evidence: Optional[Evidence] = None
    poc: Optional[str] = None  # code snippet or curl
    remediation: str
    references: List[str] = []
    cwe_id: Optional[str] = None
    owasp: Optional[str] = None
    cvss: Optional[str] = None
    source: Literal["core", "zap", "burp"] = "core"
    source_id: Optional[str] = None
    status: Literal["new", "confirmed", "false_positive", "accepted_risk"] = "new"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: List[str] = []
```

## Configuration (YAML)
```yaml
project: "Acme WebApp"
targets:
  - "https://app.acme.test"
scope:
  include: ["https://app.acme.test"]
  exclude: ["/logout", "/admin/delete*"]
auth:
  method: cookies   # none|basic|cookies|bearer
  cookies: "sessionid=...; csrftoken=..."
  # basic: { username: "", password: "" }
  # bearer: { token: "..." }
  # login_script: path/to/login.py  # optional custom login to fetch cookies
  login_script_timeout: 30
proxies:
  http: "http://127.0.0.1:8080"  # ZAP/Burp
  https: "http://127.0.0.1:8080"
crawler:
  max_pages: 1000
  respect_robots: true
  rate_limit_rps: 2
  per_host_rps: 2
  concurrency_per_host: 4
checks:
  sqli: true
  xss: true
  csrf: true
  misconfig: true
  access_control: false
safety:
  safe_mode: true           # disable destructive payloads
  redact_secrets: true      # redact tokens/passwords in artifacts
  ssrf_protection: true
  blocklist_cidrs:
    - 127.0.0.0/8
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - 169.254.0.0/16
    - ::1/128
    - fc00::/7
    - fe80::/10
  blocklist_hosts:
    - metadata.google.internal
    - 169.254.169.254
integrations:
  zap:
    enabled: true
    api_key: "${ZAP_API_KEY}"
    url: "http://127.0.0.1:8080"
    active_scan: true
    map_confidence: true
  burp:
    enabled: false
report:
  output_dir: "reports"
  filename: "acme-webapp-report.pdf"
  engine: weasyprint        # weasyprint|wkhtmltopdf|reportlab
  template: reporting/templates/report.html
runtime:
  concurrency: 10           # global max tasks
  timeout_seconds: 20
  retries: 2
  backoff: exponential
  honor_retry_after: true
ci:
  fail_on: High             # None|Low|Medium|High|Critical (or list)
ui:
  queue: rq                 # rq|celery|inline
  redis_url: redis://localhost:6379/0
  progress_transport: sse   # sse|websocket|poll
env:
  load_dotenv: true
```

## Severity & Confidence Mapping
- Map both severity and confidence. Align with ZAP/Burp where applicable; otherwise:
  - Severity
    - Critical: direct compromise (RCE, unauthenticated SQLi, auth bypass)
    - High: data exfil, stored XSS, CSRF on sensitive ops
    - Medium: reflected XSS, weak headers with exposure
    - Low: info leaks, missing best-practice headers
  - Confidence
    - High: clear, reproducible evidence (e.g., reflection + execution)
    - Medium: strong indicators (error signatures, partial reflection)
    - Low: heuristic-only or needs manual verification
- Allow org policy overrides via config and CLI (e.g., `--fail-on High`).

## Reporting (HTML → PDF)
- Render report via HTML templates (Jinja2) and convert to PDF (WeasyPrint/wkhtmltopdf). Optional charts via ReportLab or client-side libs rendered to images.
- Sections: Cover, Executive Summary, Methodology, Scope & Assumptions, Findings (by severity), Recommendations, Appendix (artifacts, logs, PoCs).
- Each finding: title, severity/confidence badge, endpoint, parameter, structured evidence, PoC snippet, impact, remediation, references.
- Include summary charts (counts by severity), and indicate redaction status where applicable.

## CLI
- `scanner scan -c config.yml` — runs full scan, writes artifacts and PDF.
- Flags: `--no-zap`, `--only sqli,xss`, `--max-pages 200`, `--out reports/foo.pdf`, `--engine weasyprint`, `--safe-mode/--dangerous`, `--redact-secrets`, `--fail-on High`.
- Exit code: non-zero if threshold matched (e.g., Critical/High) for CI gating.

## Flask UI
- Upload or paste config; start scan as background job queued via RQ/Celery.
- Live progress via SSE/WebSocket; resumable scans with persisted state (artifacts + checkpoints).
- Findings table with filters; download PDF and JSON artifacts (redacted by default, toggle to view sensitive fields if authorized).
- Auth-protect UI if hosted; default to localhost-only.

## Storage & Artifacts
- `artifacts/<timestamp>/` — `findings.json`, `crawl.json`, `zap.json`, `burp.json`, `report.pdf`, `logs.txt`, `screenshots/`.
- Redaction policy applied to requests/responses and logs; maintain `*_raw` only if explicitly enabled and access-controlled.
- Optional SQLite for historical comparisons and trend charts; track `first_seen/last_seen` per fingerprint.

## Performance & Safety
- Respect rate limits; per-host concurrency; backoff on 429/5xx (honor `Retry-After`); user-configurable RPS.
- Safe mode disables destructive payloads; default enabled.
- SSRF protections: block link-local, loopback, RFC1918/4193 ranges, and known metadata endpoints; resolve and re-check DNS on redirects.
- Redact secrets in artifacts/logs (tokens, passwords, cookies); allow configurable patterns.
- Time-box scans per stage; allow resume/partial reruns.

## Testing Strategy
- Unit tests: payload builders, detectors, severity/confidence mapper, report rendering.
- Fixture-based tests for HTML forms, reflection, header checks; property-based tests for payloads.
- Integration tests against DVWA/Juice Shop in Docker Compose; SSRF guard tests using blocked ranges.
- Dedupe/fingerprinting tests: merging from multiple sources; redaction snapshot tests for artifacts and logs.

## Project Structure
```
web-scanner/
  cli/
    __init__.py
    main.py
  scanner/
    __init__.py
    orchestrator.py
    crawler.py
    checks/
      __init__.py
      sqli.py
      xss.py
      csrf.py
      headers.py
      access_control.py
    models.py         # Pydantic models including HTTPRequest/Response, Evidence
    severity.py       # severity & confidence mapping + policy overrides
    utils.py
  integrations/
    __init__.py
    zap_adapter.py
    burp_adapter.py
  reporting/
    __init__.py
    engines.py       # WeasyPrint/wkhtmltopdf/ReportLab bridge
    templates/
      report.html
  jobs/
    __init__.py
    queue.py         # RQ/Celery integration, resumable job state
  web/
    __init__.py
    app.py
  configs/
    example.yml
  artifacts/  (gitignored)
  tests/
    unit/
    integration/
  README.md
```

## Milestones & Deliverables
1) Week 1 — Foundations
   - Repo scaffold, models, config loader, severity mapper, basic PDF shell.
2) Week 2 — Crawl + Passive Checks
   - Crawler, header/cookie/TLS checks, findings JSON, PDF v1.
3) Week 3 — Active Checks
   - SQLi + XSS (reflected), CSRF heuristics, PoC generation.
4) Week 4 — Integrations + UI
   - ZAP adapter, dedupe mapping, Flask UI, PDF v2 (charts), polish.

## Risks & Mitigations
- False positives: include confidence levels, evidence, and reproducible PoCs.
- Scope bleed: strict URL filtering and allowlist; dry-run summary.
- Auth flows: support cookie import and pluggable login scripts.
- Legal exposure: banner + config require explicit confirmation of authorization.

## Setup Prereqs
- Python 3.11+, virtualenv
- Optional: Docker (for test targets), OWASP ZAP installed or Docker image
- Environment vars: `ZAP_API_KEY` (if using ZAP)

## Example Usage
```bash
python -m cli.main scan -c configs/example.yml --out reports/acme.pdf --only sqli,xss --no-zap
```

## Future Enhancements
- Playwright/puppeteer-backed DOM XSS detection and login flows
- CVSS v3 scoring and SARIF export
- HTML report + PDF conversion pipeline
- Differential scans and regression gating (CI)
