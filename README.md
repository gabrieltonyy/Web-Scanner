# Web-Scanner

Web-Scanner is a Python-based web vulnerability scanner and reporter focused on selected OWASP Top 10 checks. It crawls an authorized target, runs passive and active checks, imports existing OWASP ZAP alerts, and writes severity-ranked HTML/PDF and JSON artifacts.

> **Only scan systems you own or are explicitly authorized to test.** Active SQLi and XSS probes can affect target behavior.

## Current status

The CLI scan pipeline is implemented: crawl → passive checks → active checks → deduplication → artifacts/report. Phase 0 safety integrity work is also implemented:

- DNS-aware SSRF blocklists are applied to crawler, passive, and active GET requests.
- Redirects are followed manually and checked at every hop before a request is sent.
- Safe mode is enabled by default and restricts SQLi to minimal quote probes.
- `--dangerous` explicitly disables safe mode and enables the full current SQLi probe set.
- Sensitive values are redacted from findings before JSON and report rendering when `safety.redact_secrets` is enabled.
- Header, cookie, and TLS findings honor `checks.misconfig`.

The project still has no committed automated test suite. Authentication, proxy routing, retries/backoff, active ZAP scanning, Burp import, access-control checks, and several configuration options remain incomplete or unwired.

## Features

### Crawling and scope

- Async `httpx` crawler with global and per-host concurrency controls.
- Link and form-action discovery through BeautifulSoup.
- `robots.txt`, `sitemap.xml`, URL include, and exclude support.
- Per-host request-rate limiting.
- SSRF protection for configured CIDRs/hosts, including redirect destinations.

### Checks

- Security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- Cookie flags: Secure, HttpOnly, and SameSite.
- TLS version heuristic for obsolete TLS 1.0/1.1.
- CSRF heuristic for POST forms without recognized anti-CSRF fields.
- Reflected-XSS marker injection.
- Error-based SQL injection detection.

### Findings and reporting

- Pydantic finding model with severity, confidence, evidence, remediation, references, and fingerprints.
- Fingerprint-based deduplication/merge across core checks and ZAP alerts.
- `crawl.json`, `findings.json`, and HTML report artifacts per run.
- Optional PDF rendering through WeasyPrint or wkhtmltopdf.
- Pattern-based redaction for common bearer tokens, API keys, passwords, tokens, sessions, and CSRF cookies.

### Integrations and CLI

- OWASP ZAP adapter imports existing alerts via its API; it does not initiate a ZAP active scan.
- Burp Suite adapter is a placeholder.
- CI-style failure threshold via `--fail-on`.
- Explicit safe-mode override via `--dangerous`, with a stderr warning.

## Quick start

1. Create an environment and install dependencies:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

   For PDF output, install either WeasyPrint (plus its system libraries) or the `wkhtmltopdf` binary.

2. Create a target configuration:

   ```bash
   cp configs/example.yml configs/mytarget.yml
   ```

   Edit the target, scope, check selection, safety policy, and report metadata before scanning.

3. Run an authorized scan:

   ```bash
   python -m cli.main scan -c configs/mytarget.yml
   ```

   Useful options:

   ```bash
   python -m cli.main scan -c configs/mytarget.yml --fail-on High
   python -m cli.main scan -c configs/mytarget.yml --dangerous
   ```

4. Review output in `artifacts/<timestamp>/`:

   - `crawl.json` — crawled URLs
   - `findings.json` — deduplicated structured findings
   - `report.html` — rendered report
   - `report.pdf` — created when the selected PDF engine is available

## Configuration

Use [configs/example.yml](configs/example.yml) as the configuration reference.

- `targets` and `scope` define scan seeds and URL boundaries.
- `crawler` sets crawl limits, robots behavior, and per-host limits.
- `checks` enables SQLi, XSS, CSRF, and misconfiguration categories.
- `safety` controls safe mode, artifact redaction, SSRF protection, and CIDR/host blocklists.
- `integrations.zap` controls read-only alert import from an existing ZAP instance.
- `report` provides report metadata and PDF engine selection.
- `ci.fail_on` sets the default CI severity threshold.

`${VAR_NAME}` values in YAML are interpolated from the environment. Some schema fields (`auth`, `proxies`, global rate limits, retry/backoff, UI settings, and ZAP `active_scan`) are reserved for future implementation and do not currently change runtime behavior.

## Safety behavior

SSRF protection is enabled by default. The scanner resolves hostnames and rejects configured internal/metadata addresses before requesting the initial URL or any redirect target. The default policy blocks loopback, private, link-local, unique-local IPv6, and selected cloud metadata hosts. A blocked crawler/check URL is skipped and logged.

Safe mode is enabled by default. It retains minimal SQLi quote probes and the benign reflected-XSS marker, while `--dangerous` enables the broader current SQLi payload set. Artifact redaction is enabled by default; it is pattern-based, so review any additional secret formats relevant to your environment.

## Project layout

```text
cli/
  main.py                 # CLI entry point
scanner/
  orchestrator.py         # Crawl/check/report pipeline and policy wiring
  crawler.py              # Async crawling and guarded redirects
  safety.py               # SSRF guard and secret-redaction patterns
  config.py               # YAML/Pydantic configuration schema
  models.py               # Finding and HTTP evidence models
  poc.py                  # PoC rendering and header redaction helpers
  severity.py             # Severity/confidence and CI policy
  utils.py                # Fingerprinting and finding merge logic
  checks/                 # Header, cookie, TLS, CSRF, XSS, and SQLi checks
integrations/
  zap_adapter.py          # Existing ZAP alert import
  burp_adapter.py         # Burp placeholder
reporting/
  engines.py              # PDF engine adapter
  templates/report.html   # HTML report template
configs/
  example.yml             # Example scan configuration
```

## Repository hygiene

Generated bytecode, virtual environments, scan artifacts, reports, editor files, local/private configuration, and local planning or workflow documents are ignored by Git. The local workflow and planning documents are intentionally not part of the repository's tracked documentation.

## Contributing

- Keep changes focused and preserve authorization/safety defaults.
- Update `requirements.txt` when runtime dependencies change.
- Add automated tests with behavior changes; a committed test suite is still needed.
- Keep this README synchronized with actual runtime behavior and supported configuration.

## License

MIT — see [LICENSE](LICENSE).
