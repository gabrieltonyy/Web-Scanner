# Phase 0 Handover — Safety Integrity

## Summary

Before Phase 0, safety settings existed in the configuration but were not consistently used in the request paths. Redirects could be followed automatically, active checks bypassed crawler safeguards, safe mode had no effect, findings were written without artifact redaction, and passive misconfiguration checks ignored their configuration switch.

Phase 0 now enforces a shared DNS-aware SSRF policy for crawler, passive, and active GET requests; applies a constrained SQLi payload set in safe mode; adds an explicit `--dangerous` override; redacts findings before JSON and report rendering; and respects `checks.misconfig`. No Phase 1+ work was undertaken. The existing uncommitted README change was preserved and not edited as part of this phase.

## Task 0.1 — SSRF enforcement in the crawler

- **Files changed:** `scanner/crawler.py`, `scanner/safety.py`
- **What changed:** `Crawler` accepts SSRF configuration, disables automatic redirect following, validates each URL before requesting it, manually follows redirects up to five hops, and skips/logs URLs blocked during crawl. Sitemap requests now use the guarded crawler fetch path; robots root URLs are checked before `robotparser` reads them.
- **Key additions:**
  - `SSRFGuard` — shared DNS-caching URL policy object.
  - `SSRFGuard._resolve()` — asynchronous `socket.getaddrinfo` lookup with per-host cache.
  - `SSRFGuard.check()` — validates a hostname and every resolved IP against configured/default blocklists.
  - `Crawler._check_ssrf()` — crawler adapter to the shared guard.
  - `SSRFBlocked` — exception carrying the rejected URL and reason.
- **Deviations from spec:** The shared guard was placed in `scanner/safety.py`, rather than leaving duplicate DNS/check implementations in crawler and active checks. This is the prompt's preferred shared-path design.
- **How it was tested:** A `httpx.MockTransport` returned a redirect from `public.example` to an address resolved as `127.0.0.1`. The guard raised `SSRFBlocked`, and the call log contained only the public URL. A separate default-policy check confirmed `http://127.0.0.1/` is rejected.
- **Known limitations / follow-ups:** DNS is cached for the life of a scanner instance. This satisfies repeat-request efficiency but does not re-resolve a hostname at every redirect/request, so DNS rebinding resistance beyond the cached resolution should be considered in a future hardening pass.

## Task 0.2 — SSRF enforcement in active checks

- **Files changed:** `scanner/checks/sqli.py`, `scanner/checks/xss.py`, `scanner/orchestrator.py`, `scanner/safety.py`
- **What changed:** SQLi and reflected-XSS checks accept an optional `SSRFGuard`; the orchestrator supplies its configured guard to both. Guarded requests disable `httpx` automatic redirects and validate every redirect hop before the next request. Passive requests use the same guard as well, so their redirect behavior cannot bypass the policy.
- **Key additions:**
  - `SSRFGuard.get()` — redirect-aware guarded GET helper used by active and passive requests.
  - `ssrf_guard` optional keyword argument on `check_sqli()` and `check_reflected_xss()` for backwards-compatible direct callers.
- **Deviations from spec:** Direct third-party callers that omit `ssrf_guard` retain their prior raw-client behavior for API compatibility. All scanner-managed active requests provide the guard. Callers integrating these checks independently should supply a configured guard.
- **How it was tested:** Mocked SQLi and XSS requests were made to a public URL that responded with an internal redirect. Both checks raised `SSRFBlocked`; neither made an internal request.
- **Known limitations / follow-ups:** The checks only issue GET requests today. If later checks add POST/other methods, they must use a guarded equivalent rather than raw `httpx` calls.

## Task 0.3 — safe_mode enforcement

- **Files changed:** `scanner/checks/sqli.py`, `scanner/orchestrator.py`, `cli/main.py`
- **What changed:** Safe mode now limits error-based SQLi to two single-quote probes. With safe mode disabled, the existing fuller set of six probes (including comment/expression-style syntax) is enabled. `run_scan()` supports a per-run dangerous override, and `scanner scan --dangerous` disables safe mode and writes a visible stderr warning.
- **Key additions:**
  - `safe_mode` keyword argument on `check_sqli()`.
  - `dangerous` keyword argument on `run_scan()`.
  - `--dangerous` CLI argument and warning.
- **Deviations from spec:** Reflected XSS has only a benign marker-reflection probe, not a state-changing payload set, so it remains enabled in both modes. SQLi comment/expression probes were classified as the extra-risk payload class already present in the repository.
- **How it was tested:** With a mocked HTTP client, safe mode issued two SQLi requests and dangerous mode issued six. `python -m cli.main scan --help` confirms `--dangerous` is exposed with its description.
- **Known limitations / follow-ups:** The current payload classes are modest GET probes; future active checks must explicitly classify their payloads for safe mode rather than assuming this SQLi policy applies automatically.

## Task 0.4 — Redaction on stored artifacts

- **Files changed:** `scanner/orchestrator.py`, `scanner/poc.py`
- **What changed:** Before `findings.json` is written, the orchestrator redacts request/response headers, request body, response body excerpt, evidence match context, and stored PoC text when `cfg.safety.redact_secrets` is enabled. The same finding instances are then rendered into the report, so report evidence is redacted too. Request `redacted` is now set only when a request header/body value actually changed during redaction.
- **Key additions:**
  - `redact_headers()` — preserves header field names while applying existing text redaction rules to their values.
  - `Orchestrator._redact_findings()` — centralized, in-place report/artifact redaction.
- **Deviations from spec:** The repository's `HTTPRequest.redacted` field is a request-level flag rather than a `Finding`-level field. It is therefore updated based on actual request redaction; response/evidence changes are still applied but have no corresponding model flag.
- **How it was tested:** A synthetic finding containing Authorization, Set-Cookie, request body, response excerpt, evidence context, and PoC secrets was redacted. Assertions confirmed none of the raw secret values remained in the serialized finding and the request flag was true.
- **Known limitations / follow-ups:** Redaction is pattern-based and only covers the existing patterns in `scanner/safety.py`. It should be extended as new credential formats or artifact fields are introduced.

## Task 0.5 — Gate misconfig checks

- **Files changed:** `scanner/orchestrator.py`
- **What changed:** Header, cookie, and TLS checks run only when `cfg.checks.misconfig` is true. CSRF form checking is also explicitly gated by `cfg.checks.csrf`, matching the category configuration behavior.
- **Key additions:** No new public APIs; dispatch is controlled in `Orchestrator.passive_checks_for()`.
- **Deviations from spec:** Added the missing CSRF config guard while working in the same dispatch function; this corrects the analogous existing config inconsistency without adding a new feature.
- **How it was tested:** A mocked HTML response with `misconfig: false` and `csrf: false` produced zero passive findings.
- **Known limitations / follow-ups:** This verifies the dispatch condition with mocked responses. A full fixture suite remains Phase 3 work.

## Full file change list

- `scanner/safety.py` — shared default blocklists, asynchronous DNS cache, SSRF exception, and redirect-aware guard.
- `scanner/crawler.py` — SSRF-configured crawler requests, manual redirect checks, guarded sitemap/robots access, and blocked-URL logging.
- `scanner/checks/sqli.py` — guarded injected requests and safe/full payload selection.
- `scanner/checks/xss.py` — guarded injected requests.
- `scanner/orchestrator.py` — policy wiring, passive request guard, safe-mode dispatch, artifact/report redaction, and misconfiguration gating.
- `scanner/poc.py` — reusable header redaction helper.
- `cli/main.py` — explicit `--dangerous` override and warning.
- `randover.md` — this Phase 0 handover.

## Open questions for review

- Confirm that SQL comment/expression probes are the desired threshold for the `--dangerous` SQLi payload set. The existing scanner had no prior payload-risk taxonomy.
- Decide whether direct public use of `check_sqli()` / `check_reflected_xss()` should require an SSRF guard in a future breaking API change. They remain optional solely for backward compatibility.
- The README's existing “Known Limitations” text still says Phase 0 capabilities are absent. It was already an uncommitted user edit and was intentionally left untouched under the Phase 0 prompt's file-scope rule; it should be updated in a documentation-focused follow-up.

## Test/verification log

- `python -m py_compile scanner/crawler.py` — passed.
- Mock crawler redirect test — passed; only the public hop was requested.
- `python -m py_compile scanner/safety.py scanner/crawler.py scanner/checks/sqli.py` — passed.
- Shared guard redirect test — passed; internal redirect was blocked before request.
- `python -m py_compile scanner/checks/xss.py` — passed.
- Mock active SQLi/XSS redirect test — passed; neither check requested the internal URL.
- `python -m py_compile scanner/poc.py` — passed.
- Mock header redaction test — passed.
- `python -m py_compile scanner/orchestrator.py` — passed.
- Synthetic finding artifact-redaction test — passed.
- `python -m py_compile cli/main.py scanner/orchestrator.py scanner/checks/sqli.py scanner/checks/xss.py scanner/safety.py scanner/crawler.py scanner/poc.py` — passed.
- `python -m cli.main scan --help` — passed; `--dangerous` listed.
- Mock safe-mode payload-count and disabled-misconfiguration tests — passed (2 versus 6 SQLi requests; zero passive misconfiguration findings when disabled).
- `python -m compileall -q cli scanner integrations reporting` and `git diff --check` were run as final validation. No live scan was run: no authorized remote target was provided, and the default SSRF policy intentionally blocks loopback/local targets.
