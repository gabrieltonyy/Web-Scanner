from __future__ import annotations

import asyncio
import re
from typing import List, Optional
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

import httpx

from ..models import Affects, Evidence, Finding, HTTPRequest, HTTPResponse
from ..safety import SSRFGuard


SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\):",
    r"postgresql.*error",
    r"sql syntax.*mysql",
    r"ora-\d+",
    r"sqlite_error",
    r"system\.data\.oledb",
    r"odbc sql server driver",
    r"microsoft odbc",
    r"pdoexception",
]
SQL_ERROR_RE = re.compile(r"|".join(SQL_ERRORS), re.IGNORECASE | re.DOTALL)


def _inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q[param] = value
    query = urlencode(q, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))


async def check_sqli(
    url: str,
    client: httpx.AsyncClient,
    safe_mode: bool = True,
    ssrf_guard: Optional[SSRFGuard] = None,
) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if not params:
        return findings

    # The single-character probes are sufficient for the error-based detector
    # and avoid SQL comment / expression syntax in safe mode.
    payloads = ["'", '"'] if safe_mode else ["'", '"', "')", '")', "'--", '"--']

    for name in params.keys():
        for payload in payloads:
            test_url = _inject_param(url, name, params[name] + payload if params[name] else payload)
            r = await ssrf_guard.get(client, test_url) if ssrf_guard else await client.get(test_url)
            body = r.text or ""
            if SQL_ERROR_RE.search(body):
                snippet = body[:500]
                fid = f"sqli:{name}:{parsed.path}"
                findings.append(
                    Finding(
                        id=fid,
                        fingerprint=fid,
                        target=f"{parsed.scheme}://{parsed.netloc}",
                        endpoint=parsed.path or "/",
                        method="GET",
                        category="Injection",
                        title=f"Possible SQL injection via parameter '{name}'",
                        severity="High",
                        affects=Affects(location="query", param=name),
                        request=HTTPRequest(method="GET", url=test_url, headers={}, body=None, redacted=True),
                        response=HTTPResponse(status=r.status_code, headers=dict(r.headers), body_excerpt=None),
                        evidence=Evidence(type="error", value="SQL error pattern detected", match_context=snippet, signature="sql-error"),
                        remediation="Use parameterized queries / prepared statements. Validate and sanitize inputs. Avoid building SQL with string concatenation.",
                        references=["https://owasp.org/www-community/attacks/SQL_Injection"]
                    )
                )
                break
    return findings
