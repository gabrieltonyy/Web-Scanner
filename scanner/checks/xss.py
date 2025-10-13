from __future__ import annotations

import asyncio
import html
import re
from typing import Dict, List, Tuple
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

import httpx

from ..models import Affects, Evidence, Finding, HTTPRequest, HTTPResponse


def _inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q[param] = value
    query = urlencode(q, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))


async def check_reflected_xss(url: str, client: httpx.AsyncClient, https: bool = False) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if not params:
        return findings

    for name in params.keys():
        marker = f"<xss-{name}-123>"
        test_url = _inject_param(url, name, marker)
        r = await client.get(test_url)
        ctype = r.headers.get("content-type", "").lower()
        if "html" not in ctype:
            # still check but deprioritize
            pass
        body = r.text or ""
        if marker in body:
            # Capture small context
            start = max(0, body.find(marker) - 40)
            end = min(len(body), body.find(marker) + len(marker) + 40)
            context = body[start:end]
            fid = f"xss:{name}:{parsed.path}"
            findings.append(
                Finding(
                    id=fid,
                    fingerprint=fid,
                    target=f"{parsed.scheme}://{parsed.netloc}",
                    endpoint=parsed.path or "/",
                    method="GET",
                    category="XSS",
                    title=f"Reflected XSS via parameter '{name}'",
                    severity="Medium",
                    affects=Affects(location="query", param=name),
                    request=HTTPRequest(method="GET", url=test_url, headers={}, body=None, redacted=True),
                    response=HTTPResponse(status=r.status_code, headers=dict(r.headers), body_excerpt=None),
                    evidence=Evidence(type="reflection", value=marker, match_context=context, signature=marker),
                    remediation=(
                        "Properly encode untrusted input in HTML (escape <, >, \", ', /). "
                        "Use template autoescaping and a strict Content-Security-Policy."
                    ),
                    references=["https://owasp.org/www-community/attacks/xss/"]
                )
            )
    return findings
