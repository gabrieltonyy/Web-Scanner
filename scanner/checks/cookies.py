from __future__ import annotations

from typing import List, Dict

from ..models import Affects, Finding, HTTPRequest, HTTPResponse


def _split_set_cookie(raw: str) -> List[str]:
    # Very basic splitting: assumes each Set-Cookie on separate header line.
    # If concatenated, try to split on '\n'. Avoid naive comma-splitting due to Expires.
    parts = [p.strip() for p in raw.split("\n") if p.strip()]
    if parts:
        return parts
    return [raw]


def check_cookie_flags(url: str, response_headers: Dict[str, str], https: bool = True) -> List[Finding]:
    findings: List[Finding] = []
    set_cookie = None
    for k, v in response_headers.items():
        if k.lower() == "set-cookie":
            set_cookie = v
            break
    if not set_cookie:
        return findings

    cookies = _split_set_cookie(set_cookie)
    for i, c in enumerate(cookies):
        lower = c.lower()
        name = c.split("=", 1)[0].strip()
        # Missing Secure on HTTPS
        if https and "secure" not in lower:
            fid = f"cookie:{name}:Secure"
            findings.append(
                Finding(
                    id=fid,
                    fingerprint=fid,
                    target=url,
                    endpoint=url,
                    method="GET",
                    category="Sensitive Data Exposure",
                    title=f"Cookie missing Secure flag: {name}",
                    severity="Medium",
                    affects=Affects(location="cookie", param=name),
                    request=HTTPRequest(method="GET", url=url, headers={}, body=None, redacted=True),
                    response=HTTPResponse(status=200, headers=response_headers, body_excerpt=None),
                    evidence=None,
                    remediation="Mark sensitive cookies with the Secure attribute to restrict transmission to HTTPS only.",
                    references=[],
                )
            )
        if "httponly" not in lower:
            fid = f"cookie:{name}:HttpOnly"
            findings.append(
                Finding(
                    id=fid,
                    fingerprint=fid,
                    target=url,
                    endpoint=url,
                    method="GET",
                    category="Sensitive Data Exposure",
                    title=f"Cookie missing HttpOnly flag: {name}",
                    severity="Medium",
                    affects=Affects(location="cookie", param=name),
                    request=HTTPRequest(method="GET", url=url, headers={}, body=None, redacted=True),
                    response=HTTPResponse(status=200, headers=response_headers, body_excerpt=None),
                    evidence=None,
                    remediation="Mark cookies with the HttpOnly attribute to mitigate client-side script access.",
                    references=[],
                )
            )
        if "samesite" not in lower:
            fid = f"cookie:{name}:SameSite"
            findings.append(
                Finding(
                    id=fid,
                    fingerprint=fid,
                    target=url,
                    endpoint=url,
                    method="GET",
                    category="Sensitive Data Exposure",
                    title=f"Cookie missing SameSite attribute: {name}",
                    severity="Low",
                    affects=Affects(location="cookie", param=name),
                    request=HTTPRequest(method="GET", url=url, headers={}, body=None, redacted=True),
                    response=HTTPResponse(status=200, headers=response_headers, body_excerpt=None),
                    evidence=None,
                    remediation="Set SameSite=Lax or Strict on cookies to reduce CSRF risk.",
                    references=[],
                )
            )

    return findings

