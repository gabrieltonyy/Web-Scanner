from __future__ import annotations

from typing import List

from ..models import Affects, Finding, HTTPRequest, HTTPResponse


MISSING_HEADER_SEVERITY = {
    "Content-Security-Policy": "Medium",
    "Strict-Transport-Security": "Medium",
    "X-Frame-Options": "Low",
    "X-Content-Type-Options": "Low",
    "Referrer-Policy": "Low",
    "Permissions-Policy": "Low",
}


def check_security_headers(url: str, response_headers: dict) -> List[Finding]:
    findings: List[Finding] = []
    present = {k.lower() for k in response_headers.keys()}
    for header, sev in MISSING_HEADER_SEVERITY.items():
        if header.lower() not in present:
            fid = f"headers:{header}"
            findings.append(
                Finding(
                    id=fid,
                    fingerprint=fid,
                    target=url,
                    endpoint=url,
                    method="GET",
                    category="Security Misconfiguration",
                    title=f"Missing security header: {header}",
                    severity=sev,  # type: ignore[arg-type]
                    affects=Affects(location="header", param=header),
                    request=HTTPRequest(method="GET", url=url, headers={}, body=None, redacted=True),
                    response=HTTPResponse(status=200, headers=response_headers, body_excerpt=None),
                    evidence=None,
                    remediation=f"Set the {header} header to an appropriate value.",
                    references=[],
                )
            )
    return findings

