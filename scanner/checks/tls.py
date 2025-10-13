from __future__ import annotations

import socket
import ssl
from urllib.parse import urlparse
from typing import List

from ..models import Affects, Finding, HTTPRequest, HTTPResponse


def check_tls_version(url: str, response_headers: dict) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        return findings

    host = parsed.hostname or ""
    port = parsed.port or 443

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version() or "unknown"
    except Exception:
        # If TLS check fails, do not generate a finding; network may block.
        return findings

    if version in {"TLSv1", "TLSv1.1"}:
        sev = "High" if version == "TLSv1" else "Medium"
        fid = f"tls:obsolete:{version}"
        findings.append(
            Finding(
                id=fid,
                fingerprint=fid,
                target=url,
                endpoint=url,
                method="GET",
                category="Cryptographic Issues",
                title=f"Obsolete TLS version negotiated: {version}",
                severity=sev,  # type: ignore[arg-type]
                affects=Affects(location="header", param="Strict-Transport-Security"),
                request=HTTPRequest(method="GET", url=url, headers={}, body=None, redacted=True),
                response=HTTPResponse(status=200, headers=response_headers, body_excerpt=None),
                evidence=None,
                remediation="Disable TLS 1.0/1.1 and require TLS 1.2+.",
                references=["https://datatracker.ietf.org/doc/rfc8996/"],
            )
        )

    return findings

