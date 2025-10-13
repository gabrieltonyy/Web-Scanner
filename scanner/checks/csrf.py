from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from ..models import Affects, Evidence, Finding, HTTPRequest, HTTPResponse


TOKEN_NAMES = {
    "csrf",
    "csrfmiddlewaretoken",
    "_csrf",
    "csrf_token",
    "xsrf",
    "x_csrf_token",
    "__requestverificationtoken",
    "authenticity_token",
}


def check_csrf_forms(url: str, html_text: str, response_headers: dict) -> List[Finding]:
    findings: List[Finding] = []
    soup = BeautifulSoup(html_text, "html.parser")
    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()
        # Heuristic: focus on POST forms (state-changing). Optionally, flag GET with caution.
        if method != "post":
            continue
        # Look for hidden inputs or any field that appears to be a CSRF token
        has_token = False
        for inp in form.find_all("input"):
            name = (inp.get("name") or "").lower()
            if any(t in name for t in TOKEN_NAMES):
                has_token = True
                break
        if not has_token:
            parsed = urlparse(url)
            fid = f"csrf:{parsed.path}"
            findings.append(
                Finding(
                    id=fid,
                    fingerprint=fid,
                    target=f"{parsed.scheme}://{parsed.netloc}",
                    endpoint=parsed.path or "/",
                    method=method.upper(),
                    category="CSRF",
                    title="Potential CSRF: POST form missing anti-CSRF token",
                    severity="Medium",
                    affects=Affects(location="body", param=None),
                    request=HTTPRequest(method="GET", url=url, headers={}, body=None, redacted=True),
                    response=HTTPResponse(status=200, headers=response_headers, body_excerpt=None),
                    evidence=Evidence(type="pattern", value="form without CSRF token", match_context=str(form)[:400]),
                    remediation=(
                        "Include an anti-CSRF token in state-changing forms and validate it server-side. "
                        "Ensure tokens are unique per session/request."
                    ),
                    references=["https://owasp.org/www-community/attacks/csrf"]
                )
            )
    return findings

