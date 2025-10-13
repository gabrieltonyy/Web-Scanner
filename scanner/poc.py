from __future__ import annotations

import shlex
from typing import Dict

from .models import HTTPRequest, Evidence
from .safety import redact_text


def curl_from_request(req: HTTPRequest) -> str:
    parts = ["curl", "-i", "-sS", "-X", req.method.upper()]
    for k, v in (req.headers or {}).items():
        red = redact_text(f"{k}: {v}") if req.redacted else f"{k}: {v}"
        parts += ["-H", shlex.quote(red)]
    parts.append(shlex.quote(req.url))
    if req.body:
        body = redact_text(req.body) if req.redacted else req.body
        parts += ["--data-binary", shlex.quote(body)]
    return " ".join(parts)


def requests_snippet(req: HTTPRequest) -> str:
    headers = "{\n" + ",\n".join([f"    '{k}': '{redact_text(v) if req.redacted else v}'" for k, v in (req.headers or {}).items()]) + "\n}"
    body_line = "data = '" + (redact_text(req.body) if (req.body and req.redacted) else (req.body or "")) + "'\n" if req.body else ""
    return (
        "import requests\n"
        f"url = '{req.url}'\n"
        f"headers = {headers}\n"
        f"{body_line}"
        f"resp = requests.request('{req.method.upper()}', url, headers=headers{', data=data' if req.body else ''})\n"
        "print(resp.status_code)\nprint(resp.text[:500])\n"
    )


def make_reflection_evidence(payload: str, context: str | None = None) -> Evidence:
    return Evidence(type="reflection", value=payload, match_context=context, signature=payload)

