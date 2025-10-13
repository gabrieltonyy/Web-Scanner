from __future__ import annotations

import ipaddress
import re
from typing import Iterable


DEFAULT_REDACTION_PATTERNS = [
    re.compile(r"(Authorization:\s*Bearer\s+)[A-Za-z0-9\-_.~+/=]+", re.IGNORECASE),
    re.compile(r"(Api[- ]?Key:\s*)[A-Za-z0-9\-_.~+/=]+", re.IGNORECASE),
    re.compile(r"(Password=)[^;&\s]+", re.IGNORECASE),
    re.compile(r"(token=)[^;&\s]+", re.IGNORECASE),
    re.compile(r"(session(id)?=)[^;&\s]+", re.IGNORECASE),
    re.compile(r"(csrftoken=)[^;&\s]+", re.IGNORECASE),
]


def redact_text(text: str, replacement: str = "<redacted>") -> str:
    redacted = text
    for pat in DEFAULT_REDACTION_PATTERNS:
        redacted = pat.sub(lambda m: m.group(1) + replacement, redacted)
    return redacted


def is_ip_blocked(ip: str, cidr_blocks: Iterable[str]) -> bool:
    ip_obj = ipaddress.ip_address(ip)
    for block in cidr_blocks:
        try:
            net = ipaddress.ip_network(block, strict=False)
        except ValueError:
            continue
        if ip_obj in net:
            return True
    return False


def is_url_blocked(target_host_ip: str, blocklist_cidrs: Iterable[str], blocklist_hosts: Iterable[str], hostname: str | None = None) -> bool:
    if is_ip_blocked(target_host_ip, blocklist_cidrs):
        return True
    if hostname:
        hn = hostname.lower()
        for h in blocklist_hosts:
            if hn == h.lower():
                return True
    return False

