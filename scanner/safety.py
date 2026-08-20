from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from typing import Dict, Iterable, List, Optional
from urllib.parse import urljoin, urlparse

import httpx


DEFAULT_REDACTION_PATTERNS = [
    re.compile(r"(Authorization:\s*Bearer\s+)[A-Za-z0-9\-_.~+/=]+", re.IGNORECASE),
    re.compile(r"(Api[- ]?Key:\s*)[A-Za-z0-9\-_.~+/=]+", re.IGNORECASE),
    re.compile(r"(Password=)[^;&\s]+", re.IGNORECASE),
    re.compile(r"(token=)[^;&\s]+", re.IGNORECASE),
    re.compile(r"(session(id)?=)[^;&\s]+", re.IGNORECASE),
    re.compile(r"(csrftoken=)[^;&\s]+", re.IGNORECASE),
]

DEFAULT_BLOCKLIST_CIDRS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]
DEFAULT_BLOCKLIST_HOSTS = ["metadata.google.internal", "169.254.169.254"]


class SSRFBlocked(Exception):
    """Raised when a URL's host or resolved address violates the SSRF policy."""

    def __init__(self, url: str, reason: str = "blocked by SSRF policy"):
        self.url = url
        self.reason = reason
        super().__init__(f"{reason}: {url}")


class SSRFGuard:
    """Resolve and validate request URLs, including every redirect destination."""

    def __init__(
        self,
        enabled: bool = True,
        blocklist_cidrs: Optional[Iterable[str]] = None,
        blocklist_hosts: Optional[Iterable[str]] = None,
    ):
        self.enabled = enabled
        self.blocklist_cidrs = list(DEFAULT_BLOCKLIST_CIDRS if blocklist_cidrs is None else blocklist_cidrs)
        self.blocklist_hosts = list(DEFAULT_BLOCKLIST_HOSTS if blocklist_hosts is None else blocklist_hosts)
        self._dns_cache: Dict[str, List[str]] = {}

    async def _resolve(self, hostname: str) -> List[str]:
        if hostname in self._dns_cache:
            return self._dns_cache[hostname]
        ips: List[str] = []
        try:
            infos = await asyncio.to_thread(socket.getaddrinfo, hostname, None)
            ips = sorted({info[4][0] for info in infos})
        except OSError:
            pass
        self._dns_cache[hostname] = ips
        return ips

    async def check(self, url: str) -> None:
        if not self.enabled:
            return
        hostname = urlparse(url).hostname
        if not hostname:
            return
        if hostname.lower() in {host.lower() for host in self.blocklist_hosts}:
            raise SSRFBlocked(url, "hostname is blocked by SSRF policy")
        for ip in await self._resolve(hostname):
            if is_url_blocked(ip, self.blocklist_cidrs, self.blocklist_hosts, hostname=hostname):
                raise SSRFBlocked(url, f"resolved address {ip} is blocked by SSRF policy")

    async def get(
        self,
        client: httpx.AsyncClient,
        url: str,
        max_redirects: int = 5,
    ) -> httpx.Response:
        """GET a URL while validating each destination before it is requested."""
        current = url
        for _ in range(max_redirects + 1):
            await self.check(current)
            response = await client.get(current, follow_redirects=False)
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response
            location = response.headers.get("Location")
            if not location:
                return response
            current = urljoin(current, location)
        return response


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
