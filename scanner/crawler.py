from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from urllib.parse import urljoin, urlparse
import urllib.robotparser as robotparser
from typing import Dict, Iterable, List, Optional, Set
import xml.etree.ElementTree as ET

import httpx
from bs4 import BeautifulSoup

from .safety import SSRFBlocked, SSRFGuard


logger = logging.getLogger(__name__)


class Crawler:
    """Async crawler with per-host concurrency, robots.txt, sitemap, and simple link discovery."""

    def __init__(
        self,
        concurrency: int = 10,
        concurrency_per_host: int = 4,
        timeout: float = 20.0,
        per_host_rps: float = 2.0,
        respect_robots: bool = True,
        ssrf_protection: bool = True,
        blocklist_cidrs: Optional[List[str]] = None,
        blocklist_hosts: Optional[List[str]] = None,
    ):
        # follow_redirects is intentionally False: redirects are followed manually
        # in fetch() so each hop can be checked against the SSRF blocklist before
        # the request is made.
        self._client = httpx.AsyncClient(follow_redirects=False, timeout=timeout)
        self._global_sem = asyncio.Semaphore(concurrency)
        self._concurrency_per_host = concurrency_per_host
        self._host_sems: Dict[str, asyncio.Semaphore] = {}
        self._robots: Dict[str, robotparser.RobotFileParser] = {}
        self._host_last_at: Dict[str, float] = {}
        self._per_host_interval = 1.0 / per_host_rps if per_host_rps > 0 else 0.0
        self._respect_robots = respect_robots
        self._ssrf_guard = SSRFGuard(
            enabled=ssrf_protection,
            blocklist_cidrs=blocklist_cidrs,
            blocklist_hosts=blocklist_hosts,
        )

    async def close(self):
        await self._client.aclose()

    def _host_sem(self, host: str, concurrency_per_host: int) -> asyncio.Semaphore:
        if host not in self._host_sems:
            self._host_sems[host] = asyncio.Semaphore(concurrency_per_host)
        return self._host_sems[host]

    async def _robots_for(self, base: str) -> robotparser.RobotFileParser:
        parsed = urlparse(base)
        root = f"{parsed.scheme}://{parsed.netloc}/"
        if root in self._robots:
            return self._robots[root]
        await self._check_ssrf(root)
        rp = robotparser.RobotFileParser()
        rp.set_url(urljoin(root, "robots.txt"))
        with contextlib.suppress(Exception):
            rp.read()
        self._robots[root] = rp
        return rp

    async def allowed(self, url: str, user_agent: str = "web-scanner") -> bool:
        if not self._respect_robots:
            return True
        rp = await self._robots_for(url)
        with contextlib.suppress(Exception):
            return rp.can_fetch(user_agent, url)
        return True

    @staticmethod
    def in_scope(url: str, include_prefixes: Iterable[str], exclude_prefixes: Iterable[str]) -> bool:
        u = url.strip()
        if any(u.startswith(x) for x in exclude_prefixes):
            return False
        if not include_prefixes:
            return True
        return any(u.startswith(x) for x in include_prefixes)

    async def _wait_for_rps(self, host: str) -> None:
        if self._per_host_interval <= 0:
            return
        last = self._host_last_at.get(host)
        now = time.monotonic()
        if last is not None:
            elapsed = now - last
            if elapsed < self._per_host_interval:
                await asyncio.sleep(self._per_host_interval - elapsed)
        self._host_last_at[host] = time.monotonic()

    async def _check_ssrf(self, url: str) -> None:
        """Validate a crawler URL via the shared SSRF policy implementation."""
        await self._ssrf_guard.check(url)

    async def fetch(self, url: str, max_redirects: int = 5) -> httpx.Response:
        """Fetch a URL, manually following redirects so each hop is SSRF-checked
        before the request is made (rather than trusting httpx's auto-follow).
        """
        current = url
        for _ in range(max_redirects + 1):
            await self._check_ssrf(current)
            parsed = urlparse(current)
            host = parsed.netloc
            await self._wait_for_rps(host)
            resp = await self._client.get(current)

            if resp.status_code in (429, 503):
                ra = resp.headers.get("Retry-After")
                if ra:
                    with contextlib.suppress(Exception):
                        delay = float(ra)
                        await asyncio.sleep(min(delay, 10.0))
                        await self._check_ssrf(current)
                        resp = await self._client.get(current)

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    return resp
                current = urljoin(current, location)
                continue

            return resp

        # Exhausted redirect budget; return the last response as-is.
        return resp

    async def discover_sitemap(self, base: str) -> Set[str]:
        urls: Set[str] = set()
        parsed = urlparse(base)
        sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
        with contextlib.suppress(Exception):
            r = await self.fetch(sitemap_url)
            ctype = r.headers.get("content-type", "").lower()
            if r.status_code == 200 and ("xml" in ctype or ctype.startswith("application/xml")):
                root = ET.fromstring(r.text)
                for loc in root.iter("{http://www.sitemaps.org/schemas/sitemap/0.9}loc"):
                    if loc.text:
                        urls.add(loc.text.strip())
        return urls

    @staticmethod
    def _extract_links(base_url: str, html_text: str) -> List[str]:
        links: List[str] = []
        soup = BeautifulSoup(html_text, "html.parser")
        for a in soup.find_all("a", href=True):
            links.append(urljoin(base_url, a["href"]))
        for f in soup.find_all("form"):
            action = f.get("action")
            if action:
                links.append(urljoin(base_url, action))
        return links

    async def crawl(
        self,
        seeds: Iterable[str],
        include: Iterable[str],
        exclude: Iterable[str],
        max_pages: int = 1000,
        use_sitemap: bool = True,
    ) -> Set[str]:
        seen: Set[str] = set()
        queue: asyncio.Queue[str] = asyncio.Queue()
        for s in seeds:
            await queue.put(s)
            if use_sitemap:
                with contextlib.suppress(Exception):
                    sm = await self.discover_sitemap(s)
                    for u in sm:
                        await queue.put(u)

        async def worker():
            while True:
                url = await queue.get()
                try:
                    if url in seen or len(seen) >= max_pages:
                        continue
                    if not self.in_scope(url, include, exclude):
                        continue
                    try:
                        if not await self.allowed(url):
                            continue
                        parsed = urlparse(url)
                        host_sem = self._host_sem(parsed.netloc, self._host_sems.get(parsed.netloc, asyncio.Semaphore(4))._value if parsed.netloc in self._host_sems else 4)
                        async with self._global_sem, host_sem:
                            resp = await self.fetch(url)
                            seen.add(url)
                            ctype = resp.headers.get("content-type", "").lower()
                            if "html" in ctype and resp.text:
                                for link in self._extract_links(url, resp.text):
                                    if link not in seen:
                                        await queue.put(link)
                    except SSRFBlocked as exc:
                        logger.warning("Skipped blocked URL during crawl: %s", exc)
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(5)]
        await queue.join()
        for w in workers:
            w.cancel()
        # Ensure cancelled workers are awaited to avoid bubbling CancelledError
        await asyncio.gather(*workers, return_exceptions=True)
        return seen
