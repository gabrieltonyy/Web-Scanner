from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from typing import List, Set
from urllib.parse import urlparse

import httpx

from .config import Config, load_config
from .crawler import Crawler
from .checks.headers import check_security_headers
from .checks.cookies import check_cookie_flags
from .checks.tls import check_tls_version
from .checks.xss import check_reflected_xss
from .checks.sqli import check_sqli
from .checks.csrf import check_csrf_forms
from .models import Finding
from .utils import dedupe_findings
from reporting.engines import PDFRenderer
from jinja2 import Environment, FileSystemLoader


class Orchestrator:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    async def crawl(self) -> Set[str]:
        c = Crawler(
            concurrency=self.cfg.runtime.concurrency,
            concurrency_per_host=self.cfg.crawler.concurrency_per_host,
            timeout=float(self.cfg.runtime.timeout_seconds),
            per_host_rps=float(self.cfg.crawler.per_host_rps),
            respect_robots=self.cfg.crawler.respect_robots,
        )
        try:
            urls = await c.crawl(
                seeds=self.cfg.targets,
                include=self.cfg.scope.include,
                exclude=self.cfg.scope.exclude,
                max_pages=self.cfg.crawler.max_pages,
                use_sitemap=True,
            )
            return urls
        finally:
            await c.close()

    async def passive_checks_for(self, url: str, client: httpx.AsyncClient) -> List[Finding]:
        findings: List[Finding] = []
        r = await client.get(url)
        hdrs = dict(r.headers)
        findings.extend(check_security_headers(url, hdrs))
        findings.extend(check_cookie_flags(url, hdrs, https=url.startswith("https://")))
        if url.startswith("https://"):
            findings.extend(check_tls_version(url, hdrs))
        ctype = hdrs.get("content-type", "").lower()
        if "html" in ctype and r.text:
            findings.extend(check_csrf_forms(url, r.text, hdrs))
        return findings

    async def active_checks_for(self, url: str, client: httpx.AsyncClient) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(await check_reflected_xss(url, client, https=url.startswith("https://")))
        findings.extend(await check_sqli(url, client))
        return findings

    async def run(self) -> dict:
        urls = await self.crawl()
        findings: List[Finding] = []
        async with httpx.AsyncClient(follow_redirects=True, timeout=self.cfg.runtime.timeout_seconds) as client:
            for url in urls:
                try:
                    findings.extend(await self.passive_checks_for(url, client))
                    if self.cfg.checks.xss:
                        findings.extend(await check_reflected_xss(url, client, https=url.startswith("https://")))
                    if self.cfg.checks.sqli:
                        findings.extend(await check_sqli(url, client))
                except Exception:
                    # Best-effort; continue scanning
                    continue

        deduped = dedupe_findings(findings)
        artifact_dir = self._write_artifacts(urls, deduped)
        report_paths = self._render_report(artifact_dir, deduped)
        return {
            "artifact_dir": artifact_dir,
            "report": report_paths,
            "url_count": len(urls),
            "findings_count": len(deduped),
            "findings": deduped,
        }

    def _write_artifacts(self, urls: Set[str], findings: List[Finding]) -> str:
        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        outdir = os.path.join("artifacts", ts)
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(outdir, "crawl.json"), "w", encoding="utf-8") as f:
            json.dump(sorted(list(urls)), f, indent=2)
        with open(os.path.join(outdir, "findings.json"), "w", encoding="utf-8") as f:
            def to_dict(m):
                # Pydantic v2 uses model_dump; v1 used dict
                return m.model_dump() if hasattr(m, "model_dump") else m.dict()
            json.dump([to_dict(fi) for fi in findings], f, indent=2)
        return outdir

    def _render_report(self, outdir: str, findings: List[Finding]) -> dict:
        # Render HTML via Jinja2
        env = Environment(loader=FileSystemLoader("reporting/templates"))
        tpl = env.get_template("report.html")
        html = tpl.render(project=self.cfg.project, generated_at=str(datetime.utcnow()), findings=findings)
        html_path = os.path.join(outdir, "report.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        # Try to render PDF with configured engine
        pdf_path = None
        try:
            renderer = PDFRenderer(getattr(self.cfg.report, "engine", None))
            pdf_path = os.path.join(outdir, "report.pdf")
            renderer.render(html, pdf_path)
        except Exception:
            pdf_path = None
        return {"html": html_path, "pdf": pdf_path}


async def run_scan(config_path: str) -> dict:
    cfg = load_config(config_path)
    orch = Orchestrator(cfg)
    return await orch.run()
