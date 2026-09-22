from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import contextmanager
from datetime import datetime
from importlib import resources
from typing import Iterator, List, Set

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
from .safety import SSRFBlocked, SSRFGuard, redact_text
from .poc import redact_headers
from reporting.engines import PDFRenderer
from jinja2 import Environment, FileSystemLoader
from integrations.zap_adapter import ZAPAdapter

logger = logging.getLogger(__name__)


@contextmanager
def _template_directory() -> Iterator[str]:
    """Expose packaged report templates as a filesystem directory for Jinja."""
    template_dir = resources.files("reporting").joinpath("templates")
    with resources.as_file(template_dir) as path:
        yield str(path)


class Orchestrator:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._auth_headers = cfg.auth.request_headers
        self._proxy_map = cfg.proxies.as_httpx_proxies if cfg.proxies else None
        self._ssrf_guard = SSRFGuard(
            enabled=cfg.safety.ssrf_protection,
            blocklist_cidrs=cfg.safety.blocklist_cidrs,
            blocklist_hosts=cfg.safety.blocklist_hosts,
        )

    async def crawl(self) -> Set[str]:
        crawler = Crawler(
            concurrency=self.cfg.runtime.concurrency,
            concurrency_per_host=self.cfg.crawler.concurrency_per_host,
            timeout=float(self.cfg.runtime.timeout_seconds),
            per_host_rps=float(self.cfg.crawler.per_host_rps),
            respect_robots=self.cfg.crawler.respect_robots,
            ssrf_protection=self.cfg.safety.ssrf_protection,
            blocklist_cidrs=self.cfg.safety.blocklist_cidrs,
            blocklist_hosts=self.cfg.safety.blocklist_hosts,
            auth_headers=self._auth_headers,
            proxies=self._proxy_map,
            retries=self.cfg.runtime.retries,
            backoff=self.cfg.runtime.backoff,
            honor_retry_after=self.cfg.runtime.honor_retry_after,
        )
        try:
            return await crawler.crawl(
                seeds=self.cfg.targets,
                include=self.cfg.scope.include,
                exclude=self.cfg.scope.exclude,
                max_pages=self.cfg.crawler.max_pages,
                use_sitemap=True,
            )
        finally:
            await crawler.close()

    async def passive_checks_for(self, url: str, client: httpx.AsyncClient) -> List[Finding]:
        findings: List[Finding] = []
        response = await self._ssrf_guard.get(client, url, headers=self._auth_headers)
        headers = dict(response.headers)
        if self.cfg.checks.misconfig:
            findings.extend(check_security_headers(url, headers))
            findings.extend(check_cookie_flags(url, headers, https=url.startswith("https://")))
            if url.startswith("https://"):
                findings.extend(check_tls_version(url, headers))
        if self.cfg.checks.csrf and "html" in headers.get("content-type", "").lower() and response.text:
            findings.extend(check_csrf_forms(url, response.text, headers))
        return findings

    async def active_checks_for(self, url: str, client: httpx.AsyncClient) -> List[Finding]:
        findings: List[Finding] = []
        if self.cfg.checks.xss:
            findings.extend(await check_reflected_xss(url, client, https=url.startswith("https://"), ssrf_guard=self._ssrf_guard, headers=self._auth_headers))
        if self.cfg.checks.sqli:
            findings.extend(await check_sqli(url, client, safe_mode=self.cfg.safety.safe_mode, ssrf_guard=self._ssrf_guard, headers=self._auth_headers))
        return findings

    async def run(self) -> dict:
        urls = await self.crawl()
        findings: List[Finding] = []
        async with httpx.AsyncClient(follow_redirects=False, timeout=self.cfg.runtime.timeout_seconds, proxies=self._proxy_map, headers=self._auth_headers) as client:
            for url in urls:
                try:
                    findings.extend(await self.passive_checks_for(url, client))
                    findings.extend(await self.active_checks_for(url, client))
                except SSRFBlocked as exc:
                    logger.warning("Skipped blocked URL during checks: %s", exc)
                except Exception:
                    logger.exception("Checks failed for %s", url)

        if getattr(self.cfg.integrations.zap, "enabled", False):
            try:
                zap = ZAPAdapter(self.cfg.integrations.zap.url, self.cfg.integrations.zap.api_key)
                for target in self.cfg.targets:
                    findings.extend(await zap.fetch_alerts(target))
            except Exception:
                logger.exception("ZAP alert import failed")

        deduped = dedupe_findings(findings)
        artifact_dir = self._write_artifacts(urls, deduped)
        report_paths = self._render_report(artifact_dir, deduped, len(urls))
        return {"artifact_dir": artifact_dir, "report": report_paths, "url_count": len(urls), "findings_count": len(deduped), "findings": deduped}

    def _write_artifacts(self, urls: Set[str], findings: List[Finding]) -> str:
        if self.cfg.safety.redact_secrets:
            self._redact_findings(findings)
        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        outdir = os.path.join("artifacts", ts)
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(outdir, "crawl.json"), "w", encoding="utf-8") as f:
            json.dump(sorted(urls), f, indent=2)
        with open(os.path.join(outdir, "findings.json"), "w", encoding="utf-8") as f:
            json.dump([m.model_dump() if hasattr(m, "model_dump") else m.dict() for m in findings], f, indent=2)
        return outdir

    @staticmethod
    def _redact_findings(findings: List[Finding]) -> None:
        for finding in findings:
            request = finding.request
            request.headers, changed = redact_headers(request.headers)
            if request.body:
                redacted_body = redact_text(request.body)
                changed = changed or redacted_body != request.body
                request.body = redacted_body
            request.redacted = changed
            if finding.response:
                finding.response.headers, _ = redact_headers(finding.response.headers)
                if finding.response.body_excerpt:
                    finding.response.body_excerpt = redact_text(finding.response.body_excerpt)
            if finding.evidence and finding.evidence.match_context:
                finding.evidence.match_context = redact_text(finding.evidence.match_context)
            if finding.poc:
                finding.poc = redact_text(finding.poc)

    def _render_report(self, outdir: str, findings: List[Finding], url_count: int) -> dict:
        sev_order = ["Critical", "High", "Medium", "Low"]
        counts = {severity: 0 for severity in sev_order}
        by_cat: dict[str, int] = {}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
            by_cat[finding.category] = by_cat.get(finding.category, 0) + 1
        summary = {"total": len(findings), "by_severity": counts, "by_category": sorted(by_cat.items(), key=lambda x: (-x[1], x[0]))}
        with _template_directory() as template_dir:
            env = Environment(loader=FileSystemLoader(template_dir))
            html = env.get_template("report.html").render(
                project=self.cfg.project,
                report_title=self.cfg.report.title or self.cfg.project,
                generated_at=str(datetime.utcnow()),
                findings=findings,
                summary=summary,
                targets=self.cfg.targets,
                scope_include=self.cfg.scope.include,
                scope_exclude=self.cfg.scope.exclude,
                url_count=url_count,
                client=self.cfg.report.client,
                assessor=self.cfg.report.assessor,
                company=self.cfg.report.company,
                contact=self.cfg.report.contact,
                executive_summary=self.cfg.report.executive_summary,
                methodology=self.cfg.report.methodology,
                assumptions=self.cfg.report.assumptions,
            )
        html_path = os.path.join(outdir, "report.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        pdf_path = None
        try:
            pdf_path = os.path.join(outdir, "report.pdf")
            PDFRenderer(getattr(self.cfg.report, "engine", None)).render(html, pdf_path)
        except Exception:
            pdf_path = None
        return {"html": html_path, "pdf": pdf_path}


async def run_scan(config_path: str, dangerous: bool = False) -> dict:
    cfg = load_config(config_path)
    if dangerous:
        cfg.safety.safe_mode = False
    return await Orchestrator(cfg).run()
