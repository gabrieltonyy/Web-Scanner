from __future__ import annotations

from typing import List, Optional

import httpx

from scanner.models import Affects, Evidence, Finding
from scanner.severity import zap_risk_to_severity, zap_confidence_to_confidence


class ZAPAdapter:
    """Lightweight ZAP API client (view-only). Safe no-op if API unreachable.

    This implementation uses httpx directly to avoid a hard dependency on
    python-owasp-zap-v2.4. If the API is not reachable, methods return empty lists.
    """

    def __init__(self, api_url: str, api_key: Optional[str] = None):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key

    async def fetch_alerts(self, base_url: Optional[str] = None) -> List[Finding]:
        params = {"apikey": self.api_key} if self.api_key else {}
        # core/alerts view returns alerts; filter by baseurl if provided
        url = f"{self.api_url}/JSON/core/view/alerts/"
        if base_url:
            params["baseurl"] = base_url
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url, params=params)
                r.raise_for_status()
                data = r.json() or {}
        except Exception:
            return []

        alerts = data.get("alerts", []) or []
        findings: List[Finding] = []
        for a in alerts:
            try:
                url = a.get("url") or base_url or ""
                name = a.get("alert", "ZAP Alert")
                risk = a.get("riskcode") or a.get("risk") or 0
                conf = a.get("confidence") or 0
                param = a.get("param") or None
                evidence = a.get("evidence") or None
                cwe = a.get("cweid")
                pluginid = a.get("pluginId") or a.get("pluginid")
                desc = a.get("description") or ""
                ref = a.get("reference") or ""

                findings.append(
                    Finding(
                        id=f"zap:{pluginid}:{url}",
                        fingerprint=f"zap:{pluginid}:{url}:{param}",
                        target=url,
                        endpoint=url,
                        method="GET",
                        category="ZAP",
                        title=name,
                        severity=zap_risk_to_severity(risk),
                        confidence=zap_confidence_to_confidence(conf),
                        affects=Affects(location="query" if param else "path", param=param),
                        request=None,  # not provided by this view
                        response=None,
                        evidence=Evidence(type="pattern", value=evidence or "", match_context=desc[:400] if desc else None),
                        remediation=a.get("solution") or "See references and vendor hardening guides.",
                        references=[ref] if ref else [],
                        cwe_id=str(cwe) if cwe else None,
                        source="zap",
                        source_id=str(pluginid) if pluginid else None,
                    )
                )
            except Exception:
                continue
        return findings

