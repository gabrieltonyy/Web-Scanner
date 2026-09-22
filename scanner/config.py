from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import yaml

try:  # optional dotenv
    from dotenv import load_dotenv  # type: ignore
except Exception:  # pragma: no cover
    load_dotenv = None

from pydantic import BaseModel, Field, validator

from reporting.engines import DEFAULT_ENGINE


class AuthConfig(BaseModel):
    method: str = "none"
    cookies: Optional[str] = None
    basic: Optional[Dict[str, str]] = None
    bearer: Optional[Dict[str, str]] = None
    login_script: Optional[str] = None
    login_script_timeout: int = 30

    @validator("method")
    def validate_method(cls, value: str) -> str:
        allowed = {"none", "basic", "cookies", "bearer"}
        if value not in allowed:
            raise ValueError(f"auth.method must be one of {sorted(allowed)}")
        return value

    @property
    def request_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self.method == "cookies" and self.cookies:
            # Cookies must be sent in one Cookie header, not as arbitrary headers.
            cookie_parts = [part.strip() for part in self.cookies.split(";") if "=" in part]
            if cookie_parts:
                headers["Cookie"] = "; ".join(cookie_parts)

        if self.method == "basic" and self.basic:
            username = self.basic.get("username", "")
            password = self.basic.get("password", "")
            if username or password:
                import base64

                token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
                headers["Authorization"] = f"Basic {token}"

        if self.method == "bearer" and self.bearer:
            token = self.bearer.get("token") or self.bearer.get("value")
            if token:
                headers["Authorization"] = f"Bearer {token}"

        return headers


class ProxyConfig(BaseModel):
    http: Optional[str] = None
    https: Optional[str] = None

    @property
    def as_httpx_proxies(self) -> Optional[Dict[str, str]]:
        proxies: Dict[str, str] = {}
        if self.http:
            proxies["http"] = self.http
        if self.https:
            proxies["https"] = self.https
        return proxies or None


class CrawlerConfig(BaseModel):
    max_pages: int = 1000
    respect_robots: bool = True
    rate_limit_rps: int = 2
    per_host_rps: int = 2
    concurrency_per_host: int = 4


class ChecksConfig(BaseModel):
    sqli: bool = True
    xss: bool = True
    csrf: bool = True
    misconfig: bool = True
    access_control: bool = False


class SafetyConfig(BaseModel):
    safe_mode: bool = True
    redact_secrets: bool = True
    ssrf_protection: bool = True
    blocklist_cidrs: List[str] = Field(
        default_factory=lambda: [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
        ]
    )
    blocklist_hosts: List[str] = Field(
        default_factory=lambda: [
            "metadata.google.internal",
            "169.254.169.254",
        ]
    )


class ZapConfig(BaseModel):
    enabled: bool = True
    api_key: Optional[str] = None
    url: str = "http://127.0.0.1:8080"
    active_scan: bool = True
    map_confidence: bool = True


class BurpConfig(BaseModel):
    enabled: bool = False


class IntegrationsConfig(BaseModel):
    zap: ZapConfig = ZapConfig()
    burp: BurpConfig = BurpConfig()


class ReportConfig(BaseModel):
    output_dir: str = "reports"
    filename: str = "report.pdf"
    engine: str = DEFAULT_ENGINE
    template: str = "reporting/templates/report.html"
    title: Optional[str] = None
    client: Optional[str] = None
    assessor: Optional[str] = None
    company: Optional[str] = None
    contact: Optional[str] = None
    executive_summary: Optional[str] = None
    methodology: Optional[str] = None
    assumptions: Optional[str] = None

    @validator("engine")
    def validate_engine(cls, value: str) -> str:
        allowed = {"weasyprint", "wkhtmltopdf", "reportlab"}
        if value not in allowed:
            raise ValueError(f"report.engine must be one of {sorted(allowed)}")
        return value


class RuntimeConfig(BaseModel):
    concurrency: int = 10
    timeout_seconds: int = 20
    retries: int = 2
    backoff: str = "exponential"
    honor_retry_after: bool = True

    @validator("retries")
    def validate_retries(cls, value: int) -> int:
        if value < 0:
            raise ValueError("runtime.retries must be >= 0")
        return value


class CIConfig(BaseModel):
    fail_on: Optional[str] = None


class UIConfig(BaseModel):
    queue: str = "rq"
    redis_url: str = "redis://localhost:6379/0"
    progress_transport: str = "sse"


class EnvConfig(BaseModel):
    load_dotenv: bool = True


class ScopeConfig(BaseModel):
    include: List[str] = Field(default_factory=list)
    exclude: List[str] = Field(default_factory=list)


class Config(BaseModel):
    project: str = "Unnamed Project"
    targets: List[str]
    scope: ScopeConfig
    auth: AuthConfig = AuthConfig()
    proxies: Optional[ProxyConfig] = None
    crawler: CrawlerConfig = CrawlerConfig()
    checks: ChecksConfig = ChecksConfig()
    safety: SafetyConfig = SafetyConfig()
    integrations: IntegrationsConfig = IntegrationsConfig()
    report: ReportConfig = ReportConfig()
    runtime: RuntimeConfig = RuntimeConfig()
    ci: CIConfig = CIConfig()
    ui: UIConfig = UIConfig()
    env: EnvConfig = EnvConfig()

    @validator("targets")
    def validate_targets(cls, value: List[str]) -> List[str]:
        if not value:
            raise ValueError("config.targets must not be empty")
        cleaned = [str(v).strip() for v in value if str(v).strip()]
        if not cleaned:
            raise ValueError("config.targets must contain at least one non-empty URL")
        return cleaned

    @validator("scope", pre=True)
    def validate_scope(cls, value: Any) -> Any:
        if value is None:
            return {"include": [], "exclude": []}
        return value


def _interpolate_env(data: Any) -> Any:
    if isinstance(data, dict):
        return {k: _interpolate_env(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_interpolate_env(v) for v in data]
    if isinstance(data, str):
        return os.path.expandvars(data)
    return data


def load_config(path: str) -> Config:
    if load_dotenv:
        load_dotenv()
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    raw = _interpolate_env(raw)
    return Config(**raw)
