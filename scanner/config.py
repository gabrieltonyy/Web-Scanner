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


class ProxyConfig(BaseModel):
    http: Optional[str] = None
    https: Optional[str] = None


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
    # Optional presentation metadata
    title: Optional[str] = None
    client: Optional[str] = None
    assessor: Optional[str] = None
    company: Optional[str] = None
    contact: Optional[str] = None
    executive_summary: Optional[str] = None
    methodology: Optional[str] = None
    assumptions: Optional[str] = None


class RuntimeConfig(BaseModel):
    concurrency: int = 10
    timeout_seconds: int = 20
    retries: int = 2
    backoff: str = "exponential"
    honor_retry_after: bool = True


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


def _interpolate_env(data: Any) -> Any:
    if isinstance(data, dict):
        return {k: _interpolate_env(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_interpolate_env(v) for v in data]
    if isinstance(data, str):
        # Simple ${VAR} replacement via environment
        return os.path.expandvars(data)
    return data


def load_config(path: str) -> Config:
    if load_dotenv:
        load_dotenv()
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    raw = _interpolate_env(raw)
    return Config(**raw)
