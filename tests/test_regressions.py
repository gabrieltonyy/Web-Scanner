from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from cli.main import main
from scanner.config import AuthConfig, Config, load_config
from scanner.crawler import Crawler
from scanner.models import Affects, Evidence, Finding, HTTPRequest
from scanner.safety import SSRFBlocked, SSRFGuard
from scanner.severity import Policy
from scanner.utils import dedupe_findings


def make_finding(
    *,
    fingerprint: str,
    severity: str = "Low",
    confidence: str = "Low",
    endpoint: str = "/search",
    param: str = "q",
) -> Finding:
    return Finding(
        id=fingerprint,
        fingerprint=fingerprint,
        target="https://example.test",
        endpoint=endpoint,
        method="GET",
        category="XSS",
        title="Test finding",
        severity=severity,
        confidence=confidence,
        affects=Affects(location="query", param=param),
        request=HTTPRequest(method="GET", url=f"https://example.test{endpoint}?{param}=x"),
        evidence=Evidence(type="reflection", value="marker", signature="stable"),
        remediation="Fix the test finding.",
    )


def test_cookie_authentication_uses_cookie_header() -> None:
    headers = AuthConfig(method="cookies", cookies="sessionid=abc; csrftoken=xyz").request_headers

    assert headers == {"Cookie": "sessionid=abc; csrftoken=xyz"}


def test_basic_and_bearer_authentication_headers() -> None:
    basic = AuthConfig(method="basic", basic={"username": "alice", "password": "secret"}).request_headers
    bearer = AuthConfig(method="bearer", bearer={"token": "token-value"}).request_headers

    assert basic["Authorization"] == "Basic YWxpY2U6c2VjcmV0"
    assert bearer == {"Authorization": "Bearer token-value"}


def test_invalid_configuration_values_are_rejected() -> None:
    with pytest.raises(ValueError):
        AuthConfig(method="unsupported")

    with pytest.raises(ValueError):
        Config(targets=[], scope={})

    with pytest.raises(ValueError):
        Config(targets=["https://example.test"], scope={}, runtime={"retries": -1})


def test_configuration_defaults_and_environment_interpolation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCAN_TARGET", "https://juice.example.test")
    config_path = tmp_path / "scan.yml"
    config_path.write_text(
        "targets:\n  - ${SCAN_TARGET}\nscope:\n  include: []\n",
        encoding="utf-8",
    )

    config = load_config(str(config_path))

    assert config.targets == ["https://juice.example.test"]
    assert config.safety.safe_mode is True
    assert config.safety.ssrf_protection is True
    assert config.runtime.honor_retry_after is True


@pytest.mark.asyncio
@pytest.mark.parametrize("honor_retry_after, expected_delay", [(True, 4.0), (False, 1.0)])
async def test_retry_after_is_conditionally_honored(
    monkeypatch: pytest.MonkeyPatch,
    honor_retry_after: bool,
    expected_delay: float,
) -> None:
    crawler = Crawler(
        ssrf_protection=False,
        retries=1,
        backoff="exponential",
        honor_retry_after=honor_retry_after,
    )
    responses = [
        httpx.Response(429, headers={"Retry-After": "4"}),
        httpx.Response(200),
    ]
    delays: list[float] = []

    async def fake_get(*args, **kwargs):
        return responses.pop(0)

    async def fake_sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr(crawler._client, "get", fake_get)
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    try:
        response = await crawler._request_with_retry("http://example.test/")
    finally:
        await crawler.close()

    assert response.status_code == 200
    assert delays == [expected_delay]


@pytest.mark.asyncio
async def test_retry_limit_returns_final_retryable_response(monkeypatch: pytest.MonkeyPatch) -> None:
    crawler = Crawler(ssrf_protection=False, retries=1, backoff="constant")
    calls = 0

    async def fake_get(*args, **kwargs):
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    async def fake_sleep(delay: float) -> None:
        return None

    monkeypatch.setattr(crawler._client, "get", fake_get)
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    try:
        response = await crawler._request_with_retry("http://example.test/")
    finally:
        await crawler.close()

    assert response.status_code == 503
    assert calls == 2


@pytest.mark.asyncio
async def test_redirect_to_blocked_destination_is_rejected() -> None:
    guard = SSRFGuard(enabled=True)
    transport = httpx.MockTransport(
        lambda request: httpx.Response(302, headers={"Location": "http://127.0.0.1:3000/private"}, request=request)
    )
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(SSRFBlocked):
            await guard.get(client, "http://public.example.test/start")


@pytest.mark.asyncio
async def test_allowed_redirect_is_followed() -> None:
    guard = SSRFGuard(enabled=True)
    transport = httpx.MockTransport(
        lambda request: (
            httpx.Response(302, headers={"Location": "http://allowed.example.test/final"}, request=request)
            if request.url.path == "/start"
            else httpx.Response(200, text="ok", request=request)
        )
    )

    async def resolve(hostname: str) -> list[str]:
        return ["93.184.216.34"]

    guard._resolve = resolve  # type: ignore[method-assign]
    async with httpx.AsyncClient(transport=transport) as client:
        response = await guard.get(client, "http://allowed.example.test/start")

    assert response.status_code == 200
    assert response.text == "ok"


def test_duplicate_findings_merge_severity_confidence_and_references() -> None:
    first = make_finding(fingerprint="same", severity="Low", confidence="Low")
    second = make_finding(fingerprint="same", severity="High", confidence="High")
    second.references = ["https://owasp.org/"]

    merged = dedupe_findings([first, second])

    assert len(merged) == 1
    assert merged[0].severity == "High"
    assert merged[0].confidence == "High"
    assert merged[0].references == ["https://owasp.org/"]


def test_distinct_fingerprints_remain_distinct() -> None:
    findings = dedupe_findings([
        make_finding(fingerprint="one"),
        make_finding(fingerprint="two", endpoint="/login", param="next"),
    ])

    assert {finding.fingerprint for finding in findings} == {"one", "two"}


def test_severity_policy_matches_threshold() -> None:
    findings = [make_finding(fingerprint="medium", severity="Medium")]

    assert Policy.from_value("High").should_fail(findings) is False
    assert Policy.from_value("Medium").should_fail(findings) is True
    assert Policy.from_value(None).should_fail(findings) is False


def test_cli_fail_on_returns_nonzero_when_threshold_is_met(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config_path = tmp_path / "scan.yml"
    config_path.write_text(
        "targets:\n  - https://example.test\nscope: {}\nci:\n  fail_on: null\n",
        encoding="utf-8",
    )
    finding = make_finding(fingerprint="high", severity="High")

    async def fake_scan(*args, **kwargs):
        return {"artifact_dir": "artifacts/test", "url_count": 1, "findings_count": 1, "findings": [finding]}

    monkeypatch.setattr("cli.main.run_scan", fake_scan)

    assert main(["scan", "-c", str(config_path), "--fail-on", "High"]) == 2
