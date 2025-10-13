from __future__ import annotations

from typing import Literal, Optional, List, Dict
from pydantic import BaseModel

Severity = Literal["Critical", "High", "Medium", "Low"]
Confidence = Literal["High", "Medium", "Low"]


class HTTPRequest(BaseModel):
    method: str
    url: str
    headers: Dict[str, str] = {}
    body: Optional[str] = None
    redacted: bool = True  # secrets removed according to policy


class HTTPResponse(BaseModel):
    status: int
    headers: Dict[str, str] = {}
    body_excerpt: Optional[str] = None  # small safe excerpt only


class Evidence(BaseModel):
    type: Literal["reflection", "error", "timing", "header", "pattern", "other"]
    value: str  # e.g., reflected string, error snippet, delta ms
    match_context: Optional[str] = None  # where/how it matched
    signature: Optional[str] = None  # stable signature for fingerprinting
    screenshot_path: Optional[str] = None


class Affects(BaseModel):
    location: Literal["path", "query", "body", "header", "cookie", "other"]
    param: Optional[str] = None


class Finding(BaseModel):
    id: str
    fingerprint: str
    target: str
    endpoint: str
    method: str
    category: str  # e.g., Injection, XSS, CSRF
    title: str
    severity: Severity
    confidence: Confidence = "Medium"
    affects: Affects
    request: HTTPRequest
    response: Optional[HTTPResponse] = None
    evidence: Optional[Evidence] = None
    poc: Optional[str] = None  # code snippet or curl
    remediation: str
    references: List[str] = []
    cwe_id: Optional[str] = None
    owasp: Optional[str] = None
    cvss: Optional[str] = None
    source: Literal["core", "zap", "burp"] = "core"
    source_id: Optional[str] = None
    status: Literal["new", "confirmed", "false_positive", "accepted_risk"] = "new"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: List[str] = []

