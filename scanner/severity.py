from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Literal, Optional

from .models import Finding, Severity, Confidence


SEVERITY_ORDER: list[Severity] = ["Low", "Medium", "High", "Critical"]
CONFIDENCE_ORDER: list[Confidence] = ["Low", "Medium", "High"]


def _rank_severity(s: Severity) -> int:
    return SEVERITY_ORDER.index(s)


def _rank_confidence(c: Confidence) -> int:
    return CONFIDENCE_ORDER.index(c)


def max_severity(a: Severity, b: Severity) -> Severity:
    return a if _rank_severity(a) >= _rank_severity(b) else b


def max_confidence(a: Confidence, b: Confidence) -> Confidence:
    return a if _rank_confidence(a) >= _rank_confidence(b) else b


def normalize_severity(value: str) -> Severity:
    v = value.strip().lower()
    if v in {"critical", "crit"}:
        return "Critical"
    if v in {"high", "h"}:
        return "High"
    if v in {"medium", "med", "m"}:
        return "Medium"
    return "Low"


def normalize_confidence(value: str) -> Confidence:
    v = value.strip().lower()
    if v in {"confirmed", "certain", "high", "h"}:
        return "High"
    if v in {"medium", "med", "m"}:
        return "Medium"
    return "Low"


# ZAP mapping helpers (risk: 0=info,1=low,2=medium,3=high)
def zap_risk_to_severity(risk: int | str) -> Severity:
    try:
        r = int(risk)
    except Exception:
        return normalize_severity(str(risk))
    if r >= 3:
        return "High"
    if r == 2:
        return "Medium"
    if r == 1:
        return "Low"
    return "Low"


def zap_confidence_to_confidence(confidence: int | str) -> Confidence:
    # ZAP: 0=Low,1=Medium,2=High,3=Confirmed
    try:
        c = int(confidence)
    except Exception:
        return normalize_confidence(str(confidence))
    if c >= 2:
        return "High"
    if c == 1:
        return "Medium"
    return "Low"


@dataclass
class Policy:
    fail_on: Optional[Severity] = None  # None disables gating

    @classmethod
    def from_value(cls, value: Optional[str]) -> "Policy":
        if not value:
            return cls(None)
        return cls(normalize_severity(value))

    def should_fail(self, findings: Iterable[Finding]) -> bool:
        if not self.fail_on:
            return False
        threshold_rank = _rank_severity(self.fail_on)
        for f in findings:
            if _rank_severity(f.severity) >= threshold_rank:
                return True
        return False

