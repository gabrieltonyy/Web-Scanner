from __future__ import annotations

import hashlib
from typing import Dict, Iterable, List

from .models import Finding
from .severity import max_severity, max_confidence


def compute_fingerprint(f: Finding) -> str:
    """Compute a stable fingerprint for a finding.

    Uses category, method, endpoint, param (if any), and an evidence signature/value.
    """
    parts = [
        f.category,
        f.method.upper(),
        f.endpoint,
        f.affects.param or "",
        (f.evidence.signature if f.evidence and f.evidence.signature else ""),
    ]
    h = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()
    return h


def merge_two(a: Finding, b: Finding) -> Finding:
    """Merge two findings assumed to be duplicates.

    - Keep highest severity and confidence
    - Union references and tags
    - Prefer evidence present; if both present, keep 'a' and note via tag
    - Preserve earliest first_seen and latest last_seen
    - If titles differ, keep 'a' and append alt title in tags
    - Track multi-source provenance by keeping 'source' of 'a' and adding tag
    """
    a.severity = max_severity(a.severity, b.severity)
    a.confidence = max_confidence(a.confidence, b.confidence)
    a.references = sorted(list({*(a.references or []), *(b.references or [])}))
    a.tags = sorted(list({*(a.tags or []), *(b.tags or [])}))
    if a.evidence is None and b.evidence is not None:
        a.evidence = b.evidence
    elif a.evidence is not None and b.evidence is not None and a.evidence != b.evidence:
        a.tags.append("evidence:merged")
    # first/last seen
    a.first_seen = min(filter(None, [a.first_seen, b.first_seen])) if any([a.first_seen, b.first_seen]) else None
    a.last_seen = max(filter(None, [a.last_seen, b.last_seen])) if any([a.last_seen, b.last_seen]) else None
    if a.title != b.title:
        a.tags.append(f"alt_title:{b.title}")
    if b.source != a.source:
        a.tags.append(f"source:{b.source}")
    if b.source_id and b.source_id != a.source_id:
        a.tags.append(f"source_id:{b.source_id}")
    return a


def dedupe_findings(findings: Iterable[Finding]) -> List[Finding]:
    buckets: Dict[str, Finding] = {}
    for f in findings:
        key = f.fingerprint or compute_fingerprint(f)
        if not f.fingerprint:
            f.fingerprint = key
        if key in buckets:
            buckets[key] = merge_two(buckets[key], f)
        else:
            buckets[key] = f
    return list(buckets.values())

