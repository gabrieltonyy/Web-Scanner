from __future__ import annotations

from typing import List

from scanner.models import Finding


class BurpAdapter:
    """Placeholder for Burp Suite Enterprise/Pro API integration.

    This adapter is a stub to keep the code structure ready. Implementations may
    parse exported JSON or call the API if available.
    """

    async def fetch_issues(self) -> List[Finding]:
        return []

