"""CORS DAST finding definitions (Core 5 + meta)."""

from typing import Optional

from ..models import Finding

ALL_CORS_FINDINGS: dict[str, Finding] = {}


def get_finding(finding_id: str) -> Optional[Finding]:
    """Return a deep copy of a finding template, or None if unknown.

    Real implementation is filled in by Task 2.
    """
    raise NotImplementedError("Task 2 provides the real implementation.")
