"""H1/H3 security-header diff.

Pure-logic comparison over an explicit allowlist. Three diff buckets:
  - missing_in_h3: present in H1, absent in H3
  - missing_in_h1: present in H3, absent in H1
  - value_drift:   present in both with different values

Header keys compared case-insensitively. Header values compared
case-sensitively (e.g., 'max-age=0' vs 'MAX-AGE=0' is a real misconfig).
Output lists are sorted for deterministic finding text.
"""

from dataclasses import dataclass, field
from typing import List, Mapping, Tuple


SECURITY_HEADER_ALLOWLIST: frozenset = frozenset({
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "cross-origin-opener-policy",
    "cross-origin-opener-policy-report-only",
    "cross-origin-embedder-policy",
    "cross-origin-embedder-policy-report-only",
    "cross-origin-resource-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "integrity-policy",
    "integrity-policy-report-only",
    "reporting-endpoints",
    "document-isolation-policy",
    "document-isolation-policy-report-only",
    "origin-agent-cluster",
})


@dataclass(frozen=True)
class HeaderDiffResult:
    missing_in_h3: List[str] = field(default_factory=list)
    missing_in_h1: List[str] = field(default_factory=list)
    value_drift: List[Tuple[str, str, str]] = field(default_factory=list)


def _restricted_lowercased(headers: Mapping[str, str]) -> tuple:
    """Return (lowered_dict, display_dict) — only allowlist headers, with
    lowercased keys for comparison and a parallel mapping back to the
    original casing for output formatting.
    """
    lowered: dict = {}
    display: dict = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl in SECURITY_HEADER_ALLOWLIST:
            lowered[kl] = v
            display[kl] = k
    return lowered, display


def diff_security_headers(
    h1: Mapping[str, str],
    h3: Mapping[str, str],
) -> HeaderDiffResult:
    """Diff security-relevant headers between H1 and H3 responses.

    Returns a HeaderDiffResult with three populated lists. Lists are sorted
    by header display name (preferring H1 casing when both sides have the
    header). Header values are compared case-sensitively.
    """
    h1_l, h1_disp = _restricted_lowercased(h1)
    h3_l, h3_disp = _restricted_lowercased(h3)

    missing_in_h3: List[str] = []
    missing_in_h1: List[str] = []
    value_drift: List[Tuple[str, str, str]] = []

    for key in h1_l:
        if key not in h3_l:
            missing_in_h3.append(h1_disp[key])
        elif h1_l[key] != h3_l[key]:
            # Prefer H1 display casing for the header name in the drift tuple.
            value_drift.append((h1_disp[key], h1_l[key], h3_l[key]))

    for key in h3_l:
        if key not in h1_l:
            missing_in_h1.append(h3_disp[key])

    missing_in_h3.sort()
    missing_in_h1.sort()
    value_drift.sort(key=lambda t: t[0])

    return HeaderDiffResult(
        missing_in_h3=missing_in_h3,
        missing_in_h1=missing_in_h1,
        value_drift=value_drift,
    )
