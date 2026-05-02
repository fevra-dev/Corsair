"""Fetch Metadata probe primitives and classifier.

Pure-function classifier for the four-probe canary-extended sequence:
  B = Baseline (no Sec-Fetch-* headers)
  S = Safe          (Sec-Fetch-Site: same-origin)
  A = Adversarial   (Sec-Fetch-Site: cross-site)
  C = Canary        (Sec-Fetch-Site: corsair-canary-invalid)

See docs/superpowers/specs/2026-04-26-fetch-metadata-probing-design.md §4.
"""

import hashlib
from enum import Enum
from typing import Mapping


class EnforcementResult(Enum):
    ENFORCED = "enforced"
    SOFT_ENFORCED = "soft_enforced"
    NOT_ENFORCED = "not_enforced"
    INCONCLUSIVE = "inconclusive"


SAFE_PROBE_HEADERS: Mapping[str, str] = {
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
}

ADVERSARIAL_PROBE_HEADERS: Mapping[str, str] = {
    "Sec-Fetch-Site": "cross-site",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
}

CANARY_PROBE_HEADERS: Mapping[str, str] = {
    "Sec-Fetch-Site": "corsair-canary-invalid",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
}


ENFORCEMENT_STATUS_CODES = frozenset({400, 403, 405, 451})
REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})
AUTH_STATUS_CODES = frozenset({401})


def _body_hash(body: bytes) -> str:
    """SHA-256 of the first 4 KB of body — sufficient to discriminate distinct
    responses without paying for very large pages."""
    return hashlib.sha256(body[:4096]).hexdigest()


def classify_enforcement(
    baseline_status: int,
    safe_status: int,
    adversarial_status: int,
    canary_status: int,
    baseline_body_hash: str,
    adversarial_body_hash: str,
) -> EnforcementResult:
    """Map a four-probe status/body quartet onto an EnforcementResult.

    Rules applied in order — first match wins. See spec §4.3.
    """
    # Rule 1: server blanket-rejects Sec-Fetch — signal poisoned.
    if safe_status in ENFORCEMENT_STATUS_CODES:
        return EnforcementResult.INCONCLUSIVE

    # Rule 2: target unhealthy or auth-walled.
    if baseline_status >= 500 or baseline_status in AUTH_STATUS_CODES:
        return EnforcementResult.INCONCLUSIVE

    # Rule 3: spec-strict enforcement (canary also rejected).
    if (
        adversarial_status in ENFORCEMENT_STATUS_CODES
        and canary_status in ENFORCEMENT_STATUS_CODES
    ):
        return EnforcementResult.ENFORCED

    # Rule 4: allowlist enforcement (canary not in spec enum is silently
    # treated as same as baseline by the server; A is rejected).
    if (
        adversarial_status in ENFORCEMENT_STATUS_CODES
        and canary_status == baseline_status
    ):
        return EnforcementResult.ENFORCED

    # Rule 5: adversarial redirected — likely auth, not FM.
    if (
        adversarial_status in REDIRECT_STATUS_CODES
        and baseline_status not in REDIRECT_STATUS_CODES
    ):
        return EnforcementResult.INCONCLUSIVE

    # Rule 6: 2xx but body modified for cross-site — soft enforcement.
    if (
        adversarial_status < 300
        and adversarial_body_hash != baseline_body_hash
    ):
        return EnforcementResult.SOFT_ENFORCED

    # Rule 7: clean A=B, C=B → no enforcement.
    if (
        adversarial_status == baseline_status
        and canary_status == baseline_status
    ):
        return EnforcementResult.NOT_ENFORCED

    # Rule 8: anything else — INCONCLUSIVE.
    return EnforcementResult.INCONCLUSIVE
