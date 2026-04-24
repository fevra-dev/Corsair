"""
Response classification for CORS DAST.

classify_reflection(): maps a ProbeResult to a finding ID (or None).
classify_sensitivity(): signal-driven heuristic for severity downgrade.
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional

from ..models import Severity
from .probe import ProbeResult

logger = logging.getLogger(__name__)


class SensitivitySignal(Enum):
    SENSITIVE = "sensitive"
    UNKNOWN = "unknown"


@dataclass
class ReflectionVerdict:
    """Outcome of classify_reflection."""

    finding_id: str
    default_severity: Severity
    effective_severity: Severity
    downgraded: bool


# Default severities per finding ID, matching spec §5.
_DEFAULTS: Dict[str, Severity] = {
    "CORS_ARBITRARY_ORIGIN_CRED": Severity.CRITICAL,
    "CORS_ARBITRARY_ORIGIN": Severity.HIGH,
    "CORS_NULL_ORIGIN_CRED": Severity.HIGH,
    "CORS_NULL_ORIGIN": Severity.MEDIUM,
    # Wave 2
    "CORS_SUBDOMAIN_BYPASS": Severity.HIGH,
    "CORS_PROTOCOL_DOWNGRADE": Severity.HIGH,
    "CORS_INTERNAL_ORIGIN": Severity.HIGH,
}

# Downgrade map: CRITICAL→HIGH, HIGH→MEDIUM. Spec §5 marks only
# CORS_ARBITRARY_* and CORS_SUBDOMAIN_BYPASS with the ↓ indicator;
# protocol_downgrade / internal_origin / null_* do NOT downgrade.
_DOWNGRADE: Dict[str, Severity] = {
    "CORS_ARBITRARY_ORIGIN_CRED": Severity.HIGH,
    "CORS_ARBITRARY_ORIGIN": Severity.MEDIUM,
    "CORS_SUBDOMAIN_BYPASS": Severity.MEDIUM,
}

_AUTH_GATE_STATUSES = {401, 403}
_LOGIN_PATH_MARKERS = ("login", "signin", "auth", "sso")
_JSON_CT_MARKERS = ("application/json", "+json")

_SUBDOMAIN_BYPASS_LABELS = frozenset({
    "subdomain_evil_prefix",
    "subdomain_attacker_suffix",
    "subdomain_dot_confusion",
    "subdomain_tld_confusion",
    "subdomain_wildcard",
    "subdomain_contains_match",
})

_INTERNAL_ORIGIN_LABELS = frozenset({
    "internal_loopback_ip",
    "internal_loopback_name",
    "internal_rfc1918_10",
    "internal_rfc1918_192",
})


def classify_reflection(
    result: ProbeResult,
    evil_origin: str,
    request_headers: Optional[Dict[str, str]] = None,
) -> Optional[ReflectionVerdict]:
    """
    Map a ProbeResult to a finding ID (Waves 1-2).

    Returns None when:
    - Probe errored
    - Response was 401/403 (auth gate — handled by CORS_PROBE_INCONCLUSIVE
      meta aggregation in the auditor)
    - ACAO is absent, wildcard, or didn't reflect the probe's origin
    """
    if result.error:
        return None
    if result.status_code in _AUTH_GATE_STATUSES:
        return None
    if not result.acao:
        return None

    acao_stripped = result.acao.strip()
    # Wildcard is a passive-phase finding (CORS_WILDCARD_CRED), not a
    # reflection finding — classifier should skip it here.
    if acao_stripped == "*":
        return None

    acac_true = (result.acac or "").strip().lower() == "true"

    finding_id: Optional[str] = None

    if result.label == "arbitrary_origin" and acao_stripped == evil_origin:
        finding_id = (
            "CORS_ARBITRARY_ORIGIN_CRED" if acac_true else "CORS_ARBITRARY_ORIGIN"
        )
    elif result.label == "null_origin" and acao_stripped.lower() == "null":
        finding_id = "CORS_NULL_ORIGIN_CRED" if acac_true else "CORS_NULL_ORIGIN"
    elif (
        result.label in _SUBDOMAIN_BYPASS_LABELS
        and acao_stripped == result.origin_sent
    ):
        finding_id = "CORS_SUBDOMAIN_BYPASS"
    elif (
        result.label == "protocol_downgrade"
        and acao_stripped == result.origin_sent
    ):
        finding_id = "CORS_PROTOCOL_DOWNGRADE"
    elif (
        result.label in _INTERNAL_ORIGIN_LABELS
        and acao_stripped == result.origin_sent
    ):
        finding_id = "CORS_INTERNAL_ORIGIN"

    if finding_id is None:
        return None

    default = _DEFAULTS[finding_id]
    sensitivity = classify_sensitivity(result, request_headers or {})

    if finding_id in _DOWNGRADE and sensitivity == SensitivitySignal.UNKNOWN:
        effective = _DOWNGRADE[finding_id]
        downgraded = True
    else:
        effective = default
        downgraded = False

    return ReflectionVerdict(
        finding_id=finding_id,
        default_severity=default,
        effective_severity=effective,
        downgraded=downgraded,
    )


def classify_sensitivity(
    result: ProbeResult,
    request_headers: Dict[str, str],
) -> SensitivitySignal:
    """
    Signal-driven sensitivity heuristic (spec §5.1).

    Returns SENSITIVE if ANY of:
      1. Set-Cookie header on the response.
      2. Authorization header in the scan's original request headers.
      3. Response Content-Type is application/json or application/*+json.
      4. Anonymous probe returned 302/303 to a path containing
         login/signin/auth/sso.

    Otherwise UNKNOWN.
    """
    if result.set_cookie:
        return SensitivitySignal.SENSITIVE

    req_headers_lower = {k.lower(): v for k, v in request_headers.items()}
    if "authorization" in req_headers_lower:
        return SensitivitySignal.SENSITIVE

    ct = (result.content_type or "").lower()
    if any(marker in ct for marker in _JSON_CT_MARKERS):
        return SensitivitySignal.SENSITIVE

    if result.status_code in (302, 303) and result.location:
        loc_lower = result.location.lower()
        if any(marker in loc_lower for marker in _LOGIN_PATH_MARKERS):
            return SensitivitySignal.SENSITIVE

    return SensitivitySignal.UNKNOWN
