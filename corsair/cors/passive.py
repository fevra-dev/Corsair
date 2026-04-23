"""
Passive CORS analysis — inspects response headers already collected by the
scanner. Never issues network requests.

This module is the migration target for the legacy corsair/analyzers/cors.py
static analyzer. The legacy CORSAnalyzer class is now a thin adapter that
delegates to analyze() here, so the analyzer registry keeps working unchanged.

Wave 1 scope: CORS_WILDCARD_CRED + wildcard-no-creds + null-origin + specific-
origin PASS + no-CORS PASS. CORS_FRAMEWORK_DEFAULT ships in Wave 4.
"""

import logging
from typing import Dict, List, Optional

from ..models import Finding, HeaderCategory, Severity
from .findings import get_finding

logger = logging.getLogger(__name__)

_MDN_URL = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"


def _lookup_header(headers: Dict[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup."""
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return None


def _make_pass_finding(current_value: str) -> Finding:
    return Finding(
        header="Access-Control-Allow-Origin",
        category=HeaderCategory.CORS,
        severity=Severity.PASS,
        title="CORS correctly configured",
        description=(
            f"Access-Control-Allow-Origin is set to a specific origin "
            f"({current_value}), which is the recommended configuration for "
            f"endpoints that need cross-origin access from a trusted domain."
        ),
        current_value=current_value,
        recommendation="No action required.",
        example_value=current_value,
        reference_url=_MDN_URL,
    )


def _make_no_cors_pass() -> Finding:
    return Finding(
        header="Access-Control-Allow-Origin",
        category=HeaderCategory.CORS,
        severity=Severity.PASS,
        title="CORS Not Configured (Same-Origin Policy)",
        description="No CORS headers are set. Same-origin policy is in effect.",
        current_value=None,
        recommendation="No action needed unless cross-origin access is required.",
        example_value="N/A",
        reference_url=_MDN_URL,
    )


def _make_wildcard_finding() -> Finding:
    return Finding(
        header="Access-Control-Allow-Origin",
        category=HeaderCategory.CORS,
        severity=Severity.MEDIUM,
        title="CORS Allows All Origins",
        description=(
            "Access-Control-Allow-Origin is set to '*', allowing any origin to "
            "access resources. This may be intentional for public APIs, but "
            "ensure no sensitive data is exposed."
        ),
        current_value="*",
        recommendation="If not a public API, restrict to specific origins.",
        example_value="Access-Control-Allow-Origin: https://trusted.example.com",
        reference_url=_MDN_URL,
    )


def _make_null_origin_finding() -> Finding:
    return Finding(
        header="Access-Control-Allow-Origin",
        category=HeaderCategory.CORS,
        severity=Severity.HIGH,
        title="CORS Allows Null Origin",
        description=(
            "Access-Control-Allow-Origin is set to 'null'. The null origin can "
            "be sent from sandboxed iframes and data: URLs, which can be "
            "controlled by attackers."
        ),
        current_value="null",
        recommendation="Never allow the null origin.",
        example_value="Access-Control-Allow-Origin: https://trusted.example.com",
        reference_url=_MDN_URL,
    )


def analyze(headers: Dict[str, str], url: str) -> List[Finding]:
    """
    Passive CORS header analysis.

    Args:
        headers: Response headers from the scan target (any casing).
        url: Target URL (used for logging only).

    Returns:
        List of Finding objects. Always returns at least one finding (PASS
        when no CORS headers present).
    """
    findings: List[Finding] = []

    acao = _lookup_header(headers, "Access-Control-Allow-Origin")
    acac = _lookup_header(headers, "Access-Control-Allow-Credentials")

    if not acao:
        logger.info("[CORS] No CORS headers (using same-origin policy)")
        findings.append(_make_no_cors_pass())
        return findings

    logger.info(f"[CORS] Access-Control-Allow-Origin: {acao}")

    acao_stripped = acao.strip()

    if acao_stripped == "*":
        if acac and acac.strip().lower() == "true":
            finding = get_finding("CORS_WILDCARD_CRED")
            if finding is not None:
                finding.current_value = f"ACAO: {acao}, ACAC: {acac}"
                findings.append(finding)
        else:
            findings.append(_make_wildcard_finding())
    elif acao_stripped.lower() == "null":
        findings.append(_make_null_origin_finding())
    else:
        findings.append(_make_pass_finding(acao))

    return findings
