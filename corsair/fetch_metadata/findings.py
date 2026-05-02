"""Fetch Metadata finding templates, registry, and severity-matrix builder."""

import copy
from dataclasses import dataclass
from typing import Optional

from ..models import (
    ComplianceMapping,
    CVECorrelation,
    Finding,
    HeaderCategory,
    Severity,
)


def _compliance(framework: str, req_id: str, req_name: str, status: str = "FAIL") -> ComplianceMapping:
    return ComplianceMapping(
        framework=framework,
        requirement_id=req_id,
        requirement_name=req_name,
        status=status,
    )


def _cwe(cwe_id: str, desc: str) -> CVECorrelation:
    return CVECorrelation(cve_id=cwe_id, cvss_score=0.0, description=desc)


_OWASP_A01 = _compliance("OWASP_TOP_10_2025", "A01", "Broken Access Control")
_PCI_6_2_4 = _compliance("PCI_DSS_4_0", "6.2.4", "Common Software Attack Mitigations")
_NIST_SC_23 = _compliance("NIST_SP_800_53", "SC-23", "Session Authenticity")
_CWE_352 = _cwe("CWE-352", "Cross-Site Request Forgery (CSRF)")
_CWE_693 = _cwe("CWE-693", "Protection Mechanism Failure")

_REFERENCE_URL = "https://web.dev/articles/fetch-metadata"

_NON_BROWSER_CAVEAT = (
    "Caveat: non-browser scripted clients can bypass this control regardless "
    "of enforcement status. Fetch Metadata defends against browser-based CSRF "
    "and cross-origin data leaks, not API abuse or server-to-server attacks."
)

_CDN_WARNING = (
    " A CDN was fingerprinted on the response; in rare cases the CDN may strip "
    "Sec-Fetch-* headers before reaching origin. Verify on a direct-origin scan."
)

_EXAMPLE_POLICY = """\
# Pseudo-code: reference Fetch Metadata resource isolation policy.
def is_allowed(request):
    site = request.headers.get('Sec-Fetch-Site', '')
    mode = request.headers.get('Sec-Fetch-Mode', '')
    dest = request.headers.get('Sec-Fetch-Dest', '')
    if site in ('', 'same-origin', 'same-site', 'none'):
        return True
    if mode == 'navigate' and request.method == 'GET' and dest not in ('object', 'embed'):
        return True
    return False  # cross-site non-navigate GET / cross-site POST → reject
"""


# ----------------------------------------------------------------------------
# Templates
# ----------------------------------------------------------------------------

# Stored at HIGH severity so deepcopy + downgrade is the worst-case path.
_FM_NO_POLICY_TEMPLATE = Finding(
    header="Sec-Fetch-Site",
    category=HeaderCategory.ISOLATION,
    severity=Severity.HIGH,
    title="No Fetch Metadata Resource Isolation Policy",
    description=(
        "The server returned the same response to a Sec-Fetch-Site: cross-site "
        "probe as to a Sec-Fetch-Site: same-origin probe, indicating no Fetch "
        "Metadata resource isolation policy is enforced. Browser-initiated "
        "cross-site requests (CSRF via fetch, cross-origin data leaks via "
        "no-cors) are not blocked at the server layer.\n\n"
        "{mitigation_note}\n\n" + _NON_BROWSER_CAVEAT
    ),
    current_value=None,
    recommendation=(
        "Implement a server-side resource isolation policy that rejects requests "
        "where Sec-Fetch-Site is cross-site and Sec-Fetch-Mode is not navigate. "
        "Start in logging mode to identify endpoints that need cross-site "
        "exemptions, then switch to blocking. Reference: "
        "https://web.dev/articles/fetch-metadata"
    ),
    example_value=_EXAMPLE_POLICY,
    reference_url=_REFERENCE_URL,
    compliance_mappings=[_OWASP_A01, _PCI_6_2_4, _NIST_SC_23],
    cve_correlations=[_CWE_352, _CWE_693],
)

_FM_ENFORCED_TEMPLATE = Finding(
    header="Sec-Fetch-Site",
    category=HeaderCategory.ISOLATION,
    severity=Severity.PASS,
    title="Fetch Metadata Resource Isolation Policy Enforced",
    description=(
        "The server returned a rejection response (4xx) to a cross-site Fetch "
        "Metadata probe while allowing the same-origin probe. A resource "
        "isolation policy is active and blocking browser-initiated cross-site "
        "requests."
    ),
    current_value=None,
    recommendation=(
        "No action required. Consider logging enforcement rejections for "
        "threat intelligence and reviewing whether sensitive endpoints would "
        "benefit from stricter Sec-Fetch-Mode constraints."
    ),
    example_value="(positive coverage — no remediation needed)",
    reference_url=_REFERENCE_URL,
    compliance_mappings=[],
    cve_correlations=[_cwe("CWE-352", "Cross-Site Request Forgery (positive coverage)")],
)

_FM_INCONCLUSIVE_TEMPLATE = Finding(
    header="Sec-Fetch-Site",
    category=HeaderCategory.ISOLATION,
    severity=Severity.INFO,
    title="Fetch Metadata Probe Inconclusive",
    description=(
        "The Fetch Metadata enforcement probe produced an ambiguous result: "
        "{reason}. This may indicate CDN or reverse proxy header stripping, an "
        "authentication wall preventing probe differentiation, or a "
        "non-standard enforcement response. Manual verification is required."
    ),
    current_value=None,
    recommendation=(
        "Scan the origin directly (bypassing CDN) to confirm or rule out "
        "enforcement. Check application middleware for Fetch Metadata policy "
        "implementation."
    ),
    example_value="N/A",
    reference_url=_REFERENCE_URL,
    compliance_mappings=[],
    cve_correlations=[],
)


ALL_FM_FINDINGS: dict[str, Finding] = {
    "FM_NO_FETCH_METADATA_POLICY": _FM_NO_POLICY_TEMPLATE,
    "FM_FETCH_METADATA_ENFORCED": _FM_ENFORCED_TEMPLATE,
    "FM_FETCH_METADATA_INCONCLUSIVE": _FM_INCONCLUSIVE_TEMPLATE,
}


def get_finding(finding_id: str) -> Optional[Finding]:
    """Return a deep copy of a finding template, or None if unknown."""
    template = ALL_FM_FINDINGS.get(finding_id)
    if template is None:
        return None
    return copy.deepcopy(template)


# ----------------------------------------------------------------------------
# Severity calibration
# ----------------------------------------------------------------------------

@dataclass(frozen=True)
class FMContext:
    has_samesite_strict: bool
    has_samesite_lax: bool
    has_csrf_token: bool
    cdn_detected: bool


def _calibrate_severity(ctx: FMContext) -> Severity:
    """Apply spec §5.1 matrix. SameSite=Strict + CSRF token → LOW.
    Partial mitigations (Lax XOR token) → MEDIUM (or LOW with CDN downgrade).
    No mitigations → HIGH (or MEDIUM with CDN downgrade).
    """
    full_mitigations = ctx.has_samesite_strict and ctx.has_csrf_token
    partial_mitigations = (
        ctx.has_samesite_lax or ctx.has_csrf_token
    ) and not full_mitigations
    no_mitigations = not (full_mitigations or partial_mitigations)

    if full_mitigations:
        return Severity.LOW

    if partial_mitigations:
        return Severity.LOW if ctx.cdn_detected else Severity.MEDIUM

    # no_mitigations
    return Severity.MEDIUM if ctx.cdn_detected else Severity.HIGH


def _build_mitigation_note(ctx: FMContext) -> str:
    full_mitigations = ctx.has_samesite_strict and ctx.has_csrf_token
    partial_mitigations = (
        ctx.has_samesite_lax or ctx.has_csrf_token
    ) and not full_mitigations

    if full_mitigations:
        note = (
            "SameSite=Strict cookies and a CSRF token were detected. Fetch "
            "Metadata enforcement would add a third independent layer."
        )
    elif partial_mitigations:
        signals = []
        if ctx.has_samesite_lax:
            signals.append("SameSite=Lax")
        if ctx.has_csrf_token:
            signals.append("CSRF token")
        note = (
            "Partial CSRF mitigations detected: "
            + " and ".join(signals)
            + ". Adding Fetch Metadata enforcement would strengthen "
            "defense-in-depth."
        )
    else:
        note = (
            "No CSRF token cookie or SameSite=Strict cookie was detected on "
            "this endpoint."
        )

    if ctx.cdn_detected:
        note += _CDN_WARNING

    return note


def build_not_enforced_finding(ctx: FMContext, soft: bool) -> Finding:
    """Construct an FM_NO_FETCH_METADATA_POLICY finding calibrated to context.

    `soft=True` collapses severity to INFO (SOFT_ENFORCED case).
    """
    f = get_finding("FM_NO_FETCH_METADATA_POLICY")
    assert f is not None  # template is registered.

    if soft:
        f.severity = Severity.INFO
        soft_prefix = (
            "Soft enforcement detected — server returned modified content "
            "rather than 4xx; verify the policy actively blocks unauthorized "
            "cross-site access. "
        )
        f.description = soft_prefix + f.description.replace(
            "{mitigation_note}", _build_mitigation_note(ctx)
        )
        f.compliance_mappings = []
        return f

    severity = _calibrate_severity(ctx)
    f.severity = severity
    f.description = f.description.replace(
        "{mitigation_note}", _build_mitigation_note(ctx)
    )

    # Compliance mappings vary by severity per spec §5.1.
    mappings: list[ComplianceMapping] = [_OWASP_A01]
    if severity == Severity.HIGH:
        mappings.extend([_PCI_6_2_4, _NIST_SC_23])
    elif severity == Severity.MEDIUM:
        mappings.append(_NIST_SC_23)
    f.compliance_mappings = mappings

    return f


def build_inconclusive_finding(reason: str) -> Finding:
    """Construct an FM_FETCH_METADATA_INCONCLUSIVE finding with the given reason."""
    f = get_finding("FM_FETCH_METADATA_INCONCLUSIVE")
    assert f is not None
    f.description = f.description.replace("{reason}", reason)
    return f


def build_enforced_finding() -> Finding:
    """Construct an FM_FETCH_METADATA_ENFORCED PASS finding."""
    f = get_finding("FM_FETCH_METADATA_ENFORCED")
    assert f is not None
    return f
