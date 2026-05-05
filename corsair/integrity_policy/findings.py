"""Integrity-Policy finding templates, registry, and builders.

Mirrors corsair/fetch_metadata/findings.py. Public API:
  - get_finding(finding_id) -> Finding | None  (deepcopy of static template)
  - build_ip_003_finding(raw_value)
  - build_ip_006_finding(scripts, truncated)
  - build_ip_006_pass_finding(truncated)
  - build_ip_006_inconclusive_finding(error_reason)
  - build_ip_static_pass_finding()
"""

import copy
from typing import List, Optional

from ..models import (
    ComplianceMapping,
    CVECorrelation,
    Finding,
    HeaderCategory,
    Severity,
)


# ---------------------------------------------------------------------------
# DRY helpers
# ---------------------------------------------------------------------------

def _compliance(
    framework: str, req_id: str, req_name: str, status: str = "FAIL"
) -> ComplianceMapping:
    return ComplianceMapping(
        framework=framework,
        requirement_id=req_id,
        requirement_name=req_name,
        status=status,
    )


def _cwe(cwe_id: str, desc: str) -> CVECorrelation:
    return CVECorrelation(cve_id=cwe_id, cvss_score=0.0, description=desc)


# ---------------------------------------------------------------------------
# Compliance / CWE constants
# ---------------------------------------------------------------------------

_OWASP_A08 = _compliance(
    "OWASP_TOP_10_2021", "A08", "Software and Data Integrity Failures"
)
_NIST_SI_7 = _compliance(
    "NIST_SP_800_53", "SI-7", "Software, Firmware, and Information Integrity"
)
_PCI_6_4_3 = _compliance(
    "PCI_DSS_4_0", "6.4.3", "Manage all payment page scripts loaded in the browser"
)
_CWE_353 = _cwe("CWE-353", "Missing Support for Integrity Check")
_CWE_494 = _cwe("CWE-494", "Download of Code Without Integrity Check")
_CWE_829 = _cwe(
    "CWE-829", "Inclusion of Functionality from Untrusted Control Sphere"
)

_REFERENCE_URL = (
    "https://w3c.github.io/webappsec-subresource-integrity/"
    "#integrity-policy-section"
)

# ---------------------------------------------------------------------------
# IP-001: Integrity-Policy header absent
# ---------------------------------------------------------------------------

_IP_001_TEMPLATE = Finding(
    header="Integrity-Policy",
    category=HeaderCategory.INTEGRITY,
    severity=Severity.LOW,
    title="Integrity-Policy header absent",
    description=(
        "Neither Integrity-Policy nor Integrity-Policy-Report-Only is set. The "
        "browser will not enforce any baseline requirement that subresources "
        "carry an integrity attribute, so a compromised CDN or third-party host "
        "can serve modified script/style without detection. Even sites that "
        "currently set integrity= on every <script> tag benefit from defining "
        "Integrity-Policy as a policy gate, because policy survives template "
        "regressions and partial deployments.\n\n"
        "Impact: Compromised third-party scripts can execute without browser "
        "intervention."
    ),
    current_value=None,
    recommendation=(
        "Define an Integrity-Policy header in Report-Only mode first to "
        "discover scripts lacking integrity, then upgrade to enforcing once "
        "all in-scope scripts carry sha384 integrity attributes."
    ),
    example_value=(
        "Integrity-Policy: blocked-destinations=(script), endpoints=(default)"
    ),
    reference_url=_REFERENCE_URL,
    cve_correlations=[_CWE_353, _CWE_494],
    compliance_mappings=[_OWASP_A08, _NIST_SI_7, _PCI_6_4_3],
)


# ---------------------------------------------------------------------------
# Registry: static templates accessible via get_finding(finding_id)
# ---------------------------------------------------------------------------

_REGISTRY: dict = {
    "IP-001": _IP_001_TEMPLATE,
}


def get_finding(finding_id: str) -> Optional[Finding]:
    """Return a deepcopy of the static template for a finding ID."""
    template = _REGISTRY.get(finding_id)
    if template is None:
        return None
    return copy.deepcopy(template)

# ---------------------------------------------------------------------------
# IP-002: Integrity-Policy-Report-Only set without enforcing Integrity-Policy
# ---------------------------------------------------------------------------

_IP_002_TEMPLATE = Finding(
    header="Integrity-Policy-Report-Only",
    category=HeaderCategory.INTEGRITY,
    severity=Severity.INFO,
    title="Integrity-Policy in Report-Only mode without enforcing counterpart",
    description=(
        "Integrity-Policy-Report-Only is set but Integrity-Policy is not. "
        "Report-Only is a discovery aid: violations are reported via the "
        "Reporting API but the browser does not block any requests. Sites "
        "that have completed integrity rollout should promote to enforcing "
        "Integrity-Policy.\n\n"
        "Impact: Discovery posture only; no protection against compromised "
        "subresources."
    ),
    current_value=None,
    recommendation=(
        "Once Reporting API confirms zero violations under Report-Only, "
        "duplicate the directive into the enforcing Integrity-Policy header."
    ),
    example_value=(
        "Integrity-Policy: blocked-destinations=(script), endpoints=(default)"
    ),
    reference_url=_REFERENCE_URL,
    cve_correlations=[_CWE_353],
    compliance_mappings=[_OWASP_A08],
)

_REGISTRY["IP-002"] = _IP_002_TEMPLATE

# ---------------------------------------------------------------------------
# IP-003: Integrity-Policy parse error / no recognized destinations
# ---------------------------------------------------------------------------

_IP_003_TEMPLATE = Finding(
    header="Integrity-Policy",
    category=HeaderCategory.INTEGRITY,
    severity=Severity.LOW,
    title="Integrity-Policy header has no recognized destinations",
    description=(
        "Integrity-Policy is set but cannot be parsed as an RFC 9651 "
        "Structured Field Dictionary, or contains no recognized destination "
        "tokens. Browsers treat unparseable Integrity-Policy values as "
        "absent, so this site has the same effective protection as if no "
        "Integrity-Policy header were sent.\n\n"
        "Impact: Header is sent but ignored by the browser; no integrity "
        "enforcement."
    ),
    current_value=None,
    recommendation=(
        "Use the SF Dictionary syntax: blocked-destinations=(script), "
        "sources=(inline), endpoints=(name). Recognized destination tokens "
        "today are 'script' and 'style'."
    ),
    example_value=(
        "Integrity-Policy: blocked-destinations=(script), endpoints=(default)"
    ),
    reference_url=_REFERENCE_URL,
    cve_correlations=[_CWE_353],
    compliance_mappings=[_OWASP_A08],
)

_REGISTRY["IP-003"] = _IP_003_TEMPLATE


def build_ip_003_finding(raw_value: str) -> Finding:
    """Build IP-003 with the raw header value embedded for diagnostic context."""
    finding = copy.deepcopy(_IP_003_TEMPLATE)
    finding.current_value = raw_value
    finding.description = (
        finding.description
        + f"\n\nRaw header value (verbatim): {raw_value!r}"
    )
    return finding

# ---------------------------------------------------------------------------
# IP-004: Integrity-Policy lacks 'script' in blocked-destinations
# ---------------------------------------------------------------------------

_IP_004_TEMPLATE = Finding(
    header="Integrity-Policy",
    category=HeaderCategory.INTEGRITY,
    severity=Severity.LOW,
    title="Integrity-Policy does not block script destinations",
    description=(
        "Integrity-Policy is set but 'script' is not in blocked-destinations. "
        "Scripts are the highest-value target for subresource integrity "
        "enforcement because they execute arbitrary code. A policy that "
        "blocks only 'style' (or any other destination) misses the most "
        "impactful protection class.\n\n"
        "Impact: Subresource integrity enforcement applied to non-script "
        "destinations only."
    ),
    current_value=None,
    recommendation=(
        "Add 'script' to blocked-destinations. Style enforcement can coexist: "
        "blocked-destinations=(script style)."
    ),
    example_value=(
        "Integrity-Policy: blocked-destinations=(script), endpoints=(default)"
    ),
    reference_url=_REFERENCE_URL,
    cve_correlations=[_CWE_353, _CWE_829],
    compliance_mappings=[_OWASP_A08, _PCI_6_4_3],
)

_REGISTRY["IP-004"] = _IP_004_TEMPLATE

# ---------------------------------------------------------------------------
# IP-006: enforcing Integrity-Policy + cross-origin script lacking integrity
# ---------------------------------------------------------------------------

_IP_006_TEMPLATE = Finding(
    header="Integrity-Policy",
    category=HeaderCategory.INTEGRITY,
    severity=Severity.HIGH,
    title="Enforcing Integrity-Policy + scripts lacking integrity attribute",
    description=(
        "Integrity-Policy is enforcing 'script' blocking, but the document "
        "body contains one or more cross-origin <script> tags without an "
        "integrity attribute. In Chrome 138+, Firefox 145+, and Safari 26+, "
        "these scripts will be blocked by the browser, breaking page "
        "functionality. This is the page-breaking enforcement scenario.\n\n"
        "Note: scripts injected dynamically via JavaScript are not visible to "
        "this scan; only scripts present in the initial server response are "
        "examined. False positives in HTML comments and <noscript> subtrees "
        "are documented in the Corsair v0.5.5 spec — verify in browser "
        "console before remediating.\n\n"
        "Impact: Browser will block listed scripts; pages that depend on them "
        "will fail."
    ),
    current_value=None,
    recommendation=(
        "Add integrity attributes to each cross-origin <script>:\n"
        "  cat script.js | openssl dgst -sha384 -binary | openssl base64 -A\n"
        "Embed: <script src=\"...\" integrity=\"sha384-<hash>\" "
        "crossorigin=\"anonymous\"></script>\n\n"
        "Fallback: demote to Integrity-Policy-Report-Only until the rollout "
        "completes, monitor reports, then re-enforce."
    ),
    example_value=(
        "<script src=\"https://cdn.example.com/lib.js\" "
        "integrity=\"sha384-<hash>\" crossorigin=\"anonymous\"></script>"
    ),
    reference_url=_REFERENCE_URL,
    cve_correlations=[_CWE_353, _CWE_494, _CWE_829],
    compliance_mappings=[_OWASP_A08, _NIST_SI_7, _PCI_6_4_3],
)


_IP_006_PASS_TEMPLATE = Finding(
    header="Integrity-Policy",
    category=HeaderCategory.INTEGRITY,
    severity=Severity.PASS,
    title="Integrity-Policy enforcing — all examined scripts have integrity",
    description=(
        "Integrity-Policy is enforcing 'script' blocking and every cross-origin "
        "<script> tag in the response body carries an integrity attribute. "
        "This PASS does not guarantee coverage of authenticated routes or "
        "dynamically-injected scripts."
    ),
    current_value=None,
    recommendation="Continue monitoring via the configured reporting endpoint.",
    example_value="(positive coverage — no remediation needed)",
    reference_url=_REFERENCE_URL,
    cve_correlations=[],
    compliance_mappings=[],
)


_IP_006_INCONCLUSIVE_TEMPLATE = Finding(
    header="Integrity-Policy",
    category=HeaderCategory.INTEGRITY,
    severity=Severity.INFO,
    title="Integrity-Policy enforcement check inconclusive",
    description=(
        "Integrity-Policy is enforcing 'script' blocking, but the document "
        "body could not be retrieved to verify whether scripts carry "
        "integrity attributes. Manual verification recommended.\n\n"
        "Impact: Audit gap: scripts lacking integrity may be present."
    ),
    current_value=None,
    recommendation=(
        "Re-run the scan when the target is reachable, or verify in browser."
    ),
    example_value="N/A",
    reference_url=_REFERENCE_URL,
    cve_correlations=[],
    compliance_mappings=[],
)


_IP_STATIC_PASS_TEMPLATE = Finding(
    header="Integrity-Policy",
    category=HeaderCategory.INTEGRITY,
    severity=Severity.PASS,
    title="Integrity-Policy header configured with script enforcement",
    description=(
        "Integrity-Policy is set with 'script' in blocked-destinations. "
        "Static configuration check passed.\n\n"
        "Impact: Header configured to enforce script subresource integrity."
    ),
    current_value=None,
    recommendation="No change required.",
    example_value="(positive coverage — no remediation needed)",
    reference_url=_REFERENCE_URL,
    cve_correlations=[],
    compliance_mappings=[],
)


def build_ip_006_finding(scripts: List[str], truncated: bool = False) -> Finding:
    """IP-006 with the offending script list + optional truncation note."""
    finding = copy.deepcopy(_IP_006_TEMPLATE)
    count = len(scripts)
    listed = "\n".join(f"- {s}" for s in scripts)
    finding.current_value = (
        f"{count} cross-origin script(s) lacking integrity:\n{listed}"
    )
    if truncated:
        finding.description = (
            finding.description
            + "\n\nNote: response body was truncated at 1 MB; some scripts "
            "may not have been examined."
        )
    return finding


def build_ip_006_pass_finding(truncated: bool = False) -> Finding:
    finding = copy.deepcopy(_IP_006_PASS_TEMPLATE)
    if truncated:
        finding.description = (
            finding.description
            + "\n\nNote: response body was truncated at 1 MB; PASS reflects "
            "only the examined prefix."
        )
    return finding


def build_ip_006_inconclusive_finding(error_reason: str) -> Finding:
    finding = copy.deepcopy(_IP_006_INCONCLUSIVE_TEMPLATE)
    finding.current_value = error_reason
    finding.description = (
        finding.description + f"\n\nBody fetch failed: {error_reason}"
    )
    return finding


def build_ip_static_pass_finding() -> Finding:
    return copy.deepcopy(_IP_STATIC_PASS_TEMPLATE)
