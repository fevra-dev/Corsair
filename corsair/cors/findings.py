"""
CORS DAST finding definitions (Wave 1).

Ships 5 Core finding classes covering the highest-impact CORS misconfigurations:
- Arbitrary-origin reflection (±credentials)
- Null-origin trust (±credentials)
- Wildcard ACAO + credentials

Plus 2 meta findings for inconclusive runs and phase timeouts.

Additional 11 findings (subdomain bypass, protocol downgrade, internal origin,
preflight divergence, cache-key divergence, framework default, third-party XSS,
broad methods/headers, post leak) ship in Waves 2-4.
"""

import copy
from typing import Optional

from ..models import (
    ComplianceMapping,
    CVECorrelation,
    Finding,
    HeaderCategory,
    Severity,
)


def _compliance(framework: str, req_id: str, req_name: str, status: str = "FAIL"):
    return ComplianceMapping(
        framework=framework,
        requirement_id=req_id,
        requirement_name=req_name,
        status=status,
    )


def _cwe(cwe_id: str, desc: str):
    return CVECorrelation(cve_id=cwe_id, cvss_score=0.0, description=desc)


_OWASP_A05 = _compliance("OWASP_TOP_10_2025", "A05", "Security Misconfiguration")
_OWASP_A01 = _compliance("OWASP_TOP_10_2025", "A01", "Broken Access Control")
_PCI_6_2 = _compliance("PCI_DSS_4_0", "6.2", "Secure Development")
_CWE_942 = _cwe("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains")
_CWE_346 = _cwe("CWE-346", "Origin Validation Error")

_MDN_URL = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
_PORTSWIGGER_URL = "https://portswigger.net/web-security/cors"


# -- Core 5 -----------------------------------------------------------------

_CORS_ARBITRARY_ORIGIN_CRED = Finding(
    header="Access-Control-Allow-Origin",
    category=HeaderCategory.CORS,
    severity=Severity.CRITICAL,
    title="Arbitrary origin reflected with credentials",
    description=(
        "The server reflected an attacker-controlled Origin value in "
        "Access-Control-Allow-Origin AND returned Access-Control-Allow-Credentials: "
        "true. Any website a victim visits can read authenticated responses from "
        "this endpoint, enabling account takeover and data theft. This is the "
        "highest-impact CORS misconfiguration."
    ),
    current_value=None,
    recommendation=(
        "Never reflect Origin blindly when ACAC: true. Maintain a strict allowlist "
        "of trusted origins and reject all others. If dynamic allowlisting is "
        "required, validate against a known-good list before echoing Origin."
    ),
    example_value="Access-Control-Allow-Origin: https://trusted.example.com",
    reference_url=_PORTSWIGGER_URL,
    compliance_mappings=[_OWASP_A01, _OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_346, _CWE_942],
)

_CORS_ARBITRARY_ORIGIN = Finding(
    header="Access-Control-Allow-Origin",
    category=HeaderCategory.CORS,
    severity=Severity.HIGH,
    title="Arbitrary origin reflected (no credentials)",
    description=(
        "The server reflected an attacker-controlled Origin value in "
        "Access-Control-Allow-Origin without Access-Control-Allow-Credentials. "
        "Attackers can read responses from this endpoint. Impact depends on what "
        "the endpoint returns under anonymous access — a public API echoing "
        "Origin is low-risk, but any endpoint leaking IP, tokens, or internal data "
        "to any origin is a material finding."
    ),
    current_value=None,
    recommendation=(
        "Reflect Origin only from a strict allowlist. If the endpoint truly needs "
        "any-origin access, use Access-Control-Allow-Origin: * instead of echoing."
    ),
    example_value="Access-Control-Allow-Origin: https://trusted.example.com",
    reference_url=_PORTSWIGGER_URL,
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_346],
)

_CORS_NULL_ORIGIN_CRED = Finding(
    header="Access-Control-Allow-Origin",
    category=HeaderCategory.CORS,
    severity=Severity.HIGH,
    title="Null origin trusted with credentials",
    description=(
        "The server accepts Origin: null AND returns ACAC: true. The null origin "
        "is sent by sandboxed iframes, data: URLs, and file: contexts — all of "
        "which can be attacker-controlled. This grants attackers credentialed "
        "cross-origin access through a sandboxed iframe."
    ),
    current_value=None,
    recommendation=(
        "Never allow Origin: null. Reject it explicitly in your CORS middleware."
    ),
    example_value="Access-Control-Allow-Origin: https://trusted.example.com",
    reference_url=_PORTSWIGGER_URL,
    compliance_mappings=[_OWASP_A01, _OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_346, _CWE_942],
)

_CORS_NULL_ORIGIN = Finding(
    header="Access-Control-Allow-Origin",
    category=HeaderCategory.CORS,
    severity=Severity.MEDIUM,
    title="Null origin trusted (no credentials)",
    description=(
        "The server accepts Origin: null without credentials. Attackers can read "
        "responses from sandboxed iframe contexts. Impact is limited to what the "
        "endpoint returns anonymously, but null should not be on any allowlist."
    ),
    current_value=None,
    recommendation="Reject Origin: null explicitly in CORS middleware.",
    example_value="Access-Control-Allow-Origin: https://trusted.example.com",
    reference_url=_PORTSWIGGER_URL,
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_346],
)

_CORS_WILDCARD_CRED = Finding(
    header="Access-Control-Allow-Origin",
    category=HeaderCategory.CORS,
    severity=Severity.MEDIUM,
    title="Wildcard Access-Control-Allow-Origin with credentials",
    description=(
        "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials "
        "is 'true'. Browsers reject this combination, so it is not directly "
        "exploitable — but the configuration reveals a security misunderstanding "
        "that likely applies to adjacent endpoints and warrants manual review."
    ),
    current_value=None,
    recommendation=(
        "Use a specific origin instead of wildcard when credentials are needed. "
        "Audit other endpoints on the same service for similar misconfiguration."
    ),
    example_value="Access-Control-Allow-Origin: https://trusted.example.com",
    reference_url=_MDN_URL,
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_346],
)


# -- Meta findings ----------------------------------------------------------

_CORS_PROBE_INCONCLUSIVE = Finding(
    header="Access-Control-Allow-Origin",
    category=HeaderCategory.CORS,
    severity=Severity.INFO,
    title="CORS probing inconclusive",
    description=(
        "Active CORS probing could not reach a verdict. The target returned 401, "
        "403, or 5xx on every probe, or the probes were skipped because the "
        "target is not HTTP-reachable. Manual testing is recommended if the "
        "endpoint is expected to support CORS."
    ),
    current_value=None,
    recommendation=(
        "Verify manually with an authenticated request if CORS behavior is "
        "expected. Otherwise no action required."
    ),
    example_value="N/A",
    reference_url=_PORTSWIGGER_URL,
)

_CORS_PHASE_TIMEOUT = Finding(
    header="Access-Control-Allow-Origin",
    category=HeaderCategory.CORS,
    severity=Severity.INFO,
    title="CORS probe phase timed out",
    description=(
        "A CORS probing phase exceeded the 60-second global timeout and was "
        "cancelled. Partial findings (if any) are still reported. Consider "
        "re-running with a longer --timeout or scanning a more responsive endpoint."
    ),
    current_value=None,
    recommendation="Re-scan with --timeout 120 if the target is known to be slow.",
    example_value="N/A",
    reference_url=_PORTSWIGGER_URL,
)


# -- Registry ---------------------------------------------------------------

ALL_CORS_FINDINGS: dict[str, Finding] = {
    "CORS_ARBITRARY_ORIGIN_CRED": _CORS_ARBITRARY_ORIGIN_CRED,
    "CORS_ARBITRARY_ORIGIN": _CORS_ARBITRARY_ORIGIN,
    "CORS_NULL_ORIGIN_CRED": _CORS_NULL_ORIGIN_CRED,
    "CORS_NULL_ORIGIN": _CORS_NULL_ORIGIN,
    "CORS_WILDCARD_CRED": _CORS_WILDCARD_CRED,
    "CORS_PROBE_INCONCLUSIVE": _CORS_PROBE_INCONCLUSIVE,
    "CORS_PHASE_TIMEOUT": _CORS_PHASE_TIMEOUT,
}


def get_finding(finding_id: str) -> Optional[Finding]:
    """Return a deep copy of a finding template, or None if unknown."""
    template = ALL_CORS_FINDINGS.get(finding_id)
    if template is None:
        return None
    return copy.deepcopy(template)
