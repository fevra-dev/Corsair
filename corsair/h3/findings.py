"""HTTP/3 finding templates and builders.

Mirrors corsair/integrity_policy/findings.py. Public API:
  - get_finding(finding_id) -> Finding | None  (deepcopy of static template)
  - build_h3_001_high / _low / _pass
  - build_h3_002_finding / _pass
  - build_h3_003_finding
  - build_h3_inconclusive_finding(error)
  - build_h3_extras_missing_finding()
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
from .diff import HeaderDiffResult


# ---------------------------------------------------------------------------
# DRY helpers
# ---------------------------------------------------------------------------

def _compliance(framework: str, req_id: str, req_name: str, status: str = "FAIL") -> ComplianceMapping:
    return ComplianceMapping(
        framework=framework, requirement_id=req_id, requirement_name=req_name, status=status,
    )


def _cwe(cwe_id: str, desc: str) -> CVECorrelation:
    return CVECorrelation(cve_id=cwe_id, cvss_score=0.0, description=desc)


def _cve(cve_id: str, desc: str, cvss: float) -> CVECorrelation:
    return CVECorrelation(cve_id=cve_id, cvss_score=cvss, description=desc)


# ---------------------------------------------------------------------------
# Compliance / CWE constants
# ---------------------------------------------------------------------------

_OWASP_A05 = _compliance("OWASP_TOP_10_2021", "A05", "Security Misconfiguration")
_OWASP_A06 = _compliance("OWASP_TOP_10_2021", "A06", "Vulnerable and Outdated Components")
_OWASP_A07 = _compliance("OWASP_TOP_10_2021", "A07", "Identification and Authentication Failures")
_PCI_6_2_4 = _compliance("PCI_DSS_4_0", "6.2.4", "Software protected against common attacks")
_PCI_6_4_3 = _compliance("PCI_DSS_4_0", "6.4.3", "Manage all payment page scripts loaded in the browser")
_NIST_SC_23 = _compliance("NIST_SP_800_53", "SC-23", "Session Authenticity")
_NIST_SP_800_52 = _compliance("NIST_SP_800_53", "SC-12", "TLS 1.3 0-RTT guidance (SP 800-52r2 §3.6)")
_NIST_RA_5 = _compliance("NIST_SP_800_53", "RA-5", "Vulnerability Monitoring and Scanning")

_CWE_294 = _cwe("CWE-294", "Authentication Bypass by Capture-Replay")
_CWE_400 = _cwe("CWE-400", "Uncontrolled Resource Consumption")
_CWE_770 = _cwe("CWE-770", "Allocation of Resources Without Limits or Throttling")
_CWE_693 = _cwe("CWE-693", "Protection Mechanism Failure")
_CVE_2024_39321 = _cve("CVE-2024-39321", "Traefik IP-allowlist bypass via 0-RTT", 7.5)
_CVE_2025_54939 = _cve("CVE-2025-54939", "LSQUIC pre-handshake memory exhaustion", 9.1)


_REF_RFC_8470 = "https://www.rfc-editor.org/rfc/rfc8470.html"
_REF_RFC_9114 = "https://www.rfc-editor.org/rfc/rfc9114.html"
_REF_LSQUIC_ADVISORY = "https://github.com/litespeedtech/lsquic/security/advisories"


# ---------------------------------------------------------------------------
# Static templates (no per-scan context)
# ---------------------------------------------------------------------------

_H3_001_HIGH_TEMPLATE = Finding(
    header="QUIC Early Data",
    category=HeaderCategory.H3,
    severity=Severity.HIGH,
    title="HTTP/3 0-RTT — server vulnerable to early-data replay",
    description=(
        "The server advertises 0-RTT capability via TLS 1.3 NewSessionTicket "
        "(max_early_data_size > 0) and does NOT reject requests carrying the "
        "Early-Data: 1 hint with HTTP 425 Too Early. An on-path attacker can "
        "replay any captured 0-RTT request, including non-idempotent operations "
        "(POST, PUT, DELETE), against the same server until the session ticket "
        "expires. RFC 8470 mandates that early-data-aware servers reject "
        "non-idempotent requests with 425.\n\n"
        "Real-world exploitation has been demonstrated in CVE-2024-39321 "
        "(Traefik IP-allowlist bypass via 0-RTT replay)."
    ),
    current_value=None,
    recommendation=(
        "Disable 0-RTT on the QUIC listener (set max_early_data_size=0) OR "
        "honor RFC 8470 by returning 425 Too Early when Early-Data: 1 is "
        "present and the request is non-idempotent."
    ),
    example_value="max_early_data_size=0  (disabled)",
    reference_url=_REF_RFC_8470,
    cve_correlations=[_CVE_2024_39321, _CWE_294],
    compliance_mappings=[_OWASP_A07, _PCI_6_2_4, _NIST_SP_800_52],
)

_H3_001_LOW_TEMPLATE = Finding(
    header="QUIC Early Data",
    category=HeaderCategory.H3,
    severity=Severity.LOW,
    title="HTTP/3 0-RTT — early-data hint not honored (low risk)",
    description=(
        "The server does NOT advertise 0-RTT capability (max_early_data_size = 0) "
        "but also does not reject requests with the Early-Data: 1 hint via "
        "HTTP 425. There is no actual replay vector here — without 0-RTT, "
        "there is no early data to replay — but the proxy/origin may be "
        "misconfigured: an upstream proxy that DOES accept 0-RTT could forward "
        "to this origin and the origin would not protect non-idempotent "
        "requests. RFC 8470 recommends honoring Early-Data: 1 even when the "
        "origin itself does not accept 0-RTT directly."
    ),
    current_value=None,
    recommendation=(
        "If a proxy in front of this origin accepts 0-RTT, configure the origin "
        "to return 425 Too Early when Early-Data: 1 is present and the request "
        "is non-idempotent. RFC 8470 §5."
    ),
    example_value="HTTP/1.1 425 Too Early",
    reference_url=_REF_RFC_8470,
    cve_correlations=[_CWE_294],
    compliance_mappings=[_OWASP_A07, _NIST_SP_800_52],
)

_H3_001_PASS_TEMPLATE = Finding(
    header="QUIC Early Data",
    category=HeaderCategory.H3,
    severity=Severity.PASS,
    title="HTTP/3 0-RTT — server correctly rejects early-data hints",
    description=(
        "The server advertises 0-RTT capability AND correctly rejects requests "
        "with the Early-Data: 1 hint via HTTP 425 Too Early per RFC 8470. "
        "This is the secure configuration."
    ),
    current_value=None,
    recommendation="No action required. Configuration is correct.",
    example_value=None,
    reference_url=_REF_RFC_8470,
    cve_correlations=[],
    compliance_mappings=[
        ComplianceMapping(
            framework="OWASP_TOP_10_2021", requirement_id="A07",
            requirement_name="Identification and Authentication Failures",
            status="PASS",
        ),
    ],
)


_H3_002_PASS_TEMPLATE = Finding(
    header="HTTP/3 vs HTTP/1.1 Headers",
    category=HeaderCategory.H3,
    severity=Severity.PASS,
    title="HTTP/3 and HTTP/1.1 security headers are consistent",
    description=(
        "The security-relevant response headers are identical across HTTP/1.1 "
        "and HTTP/3. No drift was detected in HSTS, CSP, COOP/COEP, X-Frame-"
        "Options, or other allowlist headers."
    ),
    current_value=None,
    recommendation="No action required.",
    example_value=None,
    reference_url=_REF_RFC_9114,
    cve_correlations=[],
    compliance_mappings=[
        ComplianceMapping(
            framework="OWASP_TOP_10_2021", requirement_id="A05",
            requirement_name="Security Misconfiguration",
            status="PASS",
        ),
    ],
)


_H3_003_TEMPLATE = Finding(
    header="QUIC Server",
    category=HeaderCategory.H3,
    severity=Severity.CRITICAL,
    title="LSQUIC pre-handshake DoS (CVE-2025-54939)",
    description=(
        "The Server header identifies LiteSpeed/OpenLiteSpeed AND the response "
        "advertises HTTP/3 via Alt-Svc. LiteSpeed's QUIC implementation (LSQUIC) "
        "before version 4.3.1 is vulnerable to CVE-2025-54939, a pre-handshake "
        "memory-exhaustion DoS. An unauthenticated remote attacker can crash the "
        "QUIC worker process by sending a small volume of malformed handshake "
        "packets.\n\n"
        "This finding is passive — Corsair did not exploit the vulnerability. "
        "It correlates the Server identification with the presence of an h3 "
        "advertisement to confirm the vulnerable QUIC stack is actually serving "
        "HTTP/3 here. Active probing is not required."
    ),
    current_value=None,
    recommendation=(
        "Upgrade to LSQUIC 4.3.1 or later (LiteSpeed Web Server 6.3.x+ or "
        "OpenLiteSpeed 1.8.x+). If immediate upgrade is not possible, disable "
        "HTTP/3 advertisement in the Alt-Svc header until patched."
    ),
    example_value="Server: LiteSpeed/6.3.0",
    reference_url=_REF_LSQUIC_ADVISORY,
    cve_correlations=[_CVE_2025_54939, _CWE_400, _CWE_770],
    compliance_mappings=[_OWASP_A06, _PCI_6_2_4, _NIST_RA_5],
)


_H3_INCONCLUSIVE_TEMPLATE = Finding(
    header="HTTP/3 Probe",
    category=HeaderCategory.H3,
    severity=Severity.INFO,
    title="HTTP/3 probe inconclusive",
    description=(
        "The QUIC handshake or HEAD request did not complete. This is INFO-only: "
        "could be a firewall blocking UDP/443, an unsupported QUIC version, an "
        "ALPN mismatch, or a real configuration gap. The H1/H3 diff and 0-RTT "
        "checks could not be evaluated. The error class is recorded in "
        "current_value below."
    ),
    current_value=None,
    recommendation=(
        "If UDP/443 is intentionally blocked, ignore. Otherwise verify the "
        "QUIC listener is reachable from the scanning host."
    ),
    example_value=None,
    reference_url=_REF_RFC_9114,
    cve_correlations=[],
    compliance_mappings=[],
)


_H3_EXTRAS_MISSING_TEMPLATE = Finding(
    header="HTTP/3 Probe",
    category=HeaderCategory.H3,
    severity=Severity.INFO,
    title="HTTP/3 validation skipped — [h3] extra not installed",
    description=(
        "Corsair was invoked with --h3-probe enabled but the optional [h3] "
        "extra (which installs aioquic) is not present in the environment. "
        "HTTP/3 validation findings (H3-001/002/003) cannot be evaluated."
    ),
    current_value=None,
    recommendation="Run `pip install corsair-scan[h3]` to enable HTTP/3 probing.",
    example_value=None,
    reference_url=_REF_RFC_9114,
    cve_correlations=[],
    compliance_mappings=[],
)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: dict = {
    "H3-001-HIGH": _H3_001_HIGH_TEMPLATE,
    "H3-001-LOW": _H3_001_LOW_TEMPLATE,
    "H3-001-PASS": _H3_001_PASS_TEMPLATE,
    "H3-002-PASS": _H3_002_PASS_TEMPLATE,
    "H3-003": _H3_003_TEMPLATE,
    "H3-INCONCLUSIVE": _H3_INCONCLUSIVE_TEMPLATE,
    "H3-EXTRAS-MISSING": _H3_EXTRAS_MISSING_TEMPLATE,
}


def get_finding(finding_id: str) -> Optional[Finding]:
    """Return a deepcopy of the static template for a finding ID."""
    template = _REGISTRY.get(finding_id)
    if template is None:
        return None
    return copy.deepcopy(template)


# ---------------------------------------------------------------------------
# Builders — runtime context injected
# ---------------------------------------------------------------------------

def build_h3_001_high(early_data_capability: int, status: int) -> Finding:
    f = get_finding("H3-001-HIGH")
    f.current_value = (
        f"max_early_data_size={early_data_capability}, response_status={status}"
    )
    return f


def build_h3_001_low(status: int) -> Finding:
    f = get_finding("H3-001-LOW")
    f.current_value = f"max_early_data_size=0, response_status={status}"
    return f


def build_h3_001_pass(early_data_capability: int) -> Finding:
    f = get_finding("H3-001-PASS")
    f.current_value = f"max_early_data_size={early_data_capability}, response_status=425"
    return f


def build_h3_002_finding(diff: HeaderDiffResult) -> Finding:
    """Single bundled finding describing all active drift modes.

    Severity = max of active modes:
      - missing_in_h3 OR value_drift -> MEDIUM
      - else missing_in_h1            -> LOW
    """
    severity = (
        Severity.MEDIUM
        if (diff.missing_in_h3 or diff.value_drift)
        else Severity.LOW
    )
    sections = []
    if diff.missing_in_h3:
        sections.append("Missing on HTTP/3: " + ", ".join(diff.missing_in_h3))
    if diff.value_drift:
        drift_lines = [
            f"{name} (H1={h1!r}, H3={h3!r})" for name, h1, h3 in diff.value_drift
        ]
        sections.append("Value drift: " + "; ".join(drift_lines))
    if diff.missing_in_h1:
        sections.append("Missing on HTTP/1.1: " + ", ".join(diff.missing_in_h1))

    description = (
        "Security headers differ between HTTP/1.1 and HTTP/3:\n\n"
        + "\n".join(sections)
        + "\n\nAll security headers should be applied at the HTTP layer, not "
        "tied to specific TCP/QUIC listener configuration. Header drift between "
        "protocols is typically caused by separate vhost blocks for the QUIC "
        "listener that have diverged from the HTTP/1.1 configuration."
    )
    return Finding(
        header="HTTP/3 vs HTTP/1.1 Headers",
        category=HeaderCategory.H3,
        severity=severity,
        title="HTTP/3 and HTTP/1.1 security headers diverge",
        description=description,
        current_value=None,
        recommendation=(
            "Audit the QUIC listener configuration. Apply security headers at the "
            "HTTP layer (middleware, framework) rather than per-listener."
        ),
        example_value=None,
        reference_url=_REF_RFC_9114,
        cve_correlations=[_CWE_693],
        compliance_mappings=[_OWASP_A05, _PCI_6_4_3, _NIST_SC_23],
    )


def build_h3_002_pass() -> Finding:
    return get_finding("H3-002-PASS")


def build_h3_003_finding() -> Finding:
    return get_finding("H3-003")


def build_h3_inconclusive_finding(error: str) -> Finding:
    f = get_finding("H3-INCONCLUSIVE")
    f.current_value = error
    return f


def build_h3_extras_missing_finding() -> Finding:
    return get_finding("H3-EXTRAS-MISSING")
