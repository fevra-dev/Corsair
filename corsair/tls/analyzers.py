"""
TLS scan result analyzers.

Maps sslyze ServerScanResult data to Corsair Finding objects.
Each analyze_* function checks one aspect of the TLS configuration.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import List

from ..models import Finding
from .findings import get_finding

logger = logging.getLogger(__name__)


def _get_result(scan_attempt):
    """Unwrap sslyze 6.0 ScanAttempt to get the inner result, or return the object itself for mocks."""
    if hasattr(scan_attempt, "result"):
        return scan_attempt.result
    return scan_attempt


def analyze_scan_result(scan_result) -> List[Finding]:
    """
    Analyze a complete sslyze scan result and return all findings.

    Args:
        scan_result: sslyze ServerScanResult object

    Returns:
        List of Finding objects for all detected issues
    """
    findings: List[Finding] = []

    findings.extend(_analyze_protocols(scan_result))
    findings.extend(_analyze_ciphers(scan_result))
    findings.extend(_analyze_certificate(scan_result))
    findings.extend(_analyze_vulnerabilities(scan_result))

    return findings


def _analyze_protocols(scan_result) -> List[Finding]:
    """Check for deprecated protocol versions and missing TLS 1.3."""
    findings = []
    sr = scan_result.scan_result

    protocol_checks = [
        ("ssl_2_0_cipher_suites", "DEPRECATED_PROTOCOL_SSL2"),
        ("ssl_3_0_cipher_suites", "DEPRECATED_PROTOCOL_SSL3"),
        ("tls_1_0_cipher_suites", "DEPRECATED_PROTOCOL_TLS10"),
        ("tls_1_1_cipher_suites", "DEPRECATED_PROTOCOL_TLS11"),
    ]

    for attr, finding_id in protocol_checks:
        scan_attempt = getattr(sr, attr, None)
        if scan_attempt:
            cmd_result = _get_result(scan_attempt)
            if cmd_result and hasattr(cmd_result, "accepted_cipher_suites"):
                if cmd_result.accepted_cipher_suites:
                    finding = get_finding(finding_id)
                    if finding:
                        findings.append(finding)

    # Check for TLS 1.3 support
    tls13_attempt = getattr(sr, "tls_1_3_cipher_suites", None)
    if tls13_attempt:
        tls13 = _get_result(tls13_attempt)
        if tls13 and hasattr(tls13, "accepted_cipher_suites"):
            if not tls13.accepted_cipher_suites:
                finding = get_finding("TLS13_NOT_SUPPORTED")
                if finding:
                    findings.append(finding)

    return findings


def _get_accepted_suites(sr, attr):
    """Get accepted cipher suites from a scan attempt attribute."""
    scan_attempt = getattr(sr, attr, None)
    if not scan_attempt:
        return []
    result = _get_result(scan_attempt)
    if result and hasattr(result, "accepted_cipher_suites"):
        return result.accepted_cipher_suites or []
    return []


def _analyze_ciphers(scan_result) -> List[Finding]:
    """Check for weak cipher suites and missing forward secrecy."""
    findings = []
    sr = scan_result.scan_result

    # Collect all accepted cipher suite names from TLS 1.2
    tls12_accepted = _get_accepted_suites(sr, "tls_1_2_cipher_suites")
    tls12_suite_names = [s.cipher_suite.name for s in tls12_accepted]

    # Also check older protocols for weak ciphers
    all_suite_names = list(tls12_suite_names)
    for attr in [
        "ssl_2_0_cipher_suites",
        "ssl_3_0_cipher_suites",
        "tls_1_0_cipher_suites",
        "tls_1_1_cipher_suites",
    ]:
        suites = _get_accepted_suites(sr, attr)
        all_suite_names.extend(s.cipher_suite.name for s in suites)

    # RC4
    if any("RC4" in name for name in all_suite_names):
        finding = get_finding("WEAK_CIPHER_RC4")
        if finding:
            findings.append(finding)

    # 3DES
    if any("3DES" in name or "DES_CBC3" in name for name in all_suite_names):
        finding = get_finding("WEAK_CIPHER_3DES")
        if finding:
            findings.append(finding)

    # NULL
    if any("NULL" in name for name in all_suite_names):
        finding = get_finding("WEAK_CIPHER_NULL")
        if finding:
            findings.append(finding)

    # EXPORT
    if any("EXPORT" in name for name in all_suite_names):
        finding = get_finding("WEAK_CIPHER_EXPORT")
        if finding:
            findings.append(finding)

    # Forward secrecy check (only relevant if TLS 1.2 is the highest supported)
    tls13_accepted = _get_accepted_suites(sr, "tls_1_3_cipher_suites")
    tls13_supported = len(tls13_accepted) > 0
    if tls12_suite_names and not tls13_supported:
        has_pfs = any("ECDHE" in name or "DHE" in name for name in tls12_suite_names)
        if not has_pfs:
            finding = get_finding("NO_FORWARD_SECRECY")
            if finding:
                findings.append(finding)

    # Weak DH parameters
    for suite in tls12_accepted:
        if suite.ephemeral_key and hasattr(suite.ephemeral_key, "size"):
            if "DH" in suite.cipher_suite.name and suite.ephemeral_key.size < 2048:
                finding = get_finding("WEAK_DH_PARAMS")
                if finding:
                    finding.current_value = f"DH {suite.ephemeral_key.size}-bit"
                    findings.append(finding)
                break

    return findings


def _analyze_certificate(scan_result) -> List[Finding]:
    """Check certificate validity, trust chain, signature, and key size."""
    findings = []
    sr = scan_result.scan_result

    cert_attempt = getattr(sr, "certificate_info", None)
    if not cert_attempt:
        return findings

    cert_info = _get_result(cert_attempt)
    if not cert_info or not cert_info.certificate_deployments:
        return findings

    deployment = cert_info.certificate_deployments[0]
    chain = deployment.received_certificate_chain
    if not chain:
        return findings

    leaf = chain[0]
    now = datetime.now(timezone.utc)

    # Expiry — sslyze 6.0 uses not_valid_after_utc
    not_after = getattr(leaf, "not_valid_after_utc", None) or getattr(leaf, "not_valid_after", None)
    if not_after:
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)

        if not_after < now:
            finding = get_finding("CERT_EXPIRED")
            if finding:
                finding.current_value = f"Expired: {not_after.isoformat()}"
                findings.append(finding)
        elif not_after < now + timedelta(days=30):
            finding = get_finding("CERT_EXPIRING_SOON")
            if finding:
                days_left = (not_after - now).days
                finding.current_value = f"Expires in {days_left} days: {not_after.isoformat()}"
                findings.append(finding)

    # Trust chain (self-signed)
    if deployment.verified_certificate_chain is None:
        finding = get_finding("CERT_SELF_SIGNED")
        if finding:
            findings.append(finding)

    # Hostname match — sslyze 6.0 uses path_validation_results
    if hasattr(deployment, "leaf_certificate_subject_matches_hostname"):
        if not deployment.leaf_certificate_subject_matches_hostname:
            finding = get_finding("CERT_HOSTNAME_MISMATCH")
            if finding:
                findings.append(finding)
    elif hasattr(deployment, "path_validation_results"):
        all_failed = all(
            not pv.was_validation_successful for pv in deployment.path_validation_results
        )
        if deployment.path_validation_results and all_failed:
            finding = get_finding("CERT_HOSTNAME_MISMATCH")
            if finding:
                findings.append(finding)

    # Signature algorithm — check deployment-level flag first (sslyze 6.0)
    if hasattr(deployment, "verified_chain_has_sha1_signature"):
        if deployment.verified_chain_has_sha1_signature:
            finding = get_finding("CERT_WEAK_SIGNATURE")
            if finding:
                finding.current_value = "Signature algorithm: SHA-1 in chain"
                findings.append(finding)
    else:
        sig_algo = getattr(leaf, "signature_hash_algorithm", None)
        if sig_algo and sig_algo.name.lower() in ("sha1", "md5", "md2"):
            finding = get_finding("CERT_WEAK_SIGNATURE")
            if finding:
                finding.current_value = f"Signature algorithm: {sig_algo.name}"
                findings.append(finding)

    # Key size
    try:
        key_size = leaf.public_key().key_size
        if key_size < 2048:
            finding = get_finding("CERT_SHORT_KEY")
            if finding:
                finding.current_value = f"RSA {key_size}-bit"
                findings.append(finding)
    except (AttributeError, TypeError):
        pass

    # OCSP stapling
    if hasattr(deployment, "ocsp_response_is_trusted"):
        if not deployment.ocsp_response_is_trusted:
            finding = get_finding("NO_OCSP_STAPLING")
            if finding:
                findings.append(finding)

    return findings


def _analyze_vulnerabilities(scan_result) -> List[Finding]:
    """Check for known TLS vulnerabilities."""
    findings = []
    sr = scan_result.scan_result

    # Heartbleed
    hb_attempt = getattr(sr, "heartbleed", None)
    if hb_attempt:
        hb = _get_result(hb_attempt)
        if hb and hb.is_vulnerable_to_heartbleed:
            finding = get_finding("HEARTBLEED")
            if finding:
                findings.append(finding)

    # ROBOT
    robot_attempt = getattr(sr, "robot", None)
    if robot_attempt:
        robot = _get_result(robot_attempt)
        if robot:
            robot_name = robot.robot_result.name
            if "VULNERABLE" in robot_name:
                finding = get_finding("ROBOT")
                if finding:
                    findings.append(finding)

    # CCS Injection
    ccs_attempt = getattr(sr, "openssl_ccs_injection", None)
    if ccs_attempt:
        ccs = _get_result(ccs_attempt)
        if ccs and ccs.is_vulnerable_to_ccs_injection:
            finding = get_finding("OPENSSL_CCS_INJECTION")
            if finding:
                findings.append(finding)

    # TLS Compression
    comp_attempt = getattr(sr, "tls_compression", None)
    if comp_attempt:
        comp = _get_result(comp_attempt)
        if comp and comp.supports_compression:
            finding = get_finding("TLS_COMPRESSION")
            if finding:
                findings.append(finding)

    # Fallback SCSV
    fb_attempt = getattr(sr, "tls_fallback_scsv", None)
    if fb_attempt:
        fb = _get_result(fb_attempt)
        if fb and not fb.supports_fallback_scsv:
            finding = get_finding("NO_FALLBACK_SCSV")
            if finding:
                findings.append(finding)

    return findings
