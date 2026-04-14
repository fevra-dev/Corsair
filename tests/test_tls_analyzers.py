"""Test TLS analyzers — maps sslyze results to Corsair findings."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from corsair.models import Severity
from corsair.tls.analyzers import analyze_scan_result


def _mock_cipher_suite(name: str, key_size: int = 256, is_anonymous: bool = False):
    """Create a mock cipher suite accepted by the server."""
    suite = MagicMock()
    suite.cipher_suite.name = name
    suite.cipher_suite.key_size = key_size
    suite.cipher_suite.is_anonymous = is_anonymous
    suite.ephemeral_key = None
    return suite


def _wrap_attempt(inner_result):
    """Wrap an inner result in an sslyze 6.0 ScanAttempt-like object."""
    attempt = MagicMock(spec=["result"])
    attempt.result = inner_result
    return attempt


def _mock_cipher_result(suites):
    """Create a cipher suites scan result wrapped in an attempt."""
    inner = MagicMock(spec=["accepted_cipher_suites"])
    inner.accepted_cipher_suites = suites if suites is not None else []
    return _wrap_attempt(inner)


def _mock_scan_result(
    ssl2_suites=None,
    ssl3_suites=None,
    tls10_suites=None,
    tls11_suites=None,
    tls12_suites=None,
    tls13_suites=None,
    heartbleed_vulnerable=False,
    robot_vulnerable=False,
    ccs_injection_vulnerable=False,
    compression_enabled=False,
    fallback_scsv_supported=True,
    cert_expired=False,
    cert_self_signed=False,
    cert_hostname_mismatch=False,
    cert_sig_algorithm="sha256",
    cert_key_size=2048,
    cert_days_until_expiry=365,
    ocsp_stapling=True,
):
    """Build a mock sslyze ServerScanResult matching sslyze 6.0 structure."""
    result = MagicMock()

    # Protocol suites — wrapped in attempt objects
    result.scan_result.ssl_2_0_cipher_suites = _mock_cipher_result(ssl2_suites)
    result.scan_result.ssl_3_0_cipher_suites = _mock_cipher_result(ssl3_suites)
    result.scan_result.tls_1_0_cipher_suites = _mock_cipher_result(tls10_suites)
    result.scan_result.tls_1_1_cipher_suites = _mock_cipher_result(tls11_suites)
    result.scan_result.tls_1_2_cipher_suites = _mock_cipher_result(tls12_suites)
    result.scan_result.tls_1_3_cipher_suites = _mock_cipher_result(tls13_suites)

    # Heartbleed
    hb_inner = MagicMock(spec=["is_vulnerable_to_heartbleed"])
    hb_inner.is_vulnerable_to_heartbleed = heartbleed_vulnerable
    result.scan_result.heartbleed = _wrap_attempt(hb_inner)

    # ROBOT
    robot_inner = MagicMock(spec=["robot_result"])
    robot_inner.robot_result = MagicMock()
    if robot_vulnerable:
        robot_inner.robot_result.name = "VULNERABLE_STRONG_ORACLE"
    else:
        robot_inner.robot_result.name = "NOT_VULNERABLE_NO_ORACLE"
    result.scan_result.robot = _wrap_attempt(robot_inner)

    # CCS Injection
    ccs_inner = MagicMock(spec=["is_vulnerable_to_ccs_injection"])
    ccs_inner.is_vulnerable_to_ccs_injection = ccs_injection_vulnerable
    result.scan_result.openssl_ccs_injection = _wrap_attempt(ccs_inner)

    # TLS Compression
    comp_inner = MagicMock(spec=["supports_compression"])
    comp_inner.supports_compression = compression_enabled
    result.scan_result.tls_compression = _wrap_attempt(comp_inner)

    # Fallback SCSV
    fb_inner = MagicMock(spec=["supports_fallback_scsv"])
    fb_inner.supports_fallback_scsv = fallback_scsv_supported
    result.scan_result.tls_fallback_scsv = _wrap_attempt(fb_inner)

    # Certificate info
    leaf_cert = MagicMock()
    now = datetime.now(timezone.utc)

    if cert_expired:
        leaf_cert.not_valid_after = now - timedelta(days=1)
    else:
        leaf_cert.not_valid_after = now + timedelta(days=cert_days_until_expiry)
    leaf_cert.not_valid_before = now - timedelta(days=30)
    leaf_cert.public_key.return_value.key_size = cert_key_size
    leaf_cert.signature_hash_algorithm.name = cert_sig_algorithm
    # Remove not_valid_after_utc so analyzers fall back to not_valid_after
    del leaf_cert.not_valid_after_utc

    cert_deployment = MagicMock()
    cert_deployment.received_certificate_chain = [leaf_cert]
    cert_deployment.leaf_certificate_subject_matches_hostname = not cert_hostname_mismatch
    cert_deployment.verified_certificate_chain = None if cert_self_signed else [leaf_cert]
    cert_deployment.ocsp_response_is_trusted = ocsp_stapling
    # Remove sslyze 6.0 specific attrs so analyzers use the mock attrs above
    del cert_deployment.verified_chain_has_sha1_signature
    del cert_deployment.path_validation_results

    cert_info_inner = MagicMock(spec=["certificate_deployments"])
    cert_info_inner.certificate_deployments = [cert_deployment]
    result.scan_result.certificate_info = _wrap_attempt(cert_info_inner)

    return result


class TestProtocolAnalysis:
    def test_ssl2_detected(self):
        result = _mock_scan_result(ssl2_suites=[_mock_cipher_suite("SSL_RSA_WITH_RC4_128_MD5")])
        findings = analyze_scan_result(result)
        ids = [f.title for f in findings]
        assert any("SSLv2" in t for t in ids)
        ssl2_finding = [f for f in findings if "SSLv2" in f.title][0]
        assert ssl2_finding.severity == Severity.CRITICAL

    def test_ssl3_detected(self):
        result = _mock_scan_result(ssl3_suites=[_mock_cipher_suite("SSL_RSA_WITH_AES_128_CBC_SHA")])
        findings = analyze_scan_result(result)
        assert any("SSLv3" in f.title for f in findings)

    def test_tls10_detected(self):
        result = _mock_scan_result(
            tls10_suites=[_mock_cipher_suite("TLS_RSA_WITH_AES_128_CBC_SHA")]
        )
        findings = analyze_scan_result(result)
        assert any("TLS 1.0" in f.title for f in findings)

    def test_tls11_detected(self):
        result = _mock_scan_result(
            tls11_suites=[_mock_cipher_suite("TLS_RSA_WITH_AES_128_CBC_SHA")]
        )
        findings = analyze_scan_result(result)
        assert any("TLS 1.1" in f.title for f in findings)

    def test_tls13_missing_detected(self):
        result = _mock_scan_result(
            tls12_suites=[_mock_cipher_suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")],
            tls13_suites=[],
        )
        findings = analyze_scan_result(result)
        assert any("TLS 1.3 Not Supported" in f.title for f in findings)

    def test_clean_config_no_protocol_findings(self):
        result = _mock_scan_result(
            tls12_suites=[_mock_cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")],
            tls13_suites=[_mock_cipher_suite("TLS_AES_256_GCM_SHA384")],
        )
        findings = analyze_scan_result(result)
        protocol_findings = [
            f for f in findings if "Protocol" in f.title or "TLS 1." in f.title or "SSL" in f.title
        ]
        assert len(protocol_findings) == 0


class TestCipherAnalysis:
    def test_rc4_detected(self):
        result = _mock_scan_result(
            tls12_suites=[_mock_cipher_suite("TLS_RSA_WITH_RC4_128_SHA")],
            tls13_suites=[_mock_cipher_suite("TLS_AES_256_GCM_SHA384")],
        )
        findings = analyze_scan_result(result)
        assert any("RC4" in f.title for f in findings)

    def test_3des_detected(self):
        result = _mock_scan_result(
            tls12_suites=[_mock_cipher_suite("TLS_RSA_WITH_3DES_EDE_CBC_SHA")],
            tls13_suites=[_mock_cipher_suite("TLS_AES_256_GCM_SHA384")],
        )
        findings = analyze_scan_result(result)
        assert any("3DES" in f.title for f in findings)

    def test_no_forward_secrecy_detected(self):
        result = _mock_scan_result(
            tls12_suites=[_mock_cipher_suite("TLS_RSA_WITH_AES_256_GCM_SHA384")],
            tls13_suites=[],
        )
        findings = analyze_scan_result(result)
        assert any("Forward Secrecy" in f.title for f in findings)


class TestCertificateAnalysis:
    def test_expired_cert(self):
        result = _mock_scan_result(
            cert_expired=True,
            tls12_suites=[_mock_cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")],
            tls13_suites=[_mock_cipher_suite("TLS_AES_256_GCM_SHA384")],
        )
        findings = analyze_scan_result(result)
        assert any("Expired" in f.title for f in findings)

    def test_self_signed_cert(self):
        result = _mock_scan_result(
            cert_self_signed=True,
            tls12_suites=[_mock_cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")],
            tls13_suites=[_mock_cipher_suite("TLS_AES_256_GCM_SHA384")],
        )
        findings = analyze_scan_result(result)
        assert any("Self-Signed" in f.title for f in findings)

    def test_hostname_mismatch(self):
        result = _mock_scan_result(
            cert_hostname_mismatch=True,
            tls12_suites=[_mock_cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")],
            tls13_suites=[_mock_cipher_suite("TLS_AES_256_GCM_SHA384")],
        )
        findings = analyze_scan_result(result)
        assert any("Hostname Mismatch" in f.title for f in findings)

    def test_expiring_soon(self):
        result = _mock_scan_result(
            cert_days_until_expiry=15,
            tls12_suites=[_mock_cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")],
            tls13_suites=[_mock_cipher_suite("TLS_AES_256_GCM_SHA384")],
        )
        findings = analyze_scan_result(result)
        assert any("Expiring Soon" in f.title for f in findings)

    def test_weak_signature(self):
        result = _mock_scan_result(
            cert_sig_algorithm="sha1",
            tls12_suites=[_mock_cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")],
            tls13_suites=[_mock_cipher_suite("TLS_AES_256_GCM_SHA384")],
        )
        findings = analyze_scan_result(result)
        assert any("Signature" in f.title for f in findings)

    def test_short_key(self):
        result = _mock_scan_result(
            cert_key_size=1024,
            tls12_suites=[_mock_cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")],
            tls13_suites=[_mock_cipher_suite("TLS_AES_256_GCM_SHA384")],
        )
        findings = analyze_scan_result(result)
        assert any("Key Too Short" in f.title for f in findings)


class TestVulnerabilityAnalysis:
    def test_heartbleed(self):
        result = _mock_scan_result(
            heartbleed_vulnerable=True,
            tls12_suites=[_mock_cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")],
            tls13_suites=[_mock_cipher_suite("TLS_AES_256_GCM_SHA384")],
        )
        findings = analyze_scan_result(result)
        assert any("Heartbleed" in f.title for f in findings)

    def test_robot(self):
        result = _mock_scan_result(
            robot_vulnerable=True,
            tls12_suites=[_mock_cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")],
            tls13_suites=[_mock_cipher_suite("TLS_AES_256_GCM_SHA384")],
        )
        findings = analyze_scan_result(result)
        assert any("ROBOT" in f.title for f in findings)

    def test_ccs_injection(self):
        result = _mock_scan_result(
            ccs_injection_vulnerable=True,
            tls12_suites=[_mock_cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")],
            tls13_suites=[_mock_cipher_suite("TLS_AES_256_GCM_SHA384")],
        )
        findings = analyze_scan_result(result)
        assert any("CCS" in f.title for f in findings)

    def test_tls_compression(self):
        result = _mock_scan_result(
            compression_enabled=True,
            tls12_suites=[_mock_cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")],
            tls13_suites=[_mock_cipher_suite("TLS_AES_256_GCM_SHA384")],
        )
        findings = analyze_scan_result(result)
        assert any("Compression" in f.title or "CRIME" in f.title for f in findings)

    def test_no_fallback_scsv(self):
        result = _mock_scan_result(
            fallback_scsv_supported=False,
            tls12_suites=[_mock_cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")],
            tls13_suites=[_mock_cipher_suite("TLS_AES_256_GCM_SHA384")],
        )
        findings = analyze_scan_result(result)
        assert any("FALLBACK" in f.title or "Fallback" in f.title for f in findings)
