"""Test TLS finding definitions are complete and consistent."""

from corsair.models import HeaderCategory, Severity
from corsair.tls.findings import ALL_TLS_FINDINGS, get_finding


class TestTLSFindingDefinitions:
    def test_all_findings_use_transport_category(self):
        for finding_id, finding in ALL_TLS_FINDINGS.items():
            assert (
                finding.category == HeaderCategory.TRANSPORT
            ), f"{finding_id} has category {finding.category}, expected TRANSPORT"

    def test_all_findings_have_required_fields(self):
        for finding_id, finding in ALL_TLS_FINDINGS.items():
            assert finding.header, f"{finding_id} missing header"
            assert finding.title, f"{finding_id} missing title"
            assert finding.description, f"{finding_id} missing description"
            assert finding.recommendation, f"{finding_id} missing recommendation"
            assert finding.reference_url, f"{finding_id} missing reference_url"

    def test_all_findings_have_valid_severity(self):
        for finding_id, finding in ALL_TLS_FINDINGS.items():
            assert finding.severity in Severity, f"{finding_id} has invalid severity"

    def test_critical_findings_exist(self):
        critical_ids = [
            "TLS_MISSING",
            "DEPRECATED_PROTOCOL_SSL2",
            "DEPRECATED_PROTOCOL_SSL3",
            "WEAK_CIPHER_RC4",
            "WEAK_CIPHER_NULL",
            "WEAK_CIPHER_EXPORT",
            "CERT_EXPIRED",
            "CERT_HOSTNAME_MISMATCH",
            "HEARTBLEED",
            "ROBOT",
            "OPENSSL_CCS_INJECTION",
        ]
        for fid in critical_ids:
            assert fid in ALL_TLS_FINDINGS, f"Missing critical finding: {fid}"
            assert ALL_TLS_FINDINGS[fid].severity == Severity.CRITICAL

    def test_get_finding_returns_copy(self):
        f1 = get_finding("TLS_MISSING")
        f2 = get_finding("TLS_MISSING")
        assert f1 is not f2
        assert f1.title == f2.title

    def test_get_finding_unknown_returns_none(self):
        assert get_finding("NONEXISTENT") is None

    def test_finding_count(self):
        # Spec defines ~25 findings
        assert len(ALL_TLS_FINDINGS) >= 24
