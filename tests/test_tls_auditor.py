"""
Integration tests for TLSAuditor against badssl.com.

These tests hit real servers — run with: pytest -m slow
Skipped in CI by default.
"""

import pytest

from corsair.tls import tls_available

if not tls_available():
    pytest.skip("sslyze not installed", allow_module_level=True)

from corsair.models import Severity
from corsair.tls.auditor import TLSAuditor


@pytest.fixture
def auditor():
    return TLSAuditor(timeout=15)


@pytest.mark.slow
class TestBadSSLIntegration:
    def test_expired_cert(self, auditor):
        findings = auditor.audit("https://expired.badssl.com")
        titles = [f.title for f in findings]
        assert any("Expired" in t for t in titles)

    def test_wrong_host(self, auditor):
        findings = auditor.audit("https://wrong.host.badssl.com")
        titles = [f.title for f in findings]
        assert any("Hostname Mismatch" in t for t in titles)

    def test_self_signed(self, auditor):
        findings = auditor.audit("https://self-signed.badssl.com")
        titles = [f.title for f in findings]
        assert any("Self-Signed" in t for t in titles)

    def test_rc4(self, auditor):
        findings = auditor.audit("https://rc4.badssl.com")
        titles = [f.title for f in findings]
        assert any("RC4" in t for t in titles)

    def test_3des(self, auditor):
        findings = auditor.audit("https://3des.badssl.com")
        titles = [f.title for f in findings]
        assert any("3DES" in t for t in titles)

    def test_null_cipher(self, auditor):
        findings = auditor.audit("https://null.badssl.com")
        titles = [f.title for f in findings]
        assert any("NULL" in t for t in titles)

    def test_dh512(self, auditor):
        findings = auditor.audit("https://dh512.badssl.com")
        titles = [f.title for f in findings]
        assert any("Diffie-Hellman" in t or "DH" in t for t in titles)

    def test_sha1_intermediate(self, auditor):
        findings = auditor.audit("https://sha1-intermediate.badssl.com")
        titles = [f.title for f in findings]
        assert any("Signature" in t for t in titles)

    def test_clean_config(self, auditor):
        """Positive control — good TLS config should produce minimal findings."""
        findings = auditor.audit("https://badssl.com")
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(critical) == 0, f"Unexpected critical findings: {[f.title for f in critical]}"
        assert len(high) == 0, f"Unexpected high findings: {[f.title for f in high]}"
