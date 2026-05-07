"""Tests for corsair.h3.auditor.H3Auditor.

scan_h3 is mocked at corsair.h3.auditor.scan_h3 (its bound name in the
auditor's namespace), NOT at corsair.h3.client.scan_h3 — patching at the
client module won't affect the auditor's local binding. Lesson learned
from v0.5.5 integrity-policy work.
"""

from unittest.mock import patch, AsyncMock

import pytest

from corsair.h3.auditor import H3Auditor
from corsair.h3.client import H3ScanResult
from corsair.models import HeaderCategory, Severity


# ---------------------------------------------------------------------------
# Gate skips
# ---------------------------------------------------------------------------

class TestGateSkips:
    def test_active_false_returns_empty(self):
        a = H3Auditor(timeout=5, active=False)
        assert a.audit("https://example.com/", {"Alt-Svc": 'h3=":443"'}) == []

    def test_http_url_returns_empty(self):
        a = H3Auditor(timeout=5)
        assert a.audit("http://example.com/", {"Alt-Svc": 'h3=":443"'}) == []

    def test_no_alt_svc_returns_empty(self):
        a = H3Auditor(timeout=5)
        assert a.audit("https://example.com/", {}) == []

    def test_alt_svc_without_h3_returns_empty(self):
        a = H3Auditor(timeout=5)
        assert a.audit(
            "https://example.com/", {"Alt-Svc": 'h2=":443"; ma=86400'}
        ) == []


# ---------------------------------------------------------------------------
# Extras-missing path (h3_available patched to False)
# ---------------------------------------------------------------------------

class TestExtrasMissing:
    def test_emits_extras_missing_finding(self):
        with patch("corsair.h3.auditor.H3_AVAILABLE", False):
            a = H3Auditor(timeout=5)
            findings = a.audit(
                "https://example.com/", {"Alt-Svc": 'h3=":443"'}
            )
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "[h3]" in findings[0].description or "pip install" in findings[0].description


# ---------------------------------------------------------------------------
# 0-RTT severity tier matrix
# ---------------------------------------------------------------------------

class TestZeroRttMatrix:
    def _audit(self, scan_result, h1_headers=None):
        h1_headers = h1_headers or {"Alt-Svc": 'h3=":443"'}
        with patch("corsair.h3.auditor.scan_h3", AsyncMock(return_value=scan_result)):
            a = H3Auditor(timeout=5)
            return a.audit("https://example.com/", h1_headers)

    def test_high_when_capability_and_no_425(self):
        result = H3ScanResult(
            url="https://example.com/",
            status=200,
            headers={},
            early_data_capability=16384,
            error=None,
        )
        findings = self._audit(result)
        h3_001 = [f for f in findings if "0-RTT" in f.title and "vulnerable" in f.title]
        assert len(h3_001) == 1
        assert h3_001[0].severity == Severity.HIGH

    def test_pass_when_capability_and_425(self):
        result = H3ScanResult(
            url="https://example.com/",
            status=425,
            headers={},
            early_data_capability=16384,
            error=None,
        )
        findings = self._audit(result)
        h3_001 = [f for f in findings if "0-RTT" in f.title]
        assert any(f.severity == Severity.PASS for f in h3_001)

    def test_low_when_no_capability_and_no_425(self):
        result = H3ScanResult(
            url="https://example.com/",
            status=200,
            headers={},
            early_data_capability=0,
            error=None,
        )
        findings = self._audit(result)
        h3_001 = [f for f in findings if "0-RTT" in f.title and "low risk" in f.title]
        assert len(h3_001) == 1
        assert h3_001[0].severity == Severity.LOW

    def test_silent_when_no_capability_and_425(self):
        result = H3ScanResult(
            url="https://example.com/",
            status=425,
            headers={},
            early_data_capability=0,
            error=None,
        )
        findings = self._audit(result)
        h3_001 = [f for f in findings if "0-RTT" in f.title]
        assert h3_001 == []  # safe baseline — nothing to report


# ---------------------------------------------------------------------------
# H1/H3 header diff finding
# ---------------------------------------------------------------------------

class TestHeaderDiff:
    def _audit(self, h3_headers, h1_headers):
        result = H3ScanResult(
            url="https://example.com/",
            status=200,
            headers=h3_headers,
            early_data_capability=0,  # silent on 0-RTT
            error=None,
        )
        with patch("corsair.h3.auditor.scan_h3", AsyncMock(return_value=result)):
            a = H3Auditor(timeout=5)
            return a.audit("https://example.com/", h1_headers)

    def test_missing_in_h3_emits_medium(self):
        h1 = {
            "Alt-Svc": 'h3=":443"',
            "Strict-Transport-Security": "max-age=31536000",
        }
        h3 = {}
        findings = self._audit(h3, h1)
        h3_002 = [f for f in findings if f.title.startswith("HTTP/3 and HTTP/1.1 security headers diverge")]
        assert len(h3_002) == 1
        assert h3_002[0].severity == Severity.MEDIUM
        assert "Strict-Transport-Security" in h3_002[0].description

    def test_value_drift_emits_medium(self):
        h1 = {
            "Alt-Svc": 'h3=":443"',
            "Strict-Transport-Security": "max-age=31536000",
        }
        h3 = {"strict-transport-security": "max-age=0"}
        findings = self._audit(h3, h1)
        h3_002 = [f for f in findings if f.title.startswith("HTTP/3 and HTTP/1.1 security headers diverge")]
        assert len(h3_002) == 1
        assert h3_002[0].severity == Severity.MEDIUM

    def test_pass_when_no_drift(self):
        h1 = {
            "Alt-Svc": 'h3=":443"',
            "Strict-Transport-Security": "max-age=31536000",
        }
        h3 = {"strict-transport-security": "max-age=31536000"}
        findings = self._audit(h3, h1)
        h3_002 = [f for f in findings if "consistent" in f.title]
        assert len(h3_002) == 1
        assert h3_002[0].severity == Severity.PASS


# ---------------------------------------------------------------------------
# LSQUIC fingerprint (passive — fires before probe)
# ---------------------------------------------------------------------------

class TestLSQUICFingerprint:
    def test_emits_h3_003_when_litespeed_and_h3(self):
        # Probe will time out — but LSQUIC fingerprint should still fire
        h1 = {
            "Alt-Svc": 'h3=":443"',
            "Server": "LiteSpeed/6.0",
        }
        result = H3ScanResult(
            url="https://example.com/",
            error="timeout after 5s",
        )
        with patch("corsair.h3.auditor.scan_h3", AsyncMock(return_value=result)):
            a = H3Auditor(timeout=5)
            findings = a.audit("https://example.com/", h1)
        lsquic = [f for f in findings if "LSQUIC" in f.title]
        assert len(lsquic) == 1
        assert lsquic[0].severity == Severity.CRITICAL

    def test_no_lsquic_for_other_servers(self):
        h1 = {"Alt-Svc": 'h3=":443"', "Server": "nginx/1.27"}
        result = H3ScanResult(
            url="https://example.com/",
            status=200,
            headers={},
            early_data_capability=0,
        )
        with patch("corsair.h3.auditor.scan_h3", AsyncMock(return_value=result)):
            a = H3Auditor(timeout=5)
            findings = a.audit("https://example.com/", h1)
        assert not any("LSQUIC" in f.title for f in findings)


# ---------------------------------------------------------------------------
# Inconclusive / error paths
# ---------------------------------------------------------------------------

class TestInconclusive:
    @pytest.mark.parametrize("error", [
        "timeout after 5s",
        "connection refused: [Errno 111]",
        "tls: certificate verify failed",
        "quic: handshake failed",
        "unexpected: ValueError: bogus",
    ])
    def test_inconclusive_for_each_error_class(self, error):
        result = H3ScanResult(url="https://example.com/", error=error)
        h1 = {"Alt-Svc": 'h3=":443"'}
        with patch("corsair.h3.auditor.scan_h3", AsyncMock(return_value=result)):
            a = H3Auditor(timeout=5)
            findings = a.audit("https://example.com/", h1)
        inconclusive = [f for f in findings if "inconclusive" in f.title.lower()]
        assert len(inconclusive) == 1
        assert error in inconclusive[0].current_value


# ---------------------------------------------------------------------------
# Top-level exception handler
# ---------------------------------------------------------------------------

class TestTopLevelExceptionHandler:
    def test_unexpected_exception_returns_inconclusive(self):
        h1 = {"Alt-Svc": 'h3=":443"'}
        with patch(
            "corsair.h3.auditor.scan_h3",
            AsyncMock(side_effect=RuntimeError("simulated bug")),
        ):
            a = H3Auditor(timeout=5)
            findings = a.audit("https://example.com/", h1)
        assert len(findings) == 1
        assert "inconclusive" in findings[0].title.lower()
        assert "simulated bug" in (findings[0].current_value or "") or "RuntimeError" in (findings[0].current_value or "")


# ---------------------------------------------------------------------------
# Metadata shape
# ---------------------------------------------------------------------------

class TestFindingMetadataShape:
    def test_all_findings_categorized_as_h3(self):
        h1 = {
            "Alt-Svc": 'h3=":443"',
            "Strict-Transport-Security": "max-age=31536000",
            "Server": "LiteSpeed/6.0",
        }
        result = H3ScanResult(
            url="https://example.com/",
            status=200,
            headers={},
            early_data_capability=16384,
        )
        with patch("corsair.h3.auditor.scan_h3", AsyncMock(return_value=result)):
            a = H3Auditor(timeout=5)
            findings = a.audit("https://example.com/", h1)
        for f in findings:
            assert f.category == HeaderCategory.H3, f.title


# ---------------------------------------------------------------------------
# Scanner integration smoke
# ---------------------------------------------------------------------------

class TestScannerIntegration:
    @pytest.mark.skip(reason="HeadScanner.h3_probe param wired in Task 7")
    def test_h3_finding_emitted_via_full_pipeline(self):
        from corsair.scanner import HeadScanner

        h1_headers = {
            "Alt-Svc": 'h3=":443"',
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Type": "text/html",
        }
        result = H3ScanResult(
            url="https://example.com/",
            status=200,
            headers={},  # missing in h3 -> H3-002 MEDIUM
            early_data_capability=16384,
        )

        with patch.object(
            HeadScanner,
            "_fetch_headers",
            return_value=(200, h1_headers, "https://example.com/", None),
        ), patch(
            "corsair.h3.auditor.scan_h3", AsyncMock(return_value=result)
        ), patch(
            "corsair.cache.auditor.CacheAuditor.audit", return_value=[]
        ), patch(
            "corsair.cors.auditor.CORSAuditor.audit", return_value=[]
        ), patch(
            "corsair.fetch_metadata.FetchMetadataAuditor.audit", return_value=[]
        ), patch(
            "corsair.integrity_policy.IntegrityPolicyAuditor.audit", return_value=[]
        ):
            scanner = HeadScanner(
                timeout=5,
                cache_probe=False, cors_probe=False, fm_probe=False,
                ip_probe=False, h3_probe=True,
            )
            scan_result = scanner.scan_target("https://example.com/")

        h3_findings = [f for f in scan_result.findings if f.category == HeaderCategory.H3]
        # Expect at least: 0-RTT HIGH (capability + no 425) and H3-002 MEDIUM (HSTS missing in h3).
        assert any(f.severity == Severity.HIGH and "0-RTT" in f.title for f in h3_findings)
        assert any(f.severity == Severity.MEDIUM and "diverge" in f.title for f in h3_findings)
