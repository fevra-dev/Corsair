"""Unit tests for TLSAuditor (mocked sslyze, no network)."""

from unittest.mock import MagicMock, patch

from corsair.models import Severity
from corsair.tls.auditor import TLSAuditor


class TestParseTarget:
    def test_https_url(self):
        auditor = TLSAuditor()
        host, port = auditor._parse_target("https://example.com")
        assert host == "example.com"
        assert port == 443

    def test_https_custom_port(self):
        auditor = TLSAuditor()
        host, port = auditor._parse_target("https://example.com:8443")
        assert host == "example.com"
        assert port == 8443

    def test_ipv6_url(self):
        auditor = TLSAuditor()
        host, port = auditor._parse_target("https://[::1]:443")
        assert host == "::1"
        assert port == 443

    def test_url_with_path(self):
        auditor = TLSAuditor()
        host, port = auditor._parse_target("https://example.com/path/to/page")
        assert host == "example.com"
        assert port == 443


class TestAuditConnectionError:
    @patch("corsair.tls.auditor.TLSAuditor._run_scan")
    def test_connection_error_returns_finding(self, mock_scan):
        mock_scan.side_effect = ConnectionError("Connection refused")
        auditor = TLSAuditor()
        findings = auditor.audit("https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "Connection Failed" in findings[0].title


class TestAuditSuccess:
    @patch("corsair.tls.auditor.TLSAuditor._run_scan")
    @patch("corsair.tls.auditor.analyze_scan_result")
    def test_audit_calls_analyze(self, mock_analyze, mock_scan):
        mock_scan.return_value = MagicMock()
        mock_analyze.return_value = []
        auditor = TLSAuditor()
        findings = auditor.audit("https://example.com")
        mock_analyze.assert_called_once()
        assert findings == []
