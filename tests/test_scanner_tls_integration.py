"""Test TLS integration in HeadScanner."""

import pytest
from unittest.mock import patch, MagicMock

from corsair.scanner import HeadScanner
from corsair.models import Severity


class TestScannerTLSIntegration:
    @patch("corsair.scanner.tls_available", return_value=True)
    @patch("corsair.scanner.TLSAuditor")
    def test_tls_audit_runs_for_https(self, MockAuditor, mock_available):
        mock_instance = MockAuditor.return_value
        mock_instance.audit.return_value = []

        scanner = HeadScanner()
        with patch.object(scanner, "_fetch_headers") as mock_fetch:
            mock_fetch.return_value = (200, {"Content-Type": "text/html"}, "https://example.com", None)
            result = scanner.scan_target("https://example.com")

        mock_instance.audit.assert_called_once_with("https://example.com")

    @patch("corsair.scanner.tls_available", return_value=False)
    def test_tls_audit_skipped_when_unavailable(self, mock_available):
        scanner = HeadScanner()
        with patch.object(scanner, "_fetch_headers") as mock_fetch:
            mock_fetch.return_value = (200, {"Content-Type": "text/html"}, "https://example.com", None)
            result = scanner.scan_target("https://example.com")

        # Should complete without error, no TLS findings
        assert result.score >= 0

    @patch("corsair.scanner.tls_available", return_value=True)
    def test_http_target_gets_tls_missing(self, mock_available):
        scanner = HeadScanner()
        with patch.object(scanner, "_fetch_headers") as mock_fetch:
            mock_fetch.return_value = (200, {"Content-Type": "text/html"}, "http://example.com", None)
            result = scanner.scan_target("http://example.com")

        tls_missing = [f for f in result.findings if "TLS" in f.header and f.severity == Severity.CRITICAL]
        assert len(tls_missing) == 1
        assert "HTTP Only" in tls_missing[0].title or "No TLS" in tls_missing[0].title
