"""Test TLS integration in HeadScanner."""

from unittest.mock import patch

from corsair.models import Severity
from corsair.scanner import HeadScanner


class TestScannerTLSIntegration:
    @patch("corsair.scanner.tls_available", return_value=True)
    @patch("corsair.scanner.TLSAuditor")
    def test_tls_audit_runs_for_https(self, MockAuditor, mock_available):
        mock_instance = MockAuditor.return_value
        mock_instance.audit.return_value = []

        scanner = HeadScanner()
        with patch.object(scanner, "_fetch_headers") as mock_fetch:
            mock_fetch.return_value = (
                200,
                {"Content-Type": "text/html"},
                "https://example.com",
                None,
            )
            scanner.scan_target("https://example.com")

        mock_instance.audit.assert_called_once_with("https://example.com")

    @patch("corsair.scanner.tls_available", return_value=False)
    def test_tls_audit_skipped_when_unavailable(self, mock_available):
        scanner = HeadScanner()
        with patch.object(scanner, "_fetch_headers") as mock_fetch:
            mock_fetch.return_value = (
                200,
                {"Content-Type": "text/html"},
                "https://example.com",
                None,
            )
            result = scanner.scan_target("https://example.com")

        # Should complete without error, no TLS findings
        assert result.score >= 0

    @patch("corsair.scanner.tls_available", return_value=True)
    def test_http_target_gets_tls_missing(self, mock_available):
        scanner = HeadScanner()
        with patch.object(scanner, "_fetch_headers") as mock_fetch:
            mock_fetch.return_value = (
                200,
                {"Content-Type": "text/html"},
                "http://example.com",
                None,
            )
            result = scanner.scan_target("http://example.com")

        tls_missing = [
            f for f in result.findings if "TLS" in f.header and f.severity == Severity.CRITICAL
        ]
        assert len(tls_missing) == 1
        assert "HTTP Only" in tls_missing[0].title or "No TLS" in tls_missing[0].title


class TestTLSHint:
    @patch("corsair.reporters.console.tls_available", return_value=False)
    def test_hint_shown_when_sslyze_absent(self, mock_available):
        from corsair.models import ScanReport, TargetResult
        from corsair.reporters.console import ConsoleReporter

        result = TargetResult(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            headers={},
            findings=[],
            score=100,
            grade="A",
        )

        report = ScanReport(
            targets_scanned=1,
            average_score=100.0,
            scan_start="2026-01-01T00:00:00",
            scan_end="2026-01-01T00:00:01",
            scan_duration_ms=1000,
            results=[result],
        )

        reporter = ConsoleReporter()
        output = reporter.generate(report)
        assert "pip install corsair-scan[tls]" in output

    @patch("corsair.reporters.console.tls_available", return_value=True)
    def test_hint_not_shown_when_sslyze_present(self, mock_available):
        from corsair.models import ScanReport, TargetResult
        from corsair.reporters.console import ConsoleReporter

        result = TargetResult(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            headers={},
            findings=[],
            score=100,
            grade="A",
        )

        report = ScanReport(
            targets_scanned=1,
            average_score=100.0,
            scan_start="2026-01-01T00:00:00",
            scan_end="2026-01-01T00:00:01",
            scan_duration_ms=1000,
            results=[result],
        )

        reporter = ConsoleReporter()
        output = reporter.generate(report)
        assert "pip install corsair-scan[tls]" not in output
