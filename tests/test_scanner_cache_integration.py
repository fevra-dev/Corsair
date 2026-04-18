"""Test scanner integration with cache poisoning detection."""

from unittest.mock import patch

from corsair.scanner import HeadScanner


class TestScannerCacheIntegration:
    def _mock_fetch_headers(self, url):
        return (
            200,
            {
                "Content-Type": "text/html",
                "Cache-Control": "public, max-age=3600",
                "Server": "nginx",
            },
            url,
            None,
        )

    @patch("corsair.scanner.tls_available", return_value=False)
    def test_scan_target_calls_cache_auditor(self, _tls):
        scanner = HeadScanner()
        with patch.object(scanner, "_fetch_headers", side_effect=self._mock_fetch_headers):
            with patch("corsair.scanner.CacheAuditor") as MockAuditor:
                mock_instance = MockAuditor.return_value
                mock_instance.audit.return_value = []
                scanner.scan_target("https://example.com")
                mock_instance.audit.assert_called_once()

    @patch("corsair.scanner.tls_available", return_value=False)
    def test_cache_findings_appear_in_results(self, _tls):
        from corsair.cache.findings import get_finding

        scanner = HeadScanner()
        cache_finding = get_finding("WCP_CDN_DETECTED")
        cache_finding.current_value = "cloudflare"

        with patch.object(scanner, "_fetch_headers", side_effect=self._mock_fetch_headers):
            with patch("corsair.scanner.CacheAuditor") as MockAuditor:
                mock_instance = MockAuditor.return_value
                mock_instance.audit.return_value = [cache_finding]
                result = scanner.scan_target("https://example.com")
                assert any("CDN" in f.title for f in result.findings)

    @patch("corsair.scanner.tls_available", return_value=False)
    def test_cache_probe_false_disables_active(self, _tls):
        scanner = HeadScanner(cache_probe=False)
        with patch.object(scanner, "_fetch_headers", side_effect=self._mock_fetch_headers):
            with patch("corsair.scanner.CacheAuditor") as MockAuditor:
                mock_instance = MockAuditor.return_value
                mock_instance.audit.return_value = []
                scanner.scan_target("https://example.com")
                MockAuditor.assert_called_once_with(
                    timeout=scanner.timeout, active=False
                )

    @patch("corsair.scanner.tls_available", return_value=False)
    def test_cache_audit_failure_does_not_crash(self, _tls):
        scanner = HeadScanner()
        with patch.object(scanner, "_fetch_headers", side_effect=self._mock_fetch_headers):
            with patch("corsair.scanner.CacheAuditor") as MockAuditor:
                mock_instance = MockAuditor.return_value
                mock_instance.audit.side_effect = Exception("boom")
                result = scanner.scan_target("https://example.com")
                assert result.error is None
                assert result.score >= 0

    @patch("corsair.scanner.tls_available", return_value=False)
    def test_cache_findings_affect_score(self, _tls):
        from corsair.cache.findings import get_finding

        scanner = HeadScanner()
        critical_finding = get_finding("WCP_UNKEYED_HEADER_CRITICAL")

        with patch.object(scanner, "_fetch_headers", side_effect=self._mock_fetch_headers):
            with patch("corsair.scanner.CacheAuditor") as MockAuditor:
                mock_instance = MockAuditor.return_value
                mock_instance.audit.return_value = [critical_finding]
                result = scanner.scan_target("https://example.com")
                assert result.score < 100
