"""HeadScanner <-> CORSAuditor integration smoke tests."""

from unittest.mock import patch

from corsair.scanner import HeadScanner


def _mock_fetch(headers=None, status=200, final_url="https://example.com"):
    def _fetch(self, url):
        return (status, headers or {}, final_url, None)

    return _fetch


class TestScannerCORSIntegration:
    def test_scanner_invokes_cors_auditor(self):
        scanner = HeadScanner(cors_probe=False, cache_probe=False)
        with patch.object(
            HeadScanner,
            "_fetch_headers",
            _mock_fetch(headers={"Access-Control-Allow-Origin": "*"}),
        ):
            result = scanner.scan_target("https://example.com")

        cors_findings = [f for f in result.findings if f.category.value == "cors"]
        assert len(cors_findings) >= 1
        assert any(f.title == "CORS Allows All Origins" for f in cors_findings)

    def test_scanner_cors_opt_out_still_runs_passive(self):
        scanner = HeadScanner(cors_probe=False, cache_probe=False)
        with patch.object(
            HeadScanner,
            "_fetch_headers",
            _mock_fetch(headers={}),
        ):
            result = scanner.scan_target("https://example.com")
        cors_findings = [f for f in result.findings if f.category.value == "cors"]
        assert len(cors_findings) == 1
        assert cors_findings[0].severity.value == "PASS"

    def test_scanner_no_double_reporting_of_cors(self):
        scanner = HeadScanner(cors_probe=False, cache_probe=False)
        with patch.object(
            HeadScanner,
            "_fetch_headers",
            _mock_fetch(headers={"Access-Control-Allow-Origin": "null"}),
        ):
            result = scanner.scan_target("https://example.com")
        null_findings = [
            f for f in result.findings
            if f.category.value == "cors" and "null" in f.title.lower()
        ]
        assert len(null_findings) == 1
