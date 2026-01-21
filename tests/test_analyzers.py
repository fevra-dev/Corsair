"""Test header analyzers."""

import pytest
from corsair.analyzers import CSPAnalyzer, HSTSAnalyzer, XFrameOptionsAnalyzer
from corsair.models import Severity


class TestCSPAnalyzer:
    def test_missing_csp_is_critical(self):
        analyzer = CSPAnalyzer({}, "https://example.com")
        findings = analyzer.analyze()

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_unsafe_inline_detected(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"
        }
        analyzer = CSPAnalyzer(headers, "https://example.com")
        findings = analyzer.analyze()

        # Should find unsafe-inline issue
        unsafe_findings = [f for f in findings if "unsafe-inline" in f.description]
        assert len(unsafe_findings) > 0
        assert unsafe_findings[0].severity == Severity.HIGH


class TestHSTSAnalyzer:
    def test_missing_hsts_on_https_is_critical(self):
        analyzer = HSTSAnalyzer({}, "https://example.com")
        findings = analyzer.analyze()

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_short_max_age_is_medium(self):
        headers = {"Strict-Transport-Security": "max-age=86400"}
        analyzer = HSTSAnalyzer(headers, "https://example.com")
        findings = analyzer.analyze()

        short_age = [f for f in findings if "Too Short" in f.title]
        assert len(short_age) > 0
        assert short_age[0].severity == Severity.MEDIUM

    def test_good_hsts_passes(self):
        headers = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"}
        analyzer = HSTSAnalyzer(headers, "https://example.com")
        findings = analyzer.analyze()

        # All findings should be PASS or INFO
        for finding in findings:
            assert finding.severity in (Severity.PASS, Severity.INFO)


class TestXFrameOptionsAnalyzer:
    def test_missing_xfo_is_high(self):
        analyzer = XFrameOptionsAnalyzer({}, "https://example.com")
        findings = analyzer.analyze()

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_valid_deny_passes(self):
        headers = {"X-Frame-Options": "DENY"}
        analyzer = XFrameOptionsAnalyzer(headers, "https://example.com")
        findings = analyzer.analyze()

        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS
