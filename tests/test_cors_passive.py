"""Passive (header-only) CORS analysis tests.

These tests exercise corsair.cors.passive.analyze. They are the regression
gate for the migration from corsair/analyzers/cors.py: behavior must match
exactly so that the adapter in corsair/analyzers/cors.py keeps returning
the same findings for the same inputs.
"""

from corsair.cors.passive import analyze
from corsair.models import Severity


class TestPassiveCORS:
    def test_no_cors_headers_emits_pass(self):
        findings = analyze({}, "https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS
        assert "Same-Origin" in findings[0].title or "not configured" in findings[0].title.lower()

    def test_wildcard_no_creds_is_medium(self):
        findings = analyze(
            {"Access-Control-Allow-Origin": "*"},
            "https://example.com",
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "*" in findings[0].current_value

    def test_wildcard_with_creds_uses_wildcard_cred_finding(self):
        findings = analyze(
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
            "https://example.com",
        )
        assert len(findings) == 1
        # Migrated finding uses CORS_WILDCARD_CRED severity (MEDIUM per spec §5).
        assert findings[0].severity == Severity.MEDIUM
        assert "Wildcard" in findings[0].title

    def test_null_origin_is_high(self):
        findings = analyze(
            {"Access-Control-Allow-Origin": "null"},
            "https://example.com",
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "null" in findings[0].title.lower()

    def test_specific_origin_emits_pass(self):
        findings = analyze(
            {"Access-Control-Allow-Origin": "https://trusted.example.com"},
            "https://example.com",
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS

    def test_case_insensitive_header_lookup(self):
        findings = analyze(
            {"access-control-allow-origin": "*"},
            "https://example.com",
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM


class TestLegacyAdapter:
    """The old CORSAnalyzer class must still work for the analyzer registry."""

    def test_adapter_returns_same_findings(self):
        from corsair.analyzers.cors import CORSAnalyzer

        headers = {"Access-Control-Allow-Origin": "*"}
        analyzer = CORSAnalyzer(headers, "https://example.com")
        findings = analyzer.analyze()
        passive_findings = analyze(headers, "https://example.com")

        assert len(findings) == len(passive_findings)
        assert findings[0].severity == passive_findings[0].severity
        assert findings[0].title == passive_findings[0].title
