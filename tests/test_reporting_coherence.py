"""Tests for the Reporting-Endpoints Coherence Analyzer."""

import pytest

from corsair.analyzers.reporting import (
    _extract_csp_report_to,
    _extract_integrity_endpoints,
    _extract_nel_report_to,
    _extract_param_report_to,
    _is_navigation_response,
    _parse_report_to,
    _parse_reporting_endpoints,
)


# ---------------------------------------------------------------------------
# _parse_reporting_endpoints
# ---------------------------------------------------------------------------

class TestParseReportingEndpoints:
    def test_empty_string_returns_empty_set(self):
        assert _parse_reporting_endpoints("") == set()

    def test_single_endpoint(self):
        assert _parse_reporting_endpoints('main="https://example.com/r"') == {"main"}

    def test_multiple_endpoints(self):
        value = 'main="https://a.example.com/r", backup="https://b.example.com/r"'
        assert _parse_reporting_endpoints(value) == {"main", "backup"}

    def test_quoted_url_with_commas(self):
        # Some URLs contain commas in query strings — must not split on them.
        value = 'main="https://example.com/r?a=1,b=2", other="https://b.example.com"'
        assert _parse_reporting_endpoints(value) == {"main", "other"}

    def test_trailing_whitespace(self):
        assert _parse_reporting_endpoints('main="https://example.com/r"   ') == {"main"}

    def test_case_mixed_keys_lowercased(self):
        # RFC 8941 keys are nominally lowercase; normalize defensively.
        assert _parse_reporting_endpoints('Main="https://example.com/r"') == {"main"}

    def test_malformed_returns_empty_set(self):
        assert _parse_reporting_endpoints("this is not a structured field") == set()


# ---------------------------------------------------------------------------
# _parse_report_to
# ---------------------------------------------------------------------------

class TestParseReportTo:
    def test_empty_string_returns_empty_set(self):
        assert _parse_report_to("") == set()

    def test_bare_object_auto_wrapped(self):
        # Some servers send Report-To as a single object, not an array.
        value = '{"group": "main", "max_age": 10886400, "endpoints": [{"url": "https://r.example.com"}]}'
        assert _parse_report_to(value) == {"main"}

    def test_array_of_objects(self):
        value = '[{"group": "main", "endpoints": [{"url": "https://a"}]}, {"group": "alt", "endpoints": [{"url": "https://b"}]}]'
        assert _parse_report_to(value) == {"main", "alt"}

    def test_missing_group_defaults_to_default(self):
        # W3C spec: missing group name defaults to "default".
        value = '{"endpoints": [{"url": "https://r.example.com"}]}'
        assert _parse_report_to(value) == {"default"}

    def test_malformed_json_returns_empty_set(self):
        assert _parse_report_to("not json at all {{{") == set()

    def test_mixed_case_names_lowercased(self):
        value = '{"group": "MainGroup", "endpoints": [{"url": "https://r"}]}'
        assert _parse_report_to(value) == {"maingroup"}


# ---------------------------------------------------------------------------
# _extract_csp_report_to
# ---------------------------------------------------------------------------

class TestExtractCSPReportTo:
    def test_directive_present(self):
        value = "default-src 'self'; report-to my-endpoint"
        assert _extract_csp_report_to(value) == "my-endpoint"

    def test_directive_absent(self):
        value = "default-src 'self'; img-src *"
        assert _extract_csp_report_to(value) is None

    def test_multiple_directives_only_report_to_extracted(self):
        value = "default-src 'self'; script-src 'self'; report-to csp-endpoint; report-uri /legacy"
        assert _extract_csp_report_to(value) == "csp-endpoint"

    def test_extra_whitespace(self):
        value = "default-src 'self';   report-to    my-endpoint  "
        assert _extract_csp_report_to(value) == "my-endpoint"

    def test_case_normalized(self):
        value = "default-src 'self'; report-to MyEndpoint"
        assert _extract_csp_report_to(value) == "myendpoint"


# ---------------------------------------------------------------------------
# _extract_param_report_to
# ---------------------------------------------------------------------------

class TestExtractParamReportTo:
    def test_quoted_name(self):
        value = 'same-origin; report-to="my-endpoint"'
        assert _extract_param_report_to(value) == "my-endpoint"

    def test_unquoted_name(self):
        value = "same-origin; report-to=my-endpoint"
        assert _extract_param_report_to(value) == "my-endpoint"

    def test_missing_parameter(self):
        assert _extract_param_report_to("same-origin") is None

    def test_report_to_not_first_parameter(self):
        value = 'require-corp; some-other-param=value; report-to="rt-endpoint"'
        assert _extract_param_report_to(value) == "rt-endpoint"

    def test_empty_value(self):
        assert _extract_param_report_to("") is None


# ---------------------------------------------------------------------------
# _extract_nel_report_to
# ---------------------------------------------------------------------------

class TestExtractNELReportTo:
    def test_valid_json(self):
        value = '{"report_to": "nel-endpoint", "max_age": 86400}'
        assert _extract_nel_report_to(value) == "nel-endpoint"

    def test_malformed_json(self):
        assert _extract_nel_report_to("not json {") is None

    def test_missing_report_to_field(self):
        value = '{"max_age": 86400, "include_subdomains": true}'
        assert _extract_nel_report_to(value) is None

    def test_empty_value(self):
        assert _extract_nel_report_to("") is None

    def test_case_normalized(self):
        value = '{"report_to": "NELEndpoint"}'
        assert _extract_nel_report_to(value) == "nelendpoint"


# ---------------------------------------------------------------------------
# _extract_integrity_endpoints
# ---------------------------------------------------------------------------

class TestExtractIntegrityEndpoints:
    def test_single_endpoint(self):
        value = "blocked-destinations=(script), endpoints=(my-endpoint)"
        assert _extract_integrity_endpoints(value) == {"my-endpoint"}

    def test_multiple_endpoints(self):
        value = "blocked-destinations=(script), endpoints=(ep1 ep2 ep3)"
        assert _extract_integrity_endpoints(value) == {"ep1", "ep2", "ep3"}

    def test_missing_endpoints_param(self):
        assert _extract_integrity_endpoints("blocked-destinations=(script)") == set()

    def test_malformed_inner_list(self):
        # Unclosed parenthesis — should not crash.
        assert _extract_integrity_endpoints("endpoints=(ep1 ep2") == set()

    def test_empty_value(self):
        assert _extract_integrity_endpoints("") == set()

    def test_case_normalized(self):
        value = "endpoints=(MyEndpoint OtherEP)"
        assert _extract_integrity_endpoints(value) == {"myendpoint", "otherep"}


# ---------------------------------------------------------------------------
# _is_navigation_response
# ---------------------------------------------------------------------------

class TestIsNavigationResponse:
    def test_text_html(self):
        assert _is_navigation_response({"content-type": "text/html"}) is True

    def test_text_html_with_charset(self):
        assert _is_navigation_response({"content-type": "text/html; charset=utf-8"}) is True

    def test_application_xhtml(self):
        assert _is_navigation_response({"content-type": "application/xhtml+xml"}) is True

    def test_application_xml(self):
        assert _is_navigation_response({"content-type": "application/xml"}) is True

    def test_application_json_excluded(self):
        assert _is_navigation_response({"content-type": "application/json"}) is False

    def test_javascript_excluded(self):
        assert _is_navigation_response({"content-type": "application/javascript"}) is False

    def test_css_excluded(self):
        assert _is_navigation_response({"content-type": "text/css"}) is False

    def test_image_excluded(self):
        assert _is_navigation_response({"content-type": "image/png"}) is False

    def test_text_plain_excluded(self):
        assert _is_navigation_response({"content-type": "text/plain"}) is False

    def test_missing_content_type_treated_as_navigation(self):
        # Default per RFC 7231 is application/octet-stream, but in practice many
        # origins serving HTML omit Content-Type. Err toward running the check.
        assert _is_navigation_response({}) is True

    def test_empty_content_type_treated_as_navigation(self):
        assert _is_navigation_response({"content-type": ""}) is True

    def test_case_insensitive_content_type_header_name(self):
        assert _is_navigation_response({"Content-Type": "text/html"}) is True


# ---------------------------------------------------------------------------
# Finding templates + _build_finding
# ---------------------------------------------------------------------------

from corsair.analyzers.reporting import (
    _REPORT_001_TEMPLATE,
    _REPORT_002_TEMPLATE,
    _REPORT_004_TEMPLATE,
    _build_finding,
)
from corsair.models import HeaderCategory, Severity


class TestFindingTemplates:
    def test_report_001_is_low_severity(self):
        assert _REPORT_001_TEMPLATE.severity == Severity.LOW

    def test_report_002_is_medium_severity(self):
        assert _REPORT_002_TEMPLATE.severity == Severity.MEDIUM

    def test_report_004_is_high_severity(self):
        assert _REPORT_004_TEMPLATE.severity == Severity.HIGH

    def test_all_templates_use_reporting_category(self):
        for tpl in (_REPORT_001_TEMPLATE, _REPORT_002_TEMPLATE, _REPORT_004_TEMPLATE):
            assert tpl.category == HeaderCategory.REPORTING


class TestBuildFinding:
    def test_returns_deepcopy_not_template(self):
        f = _build_finding(_REPORT_002_TEMPLATE, "ghost", ["Content-Security-Policy"], cdn_detected=False)
        assert f is not _REPORT_002_TEMPLATE
        # Mutating the result must not pollute the template.
        f.title = "MUTATED"
        assert _REPORT_002_TEMPLATE.title != "MUTATED"

    def test_orphan_name_in_description(self):
        f = _build_finding(_REPORT_002_TEMPLATE, "ghost-endpoint", ["Content-Security-Policy"], cdn_detected=False)
        assert "ghost-endpoint" in f.description

    def test_affected_headers_in_header_field(self):
        f = _build_finding(
            _REPORT_002_TEMPLATE, "ghost",
            ["Content-Security-Policy", "Cross-Origin-Embedder-Policy"],
            cdn_detected=False,
        )
        assert "Content-Security-Policy" in f.header
        assert "Cross-Origin-Embedder-Policy" in f.header

    def test_current_value_includes_orphan_and_headers(self):
        f = _build_finding(
            _REPORT_002_TEMPLATE, "ghost",
            ["Content-Security-Policy"], cdn_detected=False,
        )
        assert "ghost" in f.current_value
        assert "Content-Security-Policy" in f.current_value

    def test_cdn_caveat_appended_when_detected(self):
        f = _build_finding(_REPORT_002_TEMPLATE, "ghost", ["Content-Security-Policy"], cdn_detected=True)
        assert "CDN" in f.description or "edge" in f.description

    def test_no_cdn_caveat_when_not_detected(self):
        f = _build_finding(_REPORT_002_TEMPLATE, "ghost", ["Content-Security-Policy"], cdn_detected=False)
        assert "CDN" not in f.description


# ---------------------------------------------------------------------------
# ReportingCoherenceAnalyzer — classification (Layer 2 from spec)
# ---------------------------------------------------------------------------

from corsair.analyzers.reporting import ReportingCoherenceAnalyzer


def _make_analyzer(headers, url="https://example.com/"):
    return ReportingCoherenceAnalyzer(headers=headers, url=url)


def _ids(findings):
    """Return a sorted list of (severity, header) tuples for stable comparison."""
    return sorted([(f.severity.value, f.header) for f in findings])


class TestClassification:
    def test_ip_only_orphan_is_high(self):
        headers = {
            "content-type": "text/html",
            "integrity-policy": "endpoints=(missing-ip-ep)",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_ip_orphan_with_csp_referrer_collapses_to_single_high(self):
        headers = {
            "content-type": "text/html",
            "integrity-policy": "endpoints=(shared-orphan)",
            "content-security-policy": "default-src 'self'; report-to shared-orphan",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "Integrity-Policy" in findings[0].header
        assert "Content-Security-Policy" in findings[0].header

    def test_ip_orphan_with_legacy_only_definition_is_high(self):
        # IP does NOT fall back to Report-To, so legacy-only definition does
        # not rescue the IP reference.
        headers = {
            "content-type": "text/html",
            "report-to": '{"group": "legacy-only", "endpoints": [{"url": "https://r"}]}',
            "integrity-policy": "endpoints=(legacy-only)",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_csp_reference_to_legacy_only_is_low(self):
        # CSP CAN fall back to Report-To in Chromium, so this is a migration
        # gap, not a hard orphan.
        headers = {
            "content-type": "text/html",
            "report-to": '{"group": "legacy-grp", "endpoints": [{"url": "https://r"}]}',
            "content-security-policy": "default-src 'self'; report-to legacy-grp",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_csp_reference_to_undefined_name_is_medium(self):
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; report-to ghost",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_placeholder_in_report_only_downgraded_to_info(self):
        headers = {
            "content-type": "text/html",
            "content-security-policy-report-only": "default-src 'self'; report-to todo",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    def test_placeholder_in_enforcing_csp_stays_medium(self):
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; report-to todo",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_placeholder_in_integrity_policy_stays_high(self):
        headers = {
            "content-type": "text/html",
            "integrity-policy": "endpoints=(todo)",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_same_orphan_in_three_headers_collapses(self):
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; report-to ghost",
            "content-security-policy-report-only": "default-src 'self'; report-to ghost",
            "cross-origin-opener-policy": 'same-origin; report-to="ghost"',
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        h = findings[0].header
        assert "Content-Security-Policy" in h
        assert "Content-Security-Policy-Report-Only" in h
        assert "Cross-Origin-Opener-Policy" in h

    def test_two_distinct_orphans_emit_two_findings(self):
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; report-to ghost-a",
            "cross-origin-opener-policy": 'same-origin; report-to="ghost-b"',
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 2
        # Both MEDIUM, distinct names.
        names_in_descriptions = {f.description for f in findings}
        assert any("ghost-a" in d for d in names_in_descriptions)
        assert any("ghost-b" in d for d in names_in_descriptions)


# ---------------------------------------------------------------------------
# Analyzer integration tests (Layer 3 from spec)
# ---------------------------------------------------------------------------

class TestAnalyzerIntegration:
    def test_healthy_site_no_findings(self):
        headers = {
            "content-type": "text/html",
            "reporting-endpoints": 'main="https://reports.example.com/main"',
            "content-security-policy": "default-src 'self'; report-to main",
        }
        findings = _make_analyzer(headers).analyze()
        assert findings == []

    def test_no_reporting_headers_no_findings(self):
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'",
        }
        findings = _make_analyzer(headers).analyze()
        assert findings == []

    def test_reporting_endpoints_defined_but_unreferenced_no_findings(self):
        headers = {
            "content-type": "text/html",
            "reporting-endpoints": 'main="https://r.example.com/r"',
        }
        findings = _make_analyzer(headers).analyze()
        assert findings == []

    def test_non_html_response_skipped_even_with_orphans(self):
        headers = {
            "content-type": "application/json",
            "content-security-policy": "default-src 'self'; report-to ghost",
        }
        findings = _make_analyzer(headers).analyze()
        assert findings == []

    def test_missing_content_type_runs_analyzer(self):
        headers = {
            "content-security-policy": "default-src 'self'; report-to ghost",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_walkthrough_example_emits_three_findings(self):
        # The §7 walkthrough from the spec.
        headers = {
            "content-type": "text/html; charset=utf-8",
            "reporting-endpoints": 'csp-endpoint="https://reports.example.com/csp"',
            "report-to": '{"group":"legacy-group","max_age":10886400,"endpoints":[{"url":"https://r.example.com"}]}',
            "content-security-policy": "default-src 'self'; report-to csp-endpoint",
            "content-security-policy-report-only": "default-src 'self'; report-to ghost-endpoint",
            "cross-origin-opener-policy": 'same-origin; report-to="legacy-group"',
            "cross-origin-embedder-policy": 'require-corp; report-to="ghost-endpoint"',
            "integrity-policy": "blocked-destinations=(script), endpoints=(missing-ip-endpoint)",
        }
        findings = _make_analyzer(headers).analyze()
        assert {f.severity for f in findings} == {Severity.HIGH, Severity.MEDIUM, Severity.LOW}
        assert len(findings) == 3
        # MEDIUM finding should list both CSP-RO and COEP.
        medium = next(f for f in findings if f.severity == Severity.MEDIUM)
        assert "Content-Security-Policy-Report-Only" in medium.header
        assert "Cross-Origin-Embedder-Policy" in medium.header

    def test_cdn_detected_appends_caveat(self, monkeypatch):
        from corsair.analyzers import reporting as mod
        monkeypatch.setattr(mod, "fingerprint_cdn", lambda _h: "cloudflare")
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; report-to ghost",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert "CDN" in findings[0].description or "edge" in findings[0].description

    def test_no_cdn_no_caveat(self, monkeypatch):
        from corsair.analyzers import reporting as mod
        monkeypatch.setattr(mod, "fingerprint_cdn", lambda _h: None)
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; report-to ghost",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert "CDN" not in findings[0].description

    def test_severity_unchanged_with_or_without_cdn(self, monkeypatch):
        from corsair.analyzers import reporting as mod
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; report-to ghost",
        }

        monkeypatch.setattr(mod, "fingerprint_cdn", lambda _h: None)
        sev_no = _make_analyzer(headers).analyze()[0].severity
        monkeypatch.setattr(mod, "fingerprint_cdn", lambda _h: "cloudflare")
        sev_yes = _make_analyzer(headers).analyze()[0].severity
        assert sev_no == sev_yes == Severity.MEDIUM

    def test_coop_ro_and_coep_ro_extracted(self):
        headers = {
            "content-type": "text/html",
            "cross-origin-opener-policy-report-only": 'same-origin; report-to="ghost-coop-ro"',
            "cross-origin-embedder-policy-report-only": 'require-corp; report-to="ghost-coep-ro"',
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 2
        names_in_descriptions = " ".join(f.description for f in findings)
        assert "ghost-coop-ro" in names_in_descriptions
        assert "ghost-coep-ro" in names_in_descriptions

    def test_malformed_report_to_does_not_crash(self):
        headers = {
            "content-type": "text/html",
            "report-to": "this is not valid json {{{",
            "content-security-policy": "default-src 'self'; report-to ghost",
        }
        # Should not raise; ghost remains an orphan.
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_malformed_reporting_endpoints_does_not_crash(self):
        headers = {
            "content-type": "text/html",
            "reporting-endpoints": "completely malformed structured field",
            "content-security-policy": "default-src 'self'; report-to ghost",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_fingerprint_cdn_raises_no_crash(self, monkeypatch):
        from corsair.analyzers import reporting as mod

        def boom(_h):
            raise RuntimeError("boom")

        monkeypatch.setattr(mod, "fingerprint_cdn", boom)
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; report-to ghost",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert "CDN" not in findings[0].description
