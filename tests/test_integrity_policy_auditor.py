"""Tests for corsair.integrity_policy.auditor.IntegrityPolicyAuditor."""

import pytest

from corsair.integrity_policy.auditor import IntegrityPolicyAuditor
from corsair.models import Severity


# ---------------------------------------------------------------------------
# Static path: one finding per primary scenario
# ---------------------------------------------------------------------------

class TestStaticPathFindingsByScenario:
    def test_ip_001_when_both_headers_absent(self):
        auditor = IntegrityPolicyAuditor(timeout=10, active=False)
        findings = auditor.audit("https://example.com/", {})
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.LOW
        assert "absent" in f.title.lower()

    def test_ip_002_when_only_report_only_present(self):
        auditor = IntegrityPolicyAuditor(timeout=10, active=False)
        headers = {"Integrity-Policy-Report-Only": "blocked-destinations=(script)"}
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "Report-Only" in findings[0].title

    def test_ip_003_on_empty_inner_list(self):
        auditor = IntegrityPolicyAuditor(timeout=10, active=False)
        headers = {"Integrity-Policy": "blocked-destinations=()"}
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "no recognized destinations" in findings[0].title.lower()

    def test_ip_003_on_unparseable_value(self):
        auditor = IntegrityPolicyAuditor(timeout=10, active=False)
        headers = {"Integrity-Policy": "garbage_value!!"}
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "garbage_value!!" in findings[0].current_value

    def test_ip_003_on_all_unknown_tokens(self):
        auditor = IntegrityPolicyAuditor(timeout=10, active=False)
        headers = {"Integrity-Policy": "blocked-destinations=(scripts foo)"}
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_ip_004_when_script_missing(self):
        auditor = IntegrityPolicyAuditor(timeout=10, active=False)
        headers = {"Integrity-Policy": "blocked-destinations=(style)"}
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "does not block script" in findings[0].title.lower()

    def test_static_pass_when_active_false(self):
        auditor = IntegrityPolicyAuditor(timeout=10, active=False)
        headers = {"Integrity-Policy": "blocked-destinations=(script)"}
        findings = auditor.audit("https://example.com/", headers)
        # Stage 2 skipped: only the static PASS finding.
        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS


# ---------------------------------------------------------------------------
# Stage 2 active path
# ---------------------------------------------------------------------------

class TestStage2ActivePath:
    def test_ip_006_fires_on_cross_origin_script_no_integrity(self, httpx_mock):
        body = (
            '<html><body>'
            '<script src="https://cdn.example.net/tag.js"></script>'
            '</body></html>'
        )
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text=body,
            headers={"Content-Type": "text/html"},
        )
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(script)",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 2  # static PASS + IP-006
        ip6 = next(f for f in findings if f.severity == Severity.HIGH)
        assert "cdn.example.net" in ip6.current_value

    def test_ip_006_pass_when_all_scripts_have_integrity(self, httpx_mock):
        body = (
            '<html><body>'
            '<script src="https://cdn.example.net/tag.js" '
            'integrity="sha384-abc" crossorigin="anonymous"></script>'
            '</body></html>'
        )
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text=body,
            headers={"Content-Type": "text/html"},
        )
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(script)",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        # static PASS + IP-006 PASS
        assert len(findings) == 2
        assert all(f.severity == Severity.PASS for f in findings)

    def test_ip_006_inconclusive_on_timeout(self, httpx_mock):
        import httpx as _httpx
        httpx_mock.add_exception(_httpx.ReadTimeout("read timeout"))
        auditor = IntegrityPolicyAuditor(timeout=1, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(script)",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        # static PASS + IP-006 INCONCLUSIVE
        assert len(findings) == 2
        inc = next(f for f in findings if f.severity == Severity.INFO)
        assert "Request timeout" in inc.current_value

    def test_ip_006_inconclusive_on_500(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=500,
            text="server error",
        )
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(script)",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        inc = next(f for f in findings if f.severity == Severity.INFO)
        assert "HTTP 500" in inc.current_value

    def test_ip_006_inconclusive_on_connect_error(self, httpx_mock):
        import httpx as _httpx
        httpx_mock.add_exception(_httpx.ConnectError("dns failure"))
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(script)",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        inc = next(f for f in findings if f.severity == Severity.INFO)
        assert "Connection error" in inc.current_value


# ---------------------------------------------------------------------------
# Stage 2 gate skips — five exit conditions
# ---------------------------------------------------------------------------

class TestStage2GateSkips:
    def test_active_false_skips_body_fetch(self, httpx_mock):
        # No httpx_mock.add_response — if Stage 2 ran, the test would fail.
        auditor = IntegrityPolicyAuditor(timeout=10, active=False)
        headers = {
            "Integrity-Policy": "blocked-destinations=(script)",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1  # static PASS only

    def test_parse_error_skips_body_fetch(self, httpx_mock):
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "garbage!!",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1  # IP-003 only

    def test_script_missing_skips_body_fetch(self, httpx_mock):
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(style)",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1  # IP-004 only

    def test_non_html_content_type_skips_body_fetch(self, httpx_mock):
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(script)",
            "Content-Type": "application/json",
        }
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1  # static PASS only

    def test_missing_content_type_skips_body_fetch(self, httpx_mock):
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {"Integrity-Policy": "blocked-destinations=(script)"}
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1  # static PASS only


# ---------------------------------------------------------------------------
# Combined / interaction cases
# ---------------------------------------------------------------------------

class TestCombinedCases:
    def test_both_headers_present_no_ip_002(self, httpx_mock):
        body = "<html><body>no scripts</body></html>"
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text=body,
            headers={"Content-Type": "text/html"},
        )
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(script)",
            "Integrity-Policy-Report-Only": "blocked-destinations=(script)",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        # Static PASS (no IP-002) + IP-006 PASS (no scripts).
        assert all(f.severity == Severity.PASS for f in findings)
        assert not any("Report-Only" in f.title for f in findings)

    def test_ip_004_skips_body_fetch_no_ip_006(self, httpx_mock):
        # No httpx_mock response — body fetch would fail the test.
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(style)",  # no script
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW  # IP-004 only


# ---------------------------------------------------------------------------
# Compliance / CWE / reference shape — lock into the test suite
# ---------------------------------------------------------------------------

from corsair.integrity_policy.findings import (
    build_ip_003_finding,
    build_ip_006_finding,
    get_finding,
)
from corsair.models import HeaderCategory


class TestFindingMetadataShape:
    def test_each_finding_categorized_as_integrity(self):
        for fid in ("IP-001", "IP-002", "IP-003", "IP-004"):
            f = get_finding(fid)
            assert f.category == HeaderCategory.INTEGRITY, fid
        f6 = build_ip_006_finding(["https://cdn.com/x.js"])
        assert f6.category == HeaderCategory.INTEGRITY

    def test_ip_001_compliance_includes_owasp_a08_and_pci(self):
        f = get_finding("IP-001")
        framework_ids = {(c.framework, c.requirement_id) for c in f.compliance_mappings}
        assert ("OWASP_TOP_10_2021", "A08") in framework_ids
        assert ("PCI_DSS_4_0", "6.4.3") in framework_ids
        assert ("NIST_SP_800_53", "SI-7") in framework_ids

    def test_reference_url_present_and_https(self):
        for fid in ("IP-001", "IP-002", "IP-003", "IP-004"):
            f = get_finding(fid)
            assert f.reference_url is not None
            assert f.reference_url.startswith("https://"), fid
        f6 = build_ip_006_finding([])
        assert f6.reference_url.startswith("https://")
