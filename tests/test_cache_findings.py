"""Test cache poisoning finding definitions are complete and consistent."""

from corsair.cache.findings import ALL_CACHE_FINDINGS, get_finding
from corsair.models import HeaderCategory, Severity


class TestCacheFindingDefinitions:
    def test_all_findings_use_caching_category(self):
        for finding_id, finding in ALL_CACHE_FINDINGS.items():
            assert (
                finding.category == HeaderCategory.CACHING
            ), f"{finding_id} has category {finding.category}, expected CACHING"

    def test_all_findings_have_required_fields(self):
        for finding_id, finding in ALL_CACHE_FINDINGS.items():
            assert finding.header, f"{finding_id} missing header"
            assert finding.title, f"{finding_id} missing title"
            assert finding.description, f"{finding_id} missing description"
            assert finding.recommendation, f"{finding_id} missing recommendation"
            assert finding.reference_url, f"{finding_id} missing reference_url"

    def test_all_findings_have_valid_severity(self):
        for finding_id, finding in ALL_CACHE_FINDINGS.items():
            assert finding.severity in Severity, f"{finding_id} has invalid severity"

    def test_finding_count(self):
        assert len(ALL_CACHE_FINDINGS) == 19

    def test_no_duplicate_ids(self):
        ids = list(ALL_CACHE_FINDINGS.keys())
        assert len(ids) == len(set(ids))

    def test_get_finding_returns_copy(self):
        f1 = get_finding("WCP_NOT_CACHED")
        f2 = get_finding("WCP_NOT_CACHED")
        assert f1 is not f2
        assert f1.title == f2.title

    def test_get_finding_unknown_returns_none(self):
        assert get_finding("NONEXISTENT") is None

    def test_passive_findings_exist(self):
        passive_ids = [
            "WCP_NOT_CACHED",
            "WCP_CDN_DETECTED",
            "WCP_PERMISSIVE_CACHE_CONTROL",
            "WCP_NO_VARY_ORIGIN",
            "WCP_CACHE_PUBLIC_SENSITIVE",
            "WCP_NO_CACHE_KEY_QS",
        ]
        for fid in passive_ids:
            assert fid in ALL_CACHE_FINDINGS, f"Missing passive finding: {fid}"

    def test_active_findings_exist(self):
        active_ids = [
            "WCP_UNKEYED_HEADER_CRITICAL",
            "WCP_UNKEYED_HEADER_HIGH",
            "WCP_UNKEYED_HEADER_MEDIUM",
            "WCP_UNKEYED_HEADER_LOW",
            "WCP_LIVE_CACHE_POISONED",
            "WCP_UNKEYED_HEADER_NO_REFLECT",
            "WCP_PROBE_SKIPPED",
        ]
        for fid in active_ids:
            assert fid in ALL_CACHE_FINDINGS, f"Missing active finding: {fid}"

    def test_cpdos_findings_exist(self):
        cpdos_ids = [
            "WCP_CPDOS_OVERSIZE",
            "WCP_CPDOS_MALFORMED",
            "WCP_CPDOS_METHOD_OVERRIDE",
        ]
        for fid in cpdos_ids:
            assert fid in ALL_CACHE_FINDINGS, f"Missing CPDoS finding: {fid}"

    def test_severity_assignments(self):
        assert ALL_CACHE_FINDINGS["WCP_NOT_CACHED"].severity == Severity.PASS
        assert ALL_CACHE_FINDINGS["WCP_CDN_DETECTED"].severity == Severity.INFO
        assert ALL_CACHE_FINDINGS["WCP_PERMISSIVE_CACHE_CONTROL"].severity == Severity.LOW
        assert ALL_CACHE_FINDINGS["WCP_NO_VARY_ORIGIN"].severity == Severity.MEDIUM
        assert ALL_CACHE_FINDINGS["WCP_NO_CACHE_KEY_QS"].severity == Severity.HIGH
        assert ALL_CACHE_FINDINGS["WCP_UNKEYED_HEADER_CRITICAL"].severity == Severity.CRITICAL
        assert ALL_CACHE_FINDINGS["WCP_LIVE_CACHE_POISONED"].severity == Severity.CRITICAL
        assert ALL_CACHE_FINDINGS["WCP_CPDOS_OVERSIZE"].severity == Severity.HIGH

    def test_compliance_mappings_present(self):
        for fid in ["WCP_NO_VARY_ORIGIN", "WCP_UNKEYED_HEADER_CRITICAL", "WCP_CPDOS_OVERSIZE"]:
            finding = ALL_CACHE_FINDINGS[fid]
            assert len(finding.compliance_mappings) > 0, f"{fid} missing compliance mappings"

    def test_alt_svc_poisoning_finding_exists(self):
        f = get_finding("WCP_ALT_SVC_POISONING")
        assert f is not None
        assert f.severity == Severity.HIGH
        assert f.header == "Alt-Svc"
        assert "HTTP/3" in f.description or "QUIC" in f.description

    def test_set_cookie_poisoning_finding_exists(self):
        f = get_finding("WCP_SET_COOKIE_POISONING")
        assert f is not None
        assert f.severity == Severity.HIGH
        assert f.header == "Set-Cookie"
        assert "session" in f.description.lower() or "fixation" in f.description.lower()

    def test_cache_keying_undetermined_finding_exists(self):
        f = get_finding("WCP_CACHE_KEYING_UNDETERMINED")
        assert f is not None
        assert f.severity == Severity.INFO
        assert "manual" in f.recommendation.lower()
