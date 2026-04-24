"""Test CORS DAST finding registry integrity (Wave 1)."""

from corsair.cors.findings import ALL_CORS_FINDINGS, get_finding
from corsair.models import HeaderCategory, Severity


class TestCORSFindingRegistry:
    def test_registry_size(self):
        # 5 Core + 2 Meta (Wave 1) + 3 Bypass (Wave 2) = 10.
        assert len(ALL_CORS_FINDINGS) == 10

    def test_all_findings_use_cors_category(self):
        for fid, finding in ALL_CORS_FINDINGS.items():
            assert finding.category == HeaderCategory.CORS, (
                f"{fid} has category {finding.category}, expected CORS"
            )

    def test_all_findings_have_required_fields(self):
        for fid, finding in ALL_CORS_FINDINGS.items():
            assert finding.header, f"{fid} missing header"
            assert finding.title, f"{fid} missing title"
            assert finding.description, f"{fid} missing description"
            assert finding.recommendation, f"{fid} missing recommendation"
            assert finding.reference_url, f"{fid} missing reference_url"

    def test_all_findings_have_valid_severity(self):
        for fid, finding in ALL_CORS_FINDINGS.items():
            assert finding.severity in Severity, f"{fid} invalid severity"

    def test_core5_finding_ids_exist(self):
        core5 = [
            "CORS_ARBITRARY_ORIGIN_CRED",
            "CORS_ARBITRARY_ORIGIN",
            "CORS_NULL_ORIGIN_CRED",
            "CORS_NULL_ORIGIN",
            "CORS_WILDCARD_CRED",
        ]
        for fid in core5:
            assert fid in ALL_CORS_FINDINGS, f"Missing Core-5 finding: {fid}"

    def test_meta_findings_exist(self):
        for fid in ("CORS_PROBE_INCONCLUSIVE", "CORS_PHASE_TIMEOUT"):
            assert fid in ALL_CORS_FINDINGS, f"Missing meta finding: {fid}"

    def test_severity_mapping_matches_spec(self):
        # Spec §5 severity defaults (before signal-driven downgrade).
        assert ALL_CORS_FINDINGS["CORS_ARBITRARY_ORIGIN_CRED"].severity == Severity.CRITICAL
        assert ALL_CORS_FINDINGS["CORS_ARBITRARY_ORIGIN"].severity == Severity.HIGH
        assert ALL_CORS_FINDINGS["CORS_NULL_ORIGIN_CRED"].severity == Severity.HIGH
        assert ALL_CORS_FINDINGS["CORS_NULL_ORIGIN"].severity == Severity.MEDIUM
        assert ALL_CORS_FINDINGS["CORS_WILDCARD_CRED"].severity == Severity.MEDIUM
        assert ALL_CORS_FINDINGS["CORS_PROBE_INCONCLUSIVE"].severity == Severity.INFO
        assert ALL_CORS_FINDINGS["CORS_PHASE_TIMEOUT"].severity == Severity.INFO

    def test_get_finding_returns_copy(self):
        f1 = get_finding("CORS_WILDCARD_CRED")
        f2 = get_finding("CORS_WILDCARD_CRED")
        assert f1 is not f2
        assert f1.title == f2.title

    def test_get_finding_unknown_returns_none(self):
        assert get_finding("CORS_NONEXISTENT") is None

    def test_no_duplicate_ids(self):
        ids = list(ALL_CORS_FINDINGS.keys())
        assert len(ids) == len(set(ids))

    def test_all_ids_use_cors_prefix(self):
        for fid in ALL_CORS_FINDINGS:
            assert fid.startswith("CORS_"), f"{fid} missing CORS_ prefix"
