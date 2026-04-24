"""Wave 2 finding registry tests."""

from corsair.cors.findings import ALL_CORS_FINDINGS, get_finding
from corsair.models import HeaderCategory, Severity


WAVE2_IDS = (
    "CORS_SUBDOMAIN_BYPASS",
    "CORS_PROTOCOL_DOWNGRADE",
    "CORS_INTERNAL_ORIGIN",
)


class TestWave2FindingsRegistered:
    def test_all_three_present_in_registry(self):
        for fid in WAVE2_IDS:
            assert fid in ALL_CORS_FINDINGS, f"{fid} missing"

    def test_get_finding_returns_deep_copy(self):
        a = get_finding("CORS_SUBDOMAIN_BYPASS")
        b = get_finding("CORS_SUBDOMAIN_BYPASS")
        assert a is not b  # deep copy — mutation safety
        a.title = "mutated"
        assert b.title != "mutated"


class TestWave2FindingsSeverities:
    """Matches spec §5 severity column."""

    def test_subdomain_bypass_is_high(self):
        f = get_finding("CORS_SUBDOMAIN_BYPASS")
        assert f.severity == Severity.HIGH

    def test_protocol_downgrade_is_high(self):
        f = get_finding("CORS_PROTOCOL_DOWNGRADE")
        assert f.severity == Severity.HIGH

    def test_internal_origin_is_high(self):
        f = get_finding("CORS_INTERNAL_ORIGIN")
        assert f.severity == Severity.HIGH


class TestWave2FindingsMetadata:
    def test_all_are_cors_category(self):
        for fid in WAVE2_IDS:
            f = get_finding(fid)
            assert f.category == HeaderCategory.CORS

    def test_all_have_non_empty_titles_and_descriptions(self):
        for fid in WAVE2_IDS:
            f = get_finding(fid)
            assert f.title, f"{fid} has empty title"
            assert len(f.description) > 50, (
                f"{fid} description too short ({len(f.description)} chars)"
            )

    def test_all_have_header_access_control_allow_origin(self):
        for fid in WAVE2_IDS:
            f = get_finding(fid)
            assert f.header == "Access-Control-Allow-Origin"

    def test_all_have_recommendations(self):
        for fid in WAVE2_IDS:
            f = get_finding(fid)
            assert f.recommendation, f"{fid} has no recommendation"
