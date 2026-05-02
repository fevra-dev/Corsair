"""Unit tests for corsair.fetch_metadata.findings."""

import pytest

from corsair.fetch_metadata.findings import (
    ALL_FM_FINDINGS,
    FMContext,
    build_not_enforced_finding,
    build_inconclusive_finding,
    get_finding,
)
from corsair.models import HeaderCategory, Severity


class TestRegistry:
    def test_three_findings_registered(self):
        assert set(ALL_FM_FINDINGS.keys()) == {
            "FM_NO_FETCH_METADATA_POLICY",
            "FM_FETCH_METADATA_ENFORCED",
            "FM_FETCH_METADATA_INCONCLUSIVE",
        }

    def test_get_finding_returns_deepcopy(self):
        a = get_finding("FM_FETCH_METADATA_ENFORCED")
        b = get_finding("FM_FETCH_METADATA_ENFORCED")
        assert a is not b
        a.title = "mutated"
        assert b.title != "mutated"

    def test_get_finding_unknown_returns_none(self):
        assert get_finding("FM_DOES_NOT_EXIST") is None


class TestPositiveFinding:
    def test_enforced_is_pass(self):
        f = get_finding("FM_FETCH_METADATA_ENFORCED")
        assert f.severity == Severity.PASS
        assert f.category == HeaderCategory.ISOLATION
        assert "enforced" in f.title.lower() or "enforcement" in f.title.lower()


class TestInconclusiveFinding:
    def test_inconclusive_is_info(self):
        f = build_inconclusive_finding(reason="Network error during probe sequence")
        assert f.severity == Severity.INFO
        assert "Network error during probe sequence" in f.description

    def test_inconclusive_template_unmodified(self):
        # Building a finding from the template must not mutate it.
        original = ALL_FM_FINDINGS["FM_FETCH_METADATA_INCONCLUSIVE"]
        original_desc = original.description
        build_inconclusive_finding(reason="Some specific reason")
        assert ALL_FM_FINDINGS["FM_FETCH_METADATA_INCONCLUSIVE"].description == original_desc


class TestSeverityMatrix:
    """All six rows from spec §5.1."""

    def test_no_mitigations_no_cdn_high(self):
        ctx = FMContext(
            has_samesite_strict=False,
            has_samesite_lax=False,
            has_csrf_token=False,
            cdn_detected=False,
        )
        f = build_not_enforced_finding(ctx, soft=False)
        assert f.severity == Severity.HIGH

    def test_no_mitigations_with_cdn_medium(self):
        ctx = FMContext(False, False, False, cdn_detected=True)
        f = build_not_enforced_finding(ctx, soft=False)
        assert f.severity == Severity.MEDIUM

    def test_lax_no_csrf_no_cdn_medium(self):
        ctx = FMContext(False, True, False, False)
        f = build_not_enforced_finding(ctx, soft=False)
        assert f.severity == Severity.MEDIUM

    def test_csrf_no_lax_no_cdn_medium(self):
        # XOR partial — CSRF token only.
        ctx = FMContext(False, False, True, False)
        f = build_not_enforced_finding(ctx, soft=False)
        assert f.severity == Severity.MEDIUM

    def test_lax_no_csrf_with_cdn_low(self):
        ctx = FMContext(False, True, False, True)
        f = build_not_enforced_finding(ctx, soft=False)
        assert f.severity == Severity.LOW

    def test_strict_and_csrf_low(self):
        ctx = FMContext(True, False, True, False)
        f = build_not_enforced_finding(ctx, soft=False)
        assert f.severity == Severity.LOW

    def test_strict_and_csrf_with_cdn_low(self):
        ctx = FMContext(True, False, True, True)
        f = build_not_enforced_finding(ctx, soft=False)
        assert f.severity == Severity.LOW

    def test_soft_enforcement_emits_info(self):
        # SOFT_ENFORCED collapses to INFO regardless of context.
        ctx = FMContext(False, False, False, False)
        f = build_not_enforced_finding(ctx, soft=True)
        assert f.severity == Severity.INFO


class TestComplianceMappings:
    def test_high_includes_pci_and_nist(self):
        ctx = FMContext(False, False, False, False)
        f = build_not_enforced_finding(ctx, soft=False)
        frameworks = {m.framework for m in f.compliance_mappings}
        assert "OWASP_TOP_10_2025" in frameworks
        assert "PCI_DSS_4_0" in frameworks
        assert "NIST_SP_800_53" in frameworks

    def test_medium_includes_nist_not_pci(self):
        ctx = FMContext(False, True, False, False)  # MEDIUM (lax only, no CDN)
        f = build_not_enforced_finding(ctx, soft=False)
        frameworks = {m.framework for m in f.compliance_mappings}
        assert "NIST_SP_800_53" in frameworks
        assert "PCI_DSS_4_0" not in frameworks

    def test_low_excludes_pci_and_nist(self):
        ctx = FMContext(True, False, True, False)  # LOW
        f = build_not_enforced_finding(ctx, soft=False)
        frameworks = {m.framework for m in f.compliance_mappings}
        assert "PCI_DSS_4_0" not in frameworks
        assert "NIST_SP_800_53" not in frameworks
        # OWASP and CWE always present.
        assert "OWASP_TOP_10_2025" in frameworks

    def test_cwe_correlations_present(self):
        ctx = FMContext(False, False, False, False)
        f = build_not_enforced_finding(ctx, soft=False)
        cwe_ids = {c.cve_id for c in f.cve_correlations}
        assert "CWE-352" in cwe_ids
        assert "CWE-693" in cwe_ids


class TestNonBrowserCaveat:
    def test_caveat_in_description(self):
        ctx = FMContext(False, False, False, False)
        f = build_not_enforced_finding(ctx, soft=False)
        assert "non-browser scripted clients" in f.description


class TestCdnDowngradeDescription:
    def test_cdn_warning_appended_when_cdn(self):
        ctx = FMContext(False, False, False, True)
        f = build_not_enforced_finding(ctx, soft=False)
        assert "CDN" in f.description or "direct-origin" in f.description

    def test_no_cdn_warning_when_no_cdn(self):
        ctx = FMContext(False, False, False, False)
        f = build_not_enforced_finding(ctx, soft=False)
        assert "direct-origin" not in f.description
