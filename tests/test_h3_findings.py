"""Tests for corsair.h3.findings — template metadata shape and builder API."""

import pytest

from corsair.h3.diff import HeaderDiffResult
from corsair.h3.findings import (
    build_h3_001_high,
    build_h3_001_low,
    build_h3_001_pass,
    build_h3_002_finding,
    build_h3_002_pass,
    build_h3_003_finding,
    build_h3_inconclusive_finding,
    build_h3_extras_missing_finding,
    get_finding,
)
from corsair.models import HeaderCategory, Severity


class TestRegistry:
    def test_get_finding_returns_deepcopy(self):
        a = get_finding("H3-001-HIGH")
        b = get_finding("H3-001-HIGH")
        a.title = "mutated"
        assert b.title != "mutated"

    def test_unknown_finding_returns_none(self):
        assert get_finding("BOGUS") is None


class TestH3001SeverityTiers:
    def test_high_tier(self):
        f = build_h3_001_high(early_data_capability=16384, status=200)
        assert f.severity == Severity.HIGH
        assert f.category == HeaderCategory.H3
        assert "HTTP/3 0-RTT" in f.title
        assert "16384" in (f.current_value or "")
        assert "200" in (f.current_value or "")

    def test_low_tier(self):
        f = build_h3_001_low(status=200)
        assert f.severity == Severity.LOW
        assert f.category == HeaderCategory.H3

    def test_pass_tier(self):
        f = build_h3_001_pass(early_data_capability=16384)
        assert f.severity == Severity.PASS
        assert f.category == HeaderCategory.H3


class TestH3002Diff:
    def test_missing_in_h3_only_is_medium(self):
        d = HeaderDiffResult(
            missing_in_h3=["Strict-Transport-Security"],
            missing_in_h1=[],
            value_drift=[],
        )
        f = build_h3_002_finding(d)
        assert f.severity == Severity.MEDIUM
        assert "Strict-Transport-Security" in f.description
        assert "Missing on HTTP/3" in f.description

    def test_value_drift_only_is_medium(self):
        d = HeaderDiffResult(
            missing_in_h3=[],
            missing_in_h1=[],
            value_drift=[("X-Frame-Options", "DENY", "SAMEORIGIN")],
        )
        f = build_h3_002_finding(d)
        assert f.severity == Severity.MEDIUM
        assert "X-Frame-Options" in f.description
        assert "DENY" in f.description and "SAMEORIGIN" in f.description

    def test_missing_in_h1_only_is_low(self):
        d = HeaderDiffResult(
            missing_in_h3=[],
            missing_in_h1=["Cross-Origin-Opener-Policy"],
            value_drift=[],
        )
        f = build_h3_002_finding(d)
        assert f.severity == Severity.LOW

    def test_combined_drift_modes_use_max_severity(self):
        d = HeaderDiffResult(
            missing_in_h3=["Strict-Transport-Security"],
            missing_in_h1=["Cross-Origin-Opener-Policy"],
            value_drift=[("X-Frame-Options", "DENY", "SAMEORIGIN")],
        )
        f = build_h3_002_finding(d)
        assert f.severity == Severity.MEDIUM  # MEDIUM > LOW

    def test_pass_when_no_drift(self):
        f = build_h3_002_pass()
        assert f.severity == Severity.PASS
        assert f.category == HeaderCategory.H3


class TestH3003LSQUIC:
    def test_critical_severity(self):
        f = build_h3_003_finding()
        assert f.severity == Severity.CRITICAL
        assert f.category == HeaderCategory.H3
        assert "CVE-2025-54939" in f.description or "LSQUIC" in f.title


class TestAuxiliaryFindings:
    def test_inconclusive_carries_error_in_current_value(self):
        f = build_h3_inconclusive_finding(error="timeout after 10s")
        assert f.severity == Severity.INFO
        assert "timeout after 10s" in (f.current_value or "")

    def test_extras_missing_finding(self):
        f = build_h3_extras_missing_finding()
        assert f.severity == Severity.INFO
        assert "[h3]" in f.description or "pip install" in f.description


class TestComplianceMappings:
    def test_h3_001_compliance(self):
        f = build_h3_001_high(early_data_capability=16384, status=200)
        framework_ids = {(c.framework, c.requirement_id) for c in f.compliance_mappings}
        assert ("OWASP_TOP_10_2021", "A07") in framework_ids

    def test_h3_002_compliance(self):
        d = HeaderDiffResult(missing_in_h3=["Strict-Transport-Security"])
        f = build_h3_002_finding(d)
        framework_ids = {(c.framework, c.requirement_id) for c in f.compliance_mappings}
        assert ("OWASP_TOP_10_2021", "A05") in framework_ids
        assert ("PCI_DSS_4_0", "6.4.3") in framework_ids

    def test_h3_003_compliance(self):
        f = build_h3_003_finding()
        framework_ids = {(c.framework, c.requirement_id) for c in f.compliance_mappings}
        assert ("OWASP_TOP_10_2021", "A06") in framework_ids
