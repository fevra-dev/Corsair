"""Test scoring system."""

import pytest
from corsair.scoring import calculate_score, calculate_grade
from corsair.models import Finding, Severity, HeaderCategory


def make_finding(severity: Severity) -> Finding:
    return Finding(
        header="Test",
        category=HeaderCategory.CONTENT,
        severity=severity,
        title="Test",
        description="Test",
        current_value=None,
        recommendation="Test",
        example_value="Test",
        reference_url=""
    )


class TestScoring:
    def test_perfect_score_with_no_findings(self):
        assert calculate_score([]) == 100

    def test_critical_deducts_25(self):
        findings = [make_finding(Severity.CRITICAL)]
        assert calculate_score(findings) == 75

    def test_multiple_findings_stack(self):
        findings = [
            make_finding(Severity.CRITICAL),  # -25
            make_finding(Severity.HIGH),      # -15
            make_finding(Severity.MEDIUM),    # -10
        ]
        assert calculate_score(findings) == 50

    def test_score_cannot_go_below_zero(self):
        findings = [make_finding(Severity.CRITICAL)] * 10
        assert calculate_score(findings) == 0

    def test_pass_findings_dont_deduct(self):
        findings = [make_finding(Severity.PASS)]
        assert calculate_score(findings) == 100


class TestGrading:
    def test_grade_a(self):
        assert calculate_grade(95) == "A"
        assert calculate_grade(90) == "A"

    def test_grade_b(self):
        assert calculate_grade(85) == "B"
        assert calculate_grade(80) == "B"

    def test_grade_f(self):
        assert calculate_grade(45) == "F"
        assert calculate_grade(0) == "F"

