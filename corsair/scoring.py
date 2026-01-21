"""
Security score calculation.

Calculates a 0-100 score based on findings and determines a letter grade.
"""

from typing import List
import logging

from .models import Finding, Severity

logger = logging.getLogger(__name__)

# Severity deductions from base score of 100
SEVERITY_DEDUCTIONS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 0,
    Severity.PASS: 0,
}

# Grade thresholds
GRADES = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
]


def calculate_score(findings: List[Finding]) -> int:
    """
    Calculate security score from findings.

    Starts at 100 and deducts points based on severity:
    - CRITICAL: -25 points
    - HIGH: -15 points
    - MEDIUM: -10 points
    - LOW: -5 points
    - INFO/PASS: 0 points

    Minimum score is 0.

    Args:
        findings: List of Finding objects

    Returns:
        Score from 0-100
    """
    score = 100

    for finding in findings:
        deduction = SEVERITY_DEDUCTIONS.get(finding.severity, 0)
        score -= deduction

        if deduction > 0:
            logger.debug(
                f"Score deduction: -{deduction} for {finding.severity.value} " f"({finding.header})"
            )

    # Clamp to 0-100
    score = max(0, min(100, score))

    logger.info(f"Final score: {score}/100")
    return score


def calculate_grade(score: int) -> str:
    """
    Calculate letter grade from score.

    A: 90-100
    B: 80-89
    C: 70-79
    D: 60-69
    F: 0-59

    Args:
        score: Score from 0-100

    Returns:
        Letter grade (A, B, C, D, or F)
    """
    for threshold, grade in GRADES:
        if score >= threshold:
            return grade
    return "F"
