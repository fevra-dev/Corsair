"""
Drift Detection Module.

Provides advanced drift detection and alerting capabilities.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

from ..models import TargetResult, Finding, Severity
from ..utils.logger import get_logger

logger = get_logger(__name__)


class DriftType(Enum):
    """Types of configuration drift."""

    SCORE_DROP = "score_drop"
    NEW_CRITICAL_ISSUE = "new_critical_issue"
    NEW_HIGH_ISSUE = "new_high_issue"
    HEADER_REMOVED = "header_removed"
    HEADER_WEAKENED = "header_weakened"
    REGRESSION = "regression"


@dataclass
class DriftAlert:
    """A drift detection alert."""

    drift_type: DriftType
    severity: str
    header: Optional[str]
    description: str
    previous_value: Optional[str]
    current_value: Optional[str]


class DriftDetector:
    """
    Detects configuration drift between scans.

    Usage:
        detector = DriftDetector()
        alerts = detector.detect(current_result, previous_result)

        for alert in alerts:
            print(f"{alert.severity}: {alert.description}")
    """

    # Score drop thresholds
    CRITICAL_SCORE_DROP = 20
    HIGH_SCORE_DROP = 10

    def __init__(self):
        """Initialize drift detector."""
        logger.info("[DriftDetector] Initialized")

    def detect(self, current: TargetResult, previous: TargetResult) -> List[DriftAlert]:
        """
        Detect drift between two scan results.

        Args:
            current: Current scan result
            previous: Previous scan result

        Returns:
            List of DriftAlert objects
        """
        alerts = []

        # Check score drift
        alerts.extend(self._check_score_drift(current, previous))

        # Check for new issues
        alerts.extend(self._check_new_issues(current, previous))

        # Check for removed headers
        alerts.extend(self._check_removed_headers(current, previous))

        # Check for weakened headers
        alerts.extend(self._check_weakened_headers(current, previous))

        # Check for regressions (previously fixed issues returning)
        alerts.extend(self._check_regressions(current, previous))

        logger.info(f"[DriftDetector] Detected {len(alerts)} drift alerts")

        return alerts

    def _check_score_drift(self, current: TargetResult, previous: TargetResult) -> List[DriftAlert]:
        """Check for significant score drops."""
        alerts = []
        delta = current.score - previous.score

        if delta <= -self.CRITICAL_SCORE_DROP:
            alerts.append(
                DriftAlert(
                    drift_type=DriftType.SCORE_DROP,
                    severity="CRITICAL",
                    header=None,
                    description=f"Score dropped by {abs(delta)} points (from {previous.score} to {current.score})",
                    previous_value=str(previous.score),
                    current_value=str(current.score),
                )
            )
        elif delta <= -self.HIGH_SCORE_DROP:
            alerts.append(
                DriftAlert(
                    drift_type=DriftType.SCORE_DROP,
                    severity="HIGH",
                    header=None,
                    description=f"Score dropped by {abs(delta)} points (from {previous.score} to {current.score})",
                    previous_value=str(previous.score),
                    current_value=str(current.score),
                )
            )

        return alerts

    def _check_new_issues(self, current: TargetResult, previous: TargetResult) -> List[DriftAlert]:
        """Check for new critical/high issues."""
        alerts = []

        # Get issue titles by severity
        current_critical = {f.title for f in current.findings if f.severity == Severity.CRITICAL}
        current_high = {f.title for f in current.findings if f.severity == Severity.HIGH}

        previous_critical = {f.title for f in previous.findings if f.severity == Severity.CRITICAL}
        previous_high = {f.title for f in previous.findings if f.severity == Severity.HIGH}

        # New critical issues
        new_critical = current_critical - previous_critical
        for issue in new_critical:
            alerts.append(
                DriftAlert(
                    drift_type=DriftType.NEW_CRITICAL_ISSUE,
                    severity="CRITICAL",
                    header=self._find_header_for_issue(current.findings, issue),
                    description=f"New critical issue: {issue}",
                    previous_value=None,
                    current_value=issue,
                )
            )

        # New high issues
        new_high = current_high - previous_high
        for issue in new_high:
            alerts.append(
                DriftAlert(
                    drift_type=DriftType.NEW_HIGH_ISSUE,
                    severity="HIGH",
                    header=self._find_header_for_issue(current.findings, issue),
                    description=f"New high issue: {issue}",
                    previous_value=None,
                    current_value=issue,
                )
            )

        return alerts

    def _check_removed_headers(
        self, current: TargetResult, previous: TargetResult
    ) -> List[DriftAlert]:
        """Check for security headers that were removed."""
        alerts = []

        important_headers = {
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "cross-origin-opener-policy",
            "cross-origin-embedder-policy",
        }

        prev_headers = {k.lower() for k in previous.headers.keys()}
        curr_headers = {k.lower() for k in current.headers.keys()}

        removed = (prev_headers & important_headers) - curr_headers

        for header in removed:
            alerts.append(
                DriftAlert(
                    drift_type=DriftType.HEADER_REMOVED,
                    severity="HIGH",
                    header=header,
                    description=f"Security header removed: {header}",
                    previous_value=previous.headers.get(header, ""),
                    current_value=None,
                )
            )

        return alerts

    def _check_weakened_headers(
        self, current: TargetResult, previous: TargetResult
    ) -> List[DriftAlert]:
        """Check for headers that were weakened."""
        alerts = []

        # HSTS max-age reduction
        prev_hsts = previous.headers.get("Strict-Transport-Security", "")
        curr_hsts = current.headers.get("Strict-Transport-Security", "")

        if prev_hsts and curr_hsts:
            prev_maxage = self._extract_max_age(prev_hsts)
            curr_maxage = self._extract_max_age(curr_hsts)

            if curr_maxage is not None and prev_maxage is not None:
                if curr_maxage < prev_maxage:
                    alerts.append(
                        DriftAlert(
                            drift_type=DriftType.HEADER_WEAKENED,
                            severity="MEDIUM",
                            header="Strict-Transport-Security",
                            description=f"HSTS max-age reduced from {prev_maxage} to {curr_maxage}",
                            previous_value=prev_hsts,
                            current_value=curr_hsts,
                        )
                    )

        # CSP weakening (added unsafe-inline or unsafe-eval)
        prev_csp = previous.headers.get("Content-Security-Policy", "")
        curr_csp = current.headers.get("Content-Security-Policy", "")

        if prev_csp and curr_csp:
            dangerous = ["'unsafe-inline'", "'unsafe-eval'", "*"]
            for d in dangerous:
                if d in curr_csp and d not in prev_csp:
                    alerts.append(
                        DriftAlert(
                            drift_type=DriftType.HEADER_WEAKENED,
                            severity="HIGH",
                            header="Content-Security-Policy",
                            description=f"CSP weakened: {d} was added",
                            previous_value=prev_csp[:100],
                            current_value=curr_csp[:100],
                        )
                    )

        return alerts

    def _check_regressions(self, current: TargetResult, previous: TargetResult) -> List[DriftAlert]:
        """Check for issues that were fixed but have returned."""
        alerts = []

        # Get PASS findings from previous (were working)
        prev_passing = {f.header for f in previous.findings if f.severity == Severity.PASS}

        # Get failing findings from current
        curr_failing = {
            f.header: f
            for f in current.findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
        }

        # Regressions = headers that were passing but now failing
        regressions = prev_passing & set(curr_failing.keys())

        for header in regressions:
            finding = curr_failing[header]
            alerts.append(
                DriftAlert(
                    drift_type=DriftType.REGRESSION,
                    severity="HIGH",
                    header=header,
                    description=f"Regression: {header} was fixed but issue returned ({finding.title})",
                    previous_value="PASS",
                    current_value=finding.severity.value,
                )
            )

        return alerts

    def _find_header_for_issue(self, findings: List[Finding], issue_title: str) -> Optional[str]:
        """Find the header associated with an issue title."""
        for f in findings:
            if f.title == issue_title:
                return f.header
        return None

    def _extract_max_age(self, hsts: str) -> Optional[int]:
        """Extract max-age value from HSTS header."""
        import re

        match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return None
