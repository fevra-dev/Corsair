"""
Referrer-Policy analyzer.

Controls how much referrer information is included with requests.
Helps prevent information leakage.
"""

from typing import List
import logging

from .base import BaseAnalyzer
from ..models import Finding, Severity, HeaderCategory

logger = logging.getLogger(__name__)


class ReferrerPolicyAnalyzer(BaseAnalyzer):
    """Analyzer for Referrer-Policy header."""

    HEADER_NAME = "Referrer-Policy"
    CATEGORY = HeaderCategory.PRIVACY

    # From most to least restrictive
    SAFE_VALUES = [
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    ]

    UNSAFE_VALUES = [
        "unsafe-url",  # Sends full URL including path and query
        "no-referrer-when-downgrade",  # Default, not explicit
    ]

    MDN_URL = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"

    def analyze(self) -> List[Finding]:
        """Analyze Referrer-Policy header."""
        findings = []

        value = self.get_header("Referrer-Policy")

        if not value:
            logger.info(f"[Referrer-Policy] Missing: {self.url}")
            findings.append(self.create_finding(
                severity=Severity.LOW,
                title="Referrer-Policy Missing",
                description=(
                    "The Referrer-Policy header is not set. "
                    "Browsers will use the default policy (typically 'strict-origin-when-cross-origin' "
                    "in modern browsers), but explicitly setting this header ensures consistent behavior."
                ),
                recommendation="Add Referrer-Policy header.",
                example_value="strict-origin-when-cross-origin",
                reference_url=self.MDN_URL
            ))
            return findings

        logger.info(f"[Referrer-Policy] Value: {value}")

        # Parse multiple values (comma or space separated)
        values = [v.strip().lower() for v in value.replace(",", " ").split()]

        # Check for unsafe values
        for v in values:
            if v == "unsafe-url":
                findings.append(self.create_finding(
                    severity=Severity.MEDIUM,
                    title="Referrer-Policy Uses unsafe-url",
                    description=(
                        "The policy 'unsafe-url' sends the full URL (including path and query string) "
                        "as the referrer. This can leak sensitive information in URLs to third parties."
                    ),
                    current_value=value,
                    recommendation="Use 'strict-origin-when-cross-origin' or more restrictive.",
                    example_value="strict-origin-when-cross-origin",
                    reference_url=self.MDN_URL
                ))
            elif v == "origin-when-cross-origin":
                findings.append(self.create_finding(
                    severity=Severity.LOW,
                    title="Referrer-Policy Could Be More Restrictive",
                    description=(
                        "The policy 'origin-when-cross-origin' sends the origin for cross-origin requests. "
                        "Consider 'strict-origin-when-cross-origin' which also requires HTTPS."
                    ),
                    current_value=value,
                    recommendation="Consider using 'strict-origin-when-cross-origin'.",
                    example_value="strict-origin-when-cross-origin",
                    reference_url=self.MDN_URL
                ))

        # If no issues found
        if not findings:
            findings.append(self.create_pass_finding(value))

        return findings

