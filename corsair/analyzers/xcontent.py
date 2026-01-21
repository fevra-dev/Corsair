"""
X-Content-Type-Options analyzer.

Prevents MIME-type sniffing attacks by forcing browsers to respect
the declared Content-Type header.
"""

from typing import List
import logging

from .base import BaseAnalyzer
from ..models import Finding, Severity, HeaderCategory

logger = logging.getLogger(__name__)


class XContentTypeOptionsAnalyzer(BaseAnalyzer):
    """Analyzer for X-Content-Type-Options header."""

    HEADER_NAME = "X-Content-Type-Options"
    CATEGORY = HeaderCategory.CONTENT

    MDN_URL = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"

    def analyze(self) -> List[Finding]:
        """Analyze X-Content-Type-Options header."""
        findings = []

        value = self.get_header("X-Content-Type-Options")

        if not value:
            logger.info(f"[X-Content-Type-Options] Missing: {self.url}")
            findings.append(
                self.create_finding(
                    severity=Severity.MEDIUM,
                    title="X-Content-Type-Options Missing",
                    description=(
                        "The X-Content-Type-Options header is not set. "
                        "Browsers may perform MIME-type sniffing, which can lead to "
                        "security vulnerabilities where files are interpreted incorrectly."
                    ),
                    recommendation="Add X-Content-Type-Options: nosniff",
                    example_value="nosniff",
                    reference_url=self.MDN_URL,
                )
            )
            return findings

        if value.lower().strip() != "nosniff":
            findings.append(
                self.create_finding(
                    severity=Severity.MEDIUM,
                    title="X-Content-Type-Options Invalid Value",
                    description=(
                        f"The value '{value}' is not valid. "
                        "The only valid value for this header is 'nosniff'."
                    ),
                    current_value=value,
                    recommendation="Set value to 'nosniff'.",
                    example_value="nosniff",
                    reference_url=self.MDN_URL,
                )
            )
        else:
            findings.append(self.create_pass_finding(value))

        return findings
