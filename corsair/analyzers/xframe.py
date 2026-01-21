"""
X-Frame-Options analyzer.

Prevents clickjacking by controlling whether the page can be embedded in frames.
Note: This is being superseded by CSP frame-ancestors, but still widely used.
"""

from typing import List
import logging

from .base import BaseAnalyzer
from ..models import Finding, Severity, HeaderCategory

logger = logging.getLogger(__name__)


class XFrameOptionsAnalyzer(BaseAnalyzer):
    """Analyzer for X-Frame-Options header."""

    HEADER_NAME = "X-Frame-Options"
    CATEGORY = HeaderCategory.FRAMING

    VALID_VALUES = ["DENY", "SAMEORIGIN"]

    MDN_URL = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"

    def analyze(self) -> List[Finding]:
        """Analyze X-Frame-Options header."""
        findings = []

        xfo_value = self.get_header("X-Frame-Options")

        # Check CSP frame-ancestors as alternative
        csp = self.get_header("Content-Security-Policy")
        has_frame_ancestors = csp and "frame-ancestors" in csp.lower()

        if not xfo_value:
            if has_frame_ancestors:
                # CSP frame-ancestors provides equivalent protection
                logger.info(f"[X-Frame-Options] Missing but frame-ancestors present")
                findings.append(
                    self.create_finding(
                        severity=Severity.INFO,
                        title="X-Frame-Options Missing (CSP Alternative Present)",
                        description=(
                            "X-Frame-Options header is not set, but CSP frame-ancestors "
                            "is configured. Modern browsers support frame-ancestors, but "
                            "X-Frame-Options provides compatibility with older browsers."
                        ),
                        recommendation="Consider adding X-Frame-Options for legacy browser support.",
                        example_value="DENY",
                        reference_url=self.MDN_URL,
                    )
                )
            else:
                logger.info(f"[X-Frame-Options] Missing: {self.url}")
                findings.append(
                    self.create_finding(
                        severity=Severity.HIGH,
                        title="X-Frame-Options Missing",
                        description=(
                            "The X-Frame-Options header is not set and CSP frame-ancestors "
                            "is also missing. The page can be embedded in frames on any site, "
                            "making it vulnerable to clickjacking attacks."
                        ),
                        recommendation="Add X-Frame-Options: DENY or use CSP frame-ancestors.",
                        example_value="DENY",
                        reference_url=self.MDN_URL,
                    )
                )
            return findings

        logger.info(f"[X-Frame-Options] Value: {xfo_value}")

        # Check for valid values
        xfo_upper = xfo_value.upper().strip()

        if xfo_upper not in self.VALID_VALUES and not xfo_upper.startswith("ALLOW-FROM"):
            findings.append(
                self.create_finding(
                    severity=Severity.MEDIUM,
                    title="X-Frame-Options Invalid Value",
                    description=(
                        f"The value '{xfo_value}' is not a valid X-Frame-Options value. "
                        f"Valid values are: DENY, SAMEORIGIN."
                    ),
                    current_value=xfo_value,
                    recommendation="Use DENY or SAMEORIGIN.",
                    example_value="DENY",
                    reference_url=self.MDN_URL,
                )
            )
        elif xfo_upper.startswith("ALLOW-FROM"):
            # ALLOW-FROM is deprecated and not supported by modern browsers
            findings.append(
                self.create_finding(
                    severity=Severity.MEDIUM,
                    title="X-Frame-Options Uses Deprecated ALLOW-FROM",
                    description=(
                        "ALLOW-FROM is deprecated and not supported by Chrome or Safari. "
                        "It only works in older versions of Firefox and IE. "
                        "Use CSP frame-ancestors instead."
                    ),
                    current_value=xfo_value,
                    recommendation="Use CSP frame-ancestors for origin-specific framing control.",
                    example_value="Content-Security-Policy: frame-ancestors 'self' https://trusted.com",
                    reference_url=self.MDN_URL,
                )
            )
        else:
            # Valid value - PASS
            findings.append(self.create_pass_finding(xfo_value))

        return findings
