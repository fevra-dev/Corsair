"""
Strict-Transport-Security (HSTS) analyzer.

HSTS forces browsers to use HTTPS for all future requests.
This prevents protocol downgrade attacks and cookie hijacking.
"""

from typing import List, Optional
import re
import logging

from .base import BaseAnalyzer
from ..models import Finding, Severity, HeaderCategory

logger = logging.getLogger(__name__)


class HSTSAnalyzer(BaseAnalyzer):
    """Analyzer for Strict-Transport-Security header."""

    HEADER_NAME = "Strict-Transport-Security"
    CATEGORY = HeaderCategory.TRANSPORT

    # HSTS Preload requirements: https://hstspreload.org/
    MIN_MAX_AGE = 31536000  # 1 year in seconds
    RECOMMENDED_MAX_AGE = 63072000  # 2 years

    MDN_URL = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"

    def analyze(self) -> List[Finding]:
        """Analyze HSTS header."""
        findings = []

        hsts_value = self.get_header("Strict-Transport-Security")

        # Check if the URL is HTTPS
        is_https = self.url.lower().startswith("https://")

        if not hsts_value:
            if is_https:
                logger.info(f"[HSTS] Missing on HTTPS site: {self.url}")
                findings.append(self.create_finding(
                    severity=Severity.CRITICAL,
                    title="Strict-Transport-Security Missing",
                    description=(
                        "The HSTS header is not set on this HTTPS site. "
                        "Without HSTS, users can be downgraded to HTTP via "
                        "man-in-the-middle attacks, exposing sensitive data."
                    ),
                    recommendation="Add HSTS header with at least 1 year max-age.",
                    example_value="max-age=31536000; includeSubDomains; preload",
                    reference_url=self.MDN_URL
                ))
            else:
                logger.info(f"[HSTS] Site is not HTTPS: {self.url}")
                findings.append(self.create_finding(
                    severity=Severity.CRITICAL,
                    title="Site Not Using HTTPS",
                    description=(
                        "This site is served over HTTP, not HTTPS. "
                        "All traffic is unencrypted and vulnerable to interception. "
                        "HSTS cannot be used without HTTPS."
                    ),
                    recommendation="Migrate to HTTPS and add HSTS header.",
                    example_value="max-age=31536000; includeSubDomains",
                    reference_url=self.MDN_URL
                ))
            return findings

        logger.info(f"[HSTS] Analyzing: {hsts_value}")

        # Parse HSTS directives
        max_age = self._extract_max_age(hsts_value)
        has_include_subdomains = "includesubdomains" in hsts_value.lower()
        has_preload = "preload" in hsts_value.lower()

        # Check max-age value
        if max_age is None:
            findings.append(self.create_finding(
                severity=Severity.HIGH,
                title="HSTS missing max-age",
                description="The HSTS header does not include a valid max-age directive.",
                current_value=hsts_value,
                recommendation="Add max-age directive with at least 31536000 (1 year).",
                example_value="max-age=31536000; includeSubDomains",
                reference_url=self.MDN_URL
            ))
        elif max_age < self.MIN_MAX_AGE:
            logger.warning(f"[HSTS] max-age too short: {max_age}")
            findings.append(self.create_finding(
                severity=Severity.MEDIUM,
                title="HSTS max-age Too Short",
                description=(
                    f"The HSTS max-age is {max_age} seconds ({max_age // 86400} days). "
                    f"For HSTS preload eligibility, minimum is {self.MIN_MAX_AGE} seconds (1 year). "
                    "Shorter values provide less protection."
                ),
                current_value=hsts_value,
                recommendation="Increase max-age to at least 31536000 (1 year).",
                example_value="max-age=31536000; includeSubDomains",
                reference_url=self.MDN_URL
            ))

        # Check includeSubDomains
        if not has_include_subdomains:
            findings.append(self.create_finding(
                severity=Severity.LOW,
                title="HSTS missing includeSubDomains",
                description=(
                    "The includeSubDomains directive is not set. "
                    "Subdomains can still be accessed over HTTP, which may "
                    "be used in attacks against the main domain."
                ),
                current_value=hsts_value,
                recommendation="Add includeSubDomains directive.",
                example_value="max-age=31536000; includeSubDomains",
                reference_url=self.MDN_URL
            ))

        # Informational: preload status
        if not has_preload and max_age and max_age >= self.MIN_MAX_AGE and has_include_subdomains:
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="HSTS Preload Not Enabled",
                description=(
                    "The preload directive is not set. Your site meets the requirements "
                    "for HSTS preloading. Consider submitting to hstspreload.org for "
                    "inclusion in browser preload lists."
                ),
                current_value=hsts_value,
                recommendation="Add preload directive and submit to hstspreload.org",
                example_value="max-age=31536000; includeSubDomains; preload",
                reference_url="https://hstspreload.org/"
            ))

        # If no issues, mark as PASS
        if not findings:
            findings.append(self.create_pass_finding(hsts_value))

        return findings

    def _extract_max_age(self, hsts: str) -> Optional[int]:
        """Extract max-age value from HSTS header."""
        match = re.search(r'max-age\s*=\s*(\d+)', hsts, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return None

