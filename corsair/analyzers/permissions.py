"""
Permissions-Policy analyzer (formerly Feature-Policy).

Controls which browser features can be used by the page and embedded content.
"""

from typing import List
import logging

from .base import BaseAnalyzer
from ..models import Finding, Severity, HeaderCategory

logger = logging.getLogger(__name__)


class PermissionsPolicyAnalyzer(BaseAnalyzer):
    """Analyzer for Permissions-Policy header."""

    HEADER_NAME = "Permissions-Policy"
    CATEGORY = HeaderCategory.PERMISSIONS

    # High-risk features that should typically be restricted
    SENSITIVE_FEATURES = [
        "geolocation",
        "microphone",
        "camera",
        "payment",
        "usb",
        "accelerometer",
        "gyroscope",
        "magnetometer",
    ]

    MDN_URL = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"

    def analyze(self) -> List[Finding]:
        """Analyze Permissions-Policy header."""
        findings = []

        # Check both new and old header names
        value = self.get_header("Permissions-Policy")
        feature_policy = self.get_header("Feature-Policy")

        if not value:
            if feature_policy:
                # Old header present
                findings.append(self.create_finding(
                    severity=Severity.LOW,
                    title="Using Deprecated Feature-Policy",
                    description=(
                        "The site uses the deprecated Feature-Policy header. "
                        "Modern browsers support Permissions-Policy instead."
                    ),
                    current_value=feature_policy,
                    recommendation="Migrate to Permissions-Policy header.",
                    example_value='geolocation=(), microphone=(), camera=()',
                    reference_url=self.MDN_URL
                ))
            else:
                logger.info(f"[Permissions-Policy] Missing: {self.url}")
                findings.append(self.create_finding(
                    severity=Severity.LOW,
                    title="Permissions-Policy Missing",
                    description=(
                        "The Permissions-Policy header is not set. "
                        "This header allows you to control which browser features "
                        "can be used by the page and embedded content. "
                        "Without it, all features may be available to embedded iframes."
                    ),
                    recommendation="Add Permissions-Policy to restrict sensitive features.",
                    example_value='geolocation=(), microphone=(), camera=(), payment=()',
                    reference_url=self.MDN_URL
                ))
            return findings

        logger.info(f"[Permissions-Policy] Value: {value}")

        # Check if sensitive features are unrestricted
        value_lower = value.lower()
        unrestricted = []

        for feature in self.SENSITIVE_FEATURES:
            # Check if feature is set to * (allow all)
            if f"{feature}=*" in value_lower:
                unrestricted.append(feature)

        if unrestricted:
            findings.append(self.create_finding(
                severity=Severity.MEDIUM,
                title="Sensitive Features Unrestricted",
                description=(
                    f"The following sensitive features are allowed for all origins: "
                    f"{', '.join(unrestricted)}. "
                    "Consider restricting these to 'self' or specific origins."
                ),
                current_value=value,
                recommendation="Restrict sensitive features to specific origins.",
                example_value='geolocation=(self), camera=(self)',
                reference_url=self.MDN_URL
            ))
        else:
            findings.append(self.create_pass_finding(value))

        return findings

