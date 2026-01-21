"""
Additional security headers analyzer.

Covers deprecated and informational headers.
"""

from typing import List
import logging

from .base import BaseAnalyzer
from ..models import Finding, Severity, HeaderCategory

logger = logging.getLogger(__name__)


class AdditionalHeadersAnalyzer(BaseAnalyzer):
    """Analyzer for additional security headers."""

    HEADER_NAME = "Various"
    CATEGORY = HeaderCategory.DEPRECATED

    def analyze(self) -> List[Finding]:
        """Analyze additional headers."""
        findings = []

        # X-XSS-Protection (deprecated but still used)
        xss = self.get_header("X-XSS-Protection")
        if xss:
            if xss.strip() == "1; mode=block":
                findings.append(Finding(
                    header="X-XSS-Protection",
                    category=HeaderCategory.LEGACY,
                    severity=Severity.INFO,
                    title="X-XSS-Protection Set (Deprecated)",
                    description=(
                        "The X-XSS-Protection header is set to '1; mode=block'. "
                        "This header is deprecated and the XSS filter has been removed from "
                        "modern browsers. Use Content-Security-Policy instead."
                    ),
                    current_value=xss,
                    recommendation="Remove and rely on CSP for XSS protection.",
                    example_value="N/A (header should be removed)",
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
                ))
            elif xss.strip() == "0":
                # Explicitly disabled - fine
                pass

        # Server header (information disclosure)
        server = self.get_header("Server")
        if server:
            # Check if it reveals version info
            import re
            if re.search(r'[\d.]+', server):
                findings.append(Finding(
                    header="Server",
                    category=HeaderCategory.LEGACY,
                    severity=Severity.LOW,
                    title="Server Header Reveals Version Information",
                    description=(
                        f"The Server header '{server}' reveals version information. "
                        "This information can help attackers identify vulnerable versions."
                    ),
                    current_value=server,
                    recommendation="Configure server to not reveal version numbers.",
                    example_value="Server: nginx",
                    reference_url="https://owasp.org/www-project-secure-headers/"
                ))

        # X-Powered-By (information disclosure)
        powered_by = self.get_header("X-Powered-By")
        if powered_by:
            findings.append(Finding(
                header="X-Powered-By",
                category=HeaderCategory.LEGACY,
                severity=Severity.LOW,
                title="X-Powered-By Header Present",
                description=(
                    f"The X-Powered-By header reveals '{powered_by}'. "
                    "This discloses technology stack information to attackers."
                ),
                current_value=powered_by,
                recommendation="Remove the X-Powered-By header.",
                example_value="N/A (header should be removed)",
                reference_url="https://owasp.org/www-project-secure-headers/"
            ))

        return findings

