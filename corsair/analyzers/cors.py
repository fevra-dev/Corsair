"""
CORS headers analyzer.

Cross-Origin Resource Sharing headers control which origins can access resources.
Misconfigured CORS can expose sensitive data to unauthorized origins.
"""

from typing import List
import logging

from .base import BaseAnalyzer
from ..models import Finding, Severity, HeaderCategory

logger = logging.getLogger(__name__)


class CORSAnalyzer(BaseAnalyzer):
    """Analyzer for CORS headers."""

    HEADER_NAME = "Access-Control-Allow-Origin"
    CATEGORY = HeaderCategory.CORS

    MDN_URL = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"

    def analyze(self) -> List[Finding]:
        """Analyze CORS headers."""
        findings = []

        acao = self.get_header("Access-Control-Allow-Origin")
        acac = self.get_header("Access-Control-Allow-Credentials")

        # No CORS headers is fine (default same-origin policy)
        if not acao:
            logger.info(f"[CORS] No CORS headers (using same-origin policy)")
            findings.append(
                self.create_finding(
                    severity=Severity.PASS,
                    title="CORS Not Configured (Same-Origin Policy)",
                    description="No CORS headers are set. Same-origin policy is in effect.",
                    recommendation="No action needed unless cross-origin access is required.",
                    example_value="N/A",
                    reference_url=self.MDN_URL,
                )
            )
            return findings

        logger.info(f"[CORS] Access-Control-Allow-Origin: {acao}")

        # Check for wildcard
        if acao.strip() == "*":
            if acac and acac.lower() == "true":
                # Wildcard with credentials is actually invalid and browsers reject it
                findings.append(
                    self.create_finding(
                        severity=Severity.HIGH,
                        title="CORS Wildcard with Credentials",
                        description=(
                            "Access-Control-Allow-Origin is set to '*' while "
                            "Access-Control-Allow-Credentials is 'true'. "
                            "This is actually invalid - browsers will reject the response. "
                            "However, the intent suggests a security misconfiguration."
                        ),
                        current_value=f"ACAO: {acao}, ACAC: {acac}",
                        recommendation="Use a specific origin instead of wildcard when credentials are needed.",
                        example_value="Access-Control-Allow-Origin: https://trusted.example.com",
                        reference_url=self.MDN_URL,
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        severity=Severity.MEDIUM,
                        title="CORS Allows All Origins",
                        description=(
                            "Access-Control-Allow-Origin is set to '*', allowing any origin "
                            "to access resources. This may be intentional for public APIs, "
                            "but ensure no sensitive data is exposed."
                        ),
                        current_value=acao,
                        recommendation="If not a public API, restrict to specific origins.",
                        example_value="Access-Control-Allow-Origin: https://trusted.example.com",
                        reference_url=self.MDN_URL,
                    )
                )

        # Check for null origin (can be exploited)
        elif acao.lower().strip() == "null":
            findings.append(
                self.create_finding(
                    severity=Severity.HIGH,
                    title="CORS Allows Null Origin",
                    description=(
                        "Access-Control-Allow-Origin is set to 'null'. "
                        "The null origin can be sent from sandboxed iframes and data: URLs, "
                        "which can be controlled by attackers."
                    ),
                    current_value=acao,
                    recommendation="Never allow the null origin.",
                    example_value="Access-Control-Allow-Origin: https://trusted.example.com",
                    reference_url=self.MDN_URL,
                )
            )
        else:
            # Specific origin - generally good
            findings.append(self.create_pass_finding(acao))

        return findings
