"""
Content-Security-Policy analyzer.

CSP is one of the most important security headers. It prevents:
- Cross-Site Scripting (XSS)
- Data injection attacks
- Clickjacking (with frame-ancestors)
"""

from typing import List, Optional
import re
import logging

from .base import BaseAnalyzer
from ..models import Finding, Severity, HeaderCategory

logger = logging.getLogger(__name__)


class CSPAnalyzer(BaseAnalyzer):
    """Analyzer for Content-Security-Policy header."""

    HEADER_NAME = "Content-Security-Policy"
    CATEGORY = HeaderCategory.CONTENT

    # Dangerous CSP sources
    DANGEROUS_SOURCES = [
        ("'unsafe-inline'", "Allows inline scripts/styles, defeats XSS protection"),
        ("'unsafe-eval'", "Allows eval(), new Function(), enables code injection"),
        ("data:", "Allows data: URIs, can be used for XSS"),
        ("blob:", "Allows blob: URIs, can be used for XSS"),
        ("*", "Wildcard allows any source"),
    ]

    # Directives where wildcards are especially dangerous
    SCRIPT_DIRECTIVES = ["script-src", "script-src-elem", "script-src-attr", "default-src"]

    MDN_URL = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"

    def analyze(self) -> List[Finding]:
        """Analyze CSP header."""
        findings = []

        csp_value = self.get_header("Content-Security-Policy")
        csp_ro = self.get_header("Content-Security-Policy-Report-Only")

        # Check if CSP is missing
        if not csp_value:
            logger.info(f"[CSP] Missing on {self.url}")

            severity = Severity.CRITICAL
            description = (
                "The Content-Security-Policy header is not set. "
                "Without CSP, the site is vulnerable to Cross-Site Scripting (XSS) "
                "and data injection attacks. CSP is a critical defense layer."
            )

            # Downgrade if report-only is present
            if csp_ro:
                severity = Severity.HIGH
                description += (
                    " Note: Content-Security-Policy-Report-Only is present, "
                    "but this does not enforce the policy."
                )

            findings.append(self.create_finding(
                severity=severity,
                title="Content-Security-Policy Missing",
                description=description,
                recommendation="Add a Content-Security-Policy header to protect against XSS.",
                example_value="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'self'",
                reference_url=self.MDN_URL
            ))
            return findings

        logger.info(f"[CSP] Analyzing policy: {csp_value[:100]}...")

        # Parse CSP directives
        directives = self._parse_csp(csp_value)

        # Check for dangerous sources
        for directive, sources in directives.items():
            for dangerous_source, reason in self.DANGEROUS_SOURCES:
                if dangerous_source in sources:
                    # Severity depends on directive
                    if directive in self.SCRIPT_DIRECTIVES:
                        severity = Severity.HIGH
                        title = f"Dangerous source in {directive}"
                    else:
                        severity = Severity.MEDIUM
                        title = f"Potentially dangerous source in {directive}"

                    logger.warning(f"[CSP] {title}: {dangerous_source}")

                    findings.append(self.create_finding(
                        severity=severity,
                        title=title,
                        description=f"The directive '{directive}' contains '{dangerous_source}'. {reason}",
                        current_value=csp_value,
                        recommendation=f"Remove '{dangerous_source}' from {directive} if possible.",
                        example_value=f"{directive} 'self'",
                        reference_url=self.MDN_URL
                    ))

        # Check if default-src is missing (policy should have a fallback)
        if "default-src" not in directives:
            findings.append(self.create_finding(
                severity=Severity.LOW,
                title="CSP missing default-src",
                description=(
                    "The CSP does not include a default-src directive. "
                    "This means any fetch directives not explicitly set will have no restrictions."
                ),
                current_value=csp_value,
                recommendation="Add a default-src directive as a fallback.",
                example_value="default-src 'self'",
                reference_url=self.MDN_URL
            ))

        # If no issues found, mark as PASS
        if not findings:
            findings.append(self.create_pass_finding(csp_value))

        return findings

    def _parse_csp(self, csp: str) -> dict:
        """
        Parse CSP header into directives.

        Returns:
            Dict mapping directive names to list of sources
        """
        directives = {}

        # Split by semicolon
        parts = [p.strip() for p in csp.split(";") if p.strip()]

        for part in parts:
            tokens = part.split()
            if not tokens:
                continue

            directive = tokens[0].lower()
            sources = [s.lower() for s in tokens[1:]]
            directives[directive] = sources

        return directives

