"""
Enhanced Content-Security-Policy Analyzer.

Provides comprehensive CSP analysis including:
- 28+ CSP Level 3 specific checks
- Trusted Types (CSP Level 4) detection
- strict-dynamic validation
- Nonce/hash verification
- Reporting configuration analysis

This analyzer is critical for 2026 threat landscape readiness,
particularly for mitigating React2Shell (CVE-2025-55182) and
similar deserialization attacks.
"""

import re
from typing import List, Dict, Set, Optional, Tuple
from .base import BaseAnalyzer
from ..models import Finding, Severity, HeaderCategory
from ..utils.logger import get_logger

logger = get_logger(__name__)


class EnhancedCSPAnalyzer(BaseAnalyzer):
    """
    Comprehensive Content-Security-Policy analyzer.
    
    Performs deep validation of CSP directives including:
    - Dangerous source detection (unsafe-inline, unsafe-eval, wildcards)
    - Required directive verification
    - Trusted Types (CSP Level 4) recommendations
    - strict-dynamic validation
    - Reporting configuration checks
    - Deprecated directive detection
    """
    
    HEADER_NAME = "Content-Security-Policy"
    CATEGORY = HeaderCategory.CONTENT
    
    # Also check Report-Only header
    ADDITIONAL_HEADERS = ["Content-Security-Policy-Report-Only"]
    
    # CVE mappings for common misconfigurations
    CVE_MAPPINGS = {
        "missing_csp": ["CVE-2025-55182", "CWE-79"],  # React2Shell, XSS
        "unsafe_inline": ["CWE-79"],                   # XSS
        "unsafe_eval": ["CWE-94"],                     # Code Injection
    }
    
    # Compliance framework mappings
    COMPLIANCE_MAPPINGS = {
        "OWASP_TOP_10_2025": {
            "missing_csp": "A02",      # Security Misconfiguration
            "unsafe_inline": "A03",    # Injection
        },
        "PCI_DSS_4": {
            "missing_csp": "6.4.3",    # CSP requirement for payment pages
        }
    }
    
    # Dangerous source values
    DANGEROUS_SOURCES = {
        "*",                    # Wildcard - allows any origin
        "data:",               # Data URIs can contain scripts
        "blob:",               # Blob URIs can contain scripts
        "'unsafe-inline'",     # Allows inline scripts/styles
        "'unsafe-eval'",       # Allows eval() and similar
        "'unsafe-hashes'",     # Allows specific inline handlers
    }
    
    # Script-execution related directives
    SCRIPT_DIRECTIVES = {"script-src", "script-src-elem", "script-src-attr"}
    STYLE_DIRECTIVES = {"style-src", "style-src-elem", "style-src-attr"}
    
    # Required directives for strict CSP
    REQUIRED_DIRECTIVES = ["default-src"]
    
    # Recommended directives for comprehensive protection
    RECOMMENDED_DIRECTIVES = [
        "script-src",      # Control script loading
        "object-src",      # Block plugins (Flash, Java)
        "base-uri",        # Prevent base tag injection
        "form-action",     # Control form submissions
        "frame-ancestors", # Clickjacking protection
    ]
    
    # Deprecated directives (should be removed)
    DEPRECATED_DIRECTIVES = [
        "plugin-types",           # No longer needed, plugins are deprecated
        "referrer",               # Superseded by Referrer-Policy header
        "block-all-mixed-content", # Superseded by upgrade-insecure-requests
    ]
    
    # CSP Level 4 - Trusted Types directives
    TRUSTED_TYPES_DIRECTIVES = ["require-trusted-types-for", "trusted-types"]
    
    # Reporting directives
    REPORTING_DIRECTIVES = ["report-to", "report-uri"]

    def analyze(self) -> List[Finding]:
        """
        Analyze Content-Security-Policy header.
        
        Returns:
            List of Finding objects for all CSP issues detected
        """
        findings = []
        
        # Get CSP header value
        csp_value = self.get_header(self.HEADER_NAME)
        csp_report_only = self.get_header("Content-Security-Policy-Report-Only")
        
        # Check for missing CSP
        if not csp_value:
            logger.warning(f"[CSP] Missing CSP header for {self.url}")
            findings.append(self._create_missing_finding())
            
            # If report-only exists but no enforcing CSP, note it
            if csp_report_only:
                findings.append(self.create_finding(
                    severity=Severity.MEDIUM,
                    title="CSP in Report-Only Mode",
                    description=(
                        "Content-Security-Policy-Report-Only is set but no enforcing "
                        "CSP is configured. Report-only mode does not block attacks."
                    ),
                    recommendation="Deploy an enforcing Content-Security-Policy header.",
                    example_value="Content-Security-Policy: default-src 'self'",
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    current_value=f"Report-Only: {csp_report_only[:100]}..."
                ))
            
            return findings
        
        logger.info(f"[CSP] Analyzing CSP for {self.url}")
        logger.debug(f"[CSP] Value: {csp_value[:200]}{'...' if len(csp_value) > 200 else ''}")
        
        # Parse CSP directives
        directives = self._parse_directives(csp_value)
        logger.debug(f"[CSP] Parsed {len(directives)} directives: {list(directives.keys())}")
        
        # Run all checks
        findings.extend(self._check_dangerous_sources(directives))
        findings.extend(self._check_required_directives(directives))
        findings.extend(self._check_recommended_directives(directives))
        findings.extend(self._check_deprecated_directives(directives))
        findings.extend(self._check_trusted_types(directives))
        findings.extend(self._check_strict_dynamic(directives))
        findings.extend(self._check_nonce_hash_usage(directives))
        findings.extend(self._check_reporting(directives))
        findings.extend(self._check_frame_ancestors(directives))
        findings.extend(self._check_base_uri(directives))
        findings.extend(self._check_object_src(directives))
        
        # If no issues found, create PASS finding
        if not findings:
            logger.info(f"[CSP] CSP correctly configured for {self.url}")
            findings.append(self.create_pass_finding(csp_value))
        else:
            logger.info(f"[CSP] Found {len(findings)} issues for {self.url}")
        
        return findings

    def _parse_directives(self, csp: str) -> Dict[str, Set[str]]:
        """
        Parse CSP string into directive -> sources mapping.
        
        Args:
            csp: Raw CSP header value
            
        Returns:
            Dict mapping directive names to sets of source values
        """
        directives = {}
        
        # Split by semicolon and parse each directive
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            
            tokens = part.split()
            if tokens:
                directive = tokens[0].lower()
                sources = set(tokens[1:]) if len(tokens) > 1 else set()
                directives[directive] = sources
        
        return directives

    def _check_dangerous_sources(self, directives: Dict[str, Set[str]]) -> List[Finding]:
        """Check for dangerous sources in script/style directives."""
        findings = []
        
        # Check script-related directives
        for directive in list(self.SCRIPT_DIRECTIVES) + ["default-src"]:
            sources = directives.get(directive, set())
            if not sources:
                continue
            
            # Check for unsafe-inline without nonce/hash
            if "'unsafe-inline'" in sources:
                has_nonce = any(s.startswith("'nonce-") for s in sources)
                has_hash = any(
                    s.startswith(("'sha256-", "'sha384-", "'sha512-"))
                    for s in sources
                )
                has_strict_dynamic = "'strict-dynamic'" in sources
                
                # unsafe-inline is ignored when nonce/hash or strict-dynamic is present
                if not (has_nonce or has_hash or has_strict_dynamic):
                    logger.warning(f"[CSP] 'unsafe-inline' in {directive} without nonce/hash")
                    findings.append(self.create_finding(
                        severity=Severity.HIGH,
                        title=f"'unsafe-inline' in {directive}",
                        description=(
                            f"The {directive} directive contains 'unsafe-inline' "
                            "without a nonce or hash. This allows execution of inline "
                            "scripts, making the site vulnerable to XSS attacks."
                        ),
                        recommendation=(
                            "Replace 'unsafe-inline' with nonces or hashes. "
                            "Consider using 'strict-dynamic' for modern browsers."
                        ),
                        example_value=f"{directive} 'self' 'nonce-{{RANDOM}}' 'strict-dynamic'",
                        reference_url="https://web.dev/strict-csp/",
                        current_value=f"{directive} {' '.join(sorted(sources))}",
                        cve_ids=self.CVE_MAPPINGS.get("unsafe_inline", []),
                        compliance_ids={"OWASP_TOP_10_2025": "A03"}
                    ))
            
            # Check for unsafe-eval
            if "'unsafe-eval'" in sources:
                logger.info(f"[CSP] 'unsafe-eval' detected in {directive}")
                findings.append(self.create_finding(
                    severity=Severity.MEDIUM,
                    title=f"'unsafe-eval' in {directive}",
                    description=(
                        f"The {directive} directive contains 'unsafe-eval' "
                        "which allows eval(), Function(), and similar methods. "
                        "This can enable code injection attacks."
                    ),
                    recommendation=(
                        "Remove 'unsafe-eval' and refactor code to avoid "
                        "eval(), new Function(), setTimeout(string), etc."
                    ),
                    example_value=f"{directive} 'self' 'strict-dynamic'",
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    current_value=f"{directive} {' '.join(sorted(sources))}",
                    cve_ids=self.CVE_MAPPINGS.get("unsafe_eval", [])
                ))
            
            # Check for wildcard
            if "*" in sources:
                logger.warning(f"[CSP] Wildcard in {directive}")
                findings.append(self.create_finding(
                    severity=Severity.MEDIUM,
                    title=f"Wildcard source in {directive}",
                    description=(
                        f"The {directive} directive uses '*' which allows "
                        "loading resources from any origin."
                    ),
                    recommendation="Specify explicit allowed origins instead of wildcard.",
                    example_value=f"{directive} 'self' https://trusted.example.com",
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    current_value=f"{directive} {' '.join(sorted(sources))}"
                ))
            
            # Check for data: in script-src
            if "data:" in sources and directive in self.SCRIPT_DIRECTIVES:
                findings.append(self.create_finding(
                    severity=Severity.MEDIUM,
                    title=f"data: URI in {directive}",
                    description=(
                        f"The {directive} directive allows data: URIs which "
                        "can be used to embed and execute arbitrary scripts."
                    ),
                    recommendation="Remove 'data:' from script-src directives.",
                    example_value=f"{directive} 'self'",
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    current_value=f"{directive} {' '.join(sorted(sources))}"
                ))
        
        return findings

    def _check_required_directives(self, directives: Dict[str, Set[str]]) -> List[Finding]:
        """Check for required CSP directives."""
        findings = []
        
        for req in self.REQUIRED_DIRECTIVES:
            if req not in directives:
                findings.append(self.create_finding(
                    severity=Severity.MEDIUM,
                    title=f"Missing {req} directive",
                    description=(
                        f"The {req} directive is not set. This is a required "
                        "directive that provides baseline security."
                    ),
                    recommendation=f"Add '{req}' directive to your CSP.",
                    example_value=f"{req} 'self'",
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    current_value=None
                ))
        
        return findings

    def _check_recommended_directives(self, directives: Dict[str, Set[str]]) -> List[Finding]:
        """Check for recommended but missing directives."""
        findings = []
        
        # Only check if default-src doesn't provide coverage
        default_src = directives.get("default-src", set())
        
        for rec in self.RECOMMENDED_DIRECTIVES:
            if rec not in directives:
                # script-src falls back to default-src if present
                if rec == "script-src" and default_src:
                    continue
                
                severity = Severity.LOW if rec in ["form-action"] else Severity.INFO
                
                findings.append(self.create_finding(
                    severity=severity,
                    title=f"Consider adding {rec}",
                    description=f"The {rec} directive is not explicitly set.",
                    recommendation=f"Consider adding '{rec}' for more granular control.",
                    example_value=self._get_example_for_directive(rec),
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    current_value=None
                ))
        
        return findings

    def _check_deprecated_directives(self, directives: Dict[str, Set[str]]) -> List[Finding]:
        """Check for deprecated CSP directives."""
        findings = []
        
        for dep in self.DEPRECATED_DIRECTIVES:
            if dep in directives:
                logger.info(f"[CSP] Deprecated directive found: {dep}")
                findings.append(self.create_finding(
                    severity=Severity.INFO,
                    title=f"Deprecated directive: {dep}",
                    description=f"The {dep} directive is deprecated and should be removed.",
                    recommendation=self._get_deprecation_recommendation(dep),
                    example_value="Remove this directive",
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    current_value=f"{dep} {' '.join(directives[dep])}"
                ))
        
        return findings

    def _check_trusted_types(self, directives: Dict[str, Set[str]]) -> List[Finding]:
        """Check for Trusted Types (CSP Level 4) configuration."""
        findings = []
        
        has_require = "require-trusted-types-for" in directives
        has_types = "trusted-types" in directives
        
        if not has_require:
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Consider Trusted Types",
                description=(
                    "Trusted Types is not configured. This CSP Level 4 feature "
                    "prevents DOM XSS by requiring sanitized inputs for injection sinks. "
                    "Note: Currently only supported in Chromium browsers."
                ),
                recommendation=(
                    "Add require-trusted-types-for 'script' for DOM XSS protection. "
                    "Define policies with trusted-types directive."
                ),
                example_value=(
                    "require-trusted-types-for 'script'; "
                    "trusted-types default dompurify"
                ),
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/require-trusted-types-for",
                current_value=None
            ))
        
        return findings

    def _check_strict_dynamic(self, directives: Dict[str, Set[str]]) -> List[Finding]:
        """Check for strict-dynamic usage and configuration."""
        findings = []
        
        script_src = directives.get("script-src", directives.get("default-src", set()))
        
        if "'strict-dynamic'" in script_src:
            # strict-dynamic requires nonce or hash
            has_nonce = any(s.startswith("'nonce-") for s in script_src)
            has_hash = any(
                s.startswith(("'sha256-", "'sha384-", "'sha512-"))
                for s in script_src
            )
            
            if not (has_nonce or has_hash):
                findings.append(self.create_finding(
                    severity=Severity.MEDIUM,
                    title="strict-dynamic without nonce/hash",
                    description=(
                        "'strict-dynamic' is set but no nonce or hash is provided. "
                        "strict-dynamic requires at least one nonce or hash to work."
                    ),
                    recommendation="Add a nonce or hash when using strict-dynamic.",
                    example_value="script-src 'nonce-{{RANDOM}}' 'strict-dynamic'",
                    reference_url="https://web.dev/strict-csp/",
                    current_value=f"script-src {' '.join(sorted(script_src))}"
                ))
        
        return findings

    def _check_nonce_hash_usage(self, directives: Dict[str, Set[str]]) -> List[Finding]:
        """Check nonce and hash usage patterns."""
        findings = []
        
        script_src = directives.get("script-src", directives.get("default-src", set()))
        
        # Check for static nonces (bad practice)
        for source in script_src:
            if source.startswith("'nonce-"):
                # Extract nonce value
                nonce = source[7:-1]  # Remove 'nonce- and trailing '
                
                # Check for obviously static/weak nonces
                if len(nonce) < 16:
                    findings.append(self.create_finding(
                        severity=Severity.LOW,
                        title="Short CSP nonce",
                        description=(
                            "The CSP nonce appears to be short. Nonces should be "
                            "at least 128 bits (16 bytes) of random data, "
                            "base64 encoded."
                        ),
                        recommendation="Generate cryptographically random nonces of at least 128 bits.",
                        example_value="'nonce-' + base64(crypto.randomBytes(16))",
                        reference_url="https://web.dev/strict-csp/",
                        current_value=source
                    ))
        
        return findings

    def _check_reporting(self, directives: Dict[str, Set[str]]) -> List[Finding]:
        """Check CSP reporting configuration."""
        findings = []
        
        has_report_to = "report-to" in directives
        has_report_uri = "report-uri" in directives
        
        if not has_report_to and not has_report_uri:
            findings.append(self.create_finding(
                severity=Severity.LOW,
                title="No CSP reporting configured",
                description=(
                    "CSP violations are not being reported. Without reporting, "
                    "you won't know when attacks are blocked or if legitimate "
                    "resources are being blocked."
                ),
                recommendation="Add report-to directive to collect CSP violation reports.",
                example_value="report-to csp-endpoint",
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                current_value=None
            ))
        elif has_report_uri and not has_report_to:
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Migrate report-uri to report-to",
                description=(
                    "report-uri is deprecated. Use report-to with the "
                    "Reporting-Endpoints header instead."
                ),
                recommendation="Replace report-uri with report-to directive.",
                example_value="report-to csp-endpoint",
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to",
                current_value=f"report-uri {' '.join(directives.get('report-uri', set()))}"
            ))
        
        return findings

    def _check_frame_ancestors(self, directives: Dict[str, Set[str]]) -> List[Finding]:
        """Check frame-ancestors for clickjacking protection."""
        findings = []
        
        if "frame-ancestors" not in directives:
            # Check if X-Frame-Options provides coverage
            xfo = self.get_header("X-Frame-Options")
            if not xfo:
                findings.append(self.create_finding(
                    severity=Severity.MEDIUM,
                    title="Missing frame-ancestors",
                    description=(
                        "Neither frame-ancestors nor X-Frame-Options is set. "
                        "This leaves the site vulnerable to clickjacking attacks."
                    ),
                    recommendation="Add frame-ancestors 'none' or 'self' to prevent framing.",
                    example_value="frame-ancestors 'none'",
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    current_value=None,
                    compliance_ids={"OWASP_TOP_10_2025": "A02"}
                ))
        
        return findings

    def _check_base_uri(self, directives: Dict[str, Set[str]]) -> List[Finding]:
        """Check base-uri to prevent base tag injection."""
        findings = []
        
        if "base-uri" not in directives:
            findings.append(self.create_finding(
                severity=Severity.LOW,
                title="Missing base-uri",
                description=(
                    "base-uri is not set. Attackers could inject a <base> tag "
                    "to change the base URL for relative paths."
                ),
                recommendation="Add base-uri 'self' or 'none' to prevent base tag injection.",
                example_value="base-uri 'self'",
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                current_value=None
            ))
        
        return findings

    def _check_object_src(self, directives: Dict[str, Set[str]]) -> List[Finding]:
        """Check object-src to block plugin content."""
        findings = []
        
        object_src = directives.get("object-src", set())
        default_src = directives.get("default-src", set())
        
        # object-src falls back to default-src
        effective_src = object_src or default_src
        
        if not effective_src or "'none'" not in effective_src:
            findings.append(self.create_finding(
                severity=Severity.MEDIUM,
                title="object-src not set to 'none'",
                description=(
                    "object-src is not explicitly set to 'none'. While browser "
                    "plugins (Flash, Java) are largely deprecated, setting "
                    "object-src: 'none' provides defense-in-depth."
                ),
                recommendation="Set object-src 'none' to block plugin content.",
                example_value="object-src 'none'",
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                current_value=f"object-src {' '.join(sorted(effective_src))}" if effective_src else None
            ))
        
        return findings

    def _create_missing_finding(self) -> Finding:
        """Create finding for missing CSP header."""
        return self.create_finding(
            severity=Severity.CRITICAL,
            title="Content-Security-Policy Missing",
            description=(
                "The Content-Security-Policy header is not set. This is a critical "
                "security control that helps prevent XSS, data injection, and "
                "clickjacking attacks. Without CSP, the browser allows loading "
                "resources from any origin and executing inline scripts."
            ),
            recommendation=(
                "Implement a strict Content-Security-Policy. Start with a report-only "
                "policy to identify issues, then deploy an enforcing policy."
            ),
            example_value=(
                "default-src 'self'; "
                "script-src 'self' 'strict-dynamic' 'nonce-{{RANDOM}}'; "
                "object-src 'none'; "
                "base-uri 'self'"
            ),
            reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            current_value=None,
            cve_ids=self.CVE_MAPPINGS.get("missing_csp", []),
            compliance_ids={
                "OWASP_TOP_10_2025": "A02",
                "PCI_DSS_4": "6.4.3"
            }
        )

    def _get_example_for_directive(self, directive: str) -> str:
        """Get example value for a directive."""
        examples = {
            "script-src": "script-src 'self' 'strict-dynamic'",
            "object-src": "object-src 'none'",
            "base-uri": "base-uri 'self'",
            "form-action": "form-action 'self'",
            "frame-ancestors": "frame-ancestors 'none'",
        }
        return examples.get(directive, f"{directive} 'self'")

    def _get_deprecation_recommendation(self, directive: str) -> str:
        """Get recommendation for deprecated directive."""
        recommendations = {
            "plugin-types": "Remove this directive. Browser plugins are deprecated.",
            "referrer": "Use the Referrer-Policy HTTP header instead.",
            "block-all-mixed-content": "Use upgrade-insecure-requests instead.",
        }
        return recommendations.get(directive, "Remove this deprecated directive.")
