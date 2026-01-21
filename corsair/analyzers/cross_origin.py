"""
Cross-Origin Isolation Analyzer.

Analyzes headers for cross-origin isolation capabilities:
- Cross-Origin-Opener-Policy (COOP)
- Cross-Origin-Embedder-Policy (COEP)
- Cross-Origin-Resource-Policy (CORP)

Critical for 2026 threat landscape:
- Gmail enforced COOP on January 20, 2026 to prevent XS-Search attacks
- Cross-origin isolation is required for SharedArrayBuffer and high-precision timers
- Spectre mitigations depend on proper COOP/COEP configuration
"""

from typing import List, Dict, Set, Optional
from .base import BaseAnalyzer
from ..models import Finding, Severity, HeaderCategory
from ..utils.logger import get_logger

logger = get_logger(__name__)


class CrossOriginIsolationAnalyzer(BaseAnalyzer):
    """
    Analyzer for cross-origin isolation headers (COOP, COEP, CORP).
    
    These headers work together to provide process isolation:
    - COOP: Controls which documents can share a browsing context group
    - COEP: Controls which resources can be loaded cross-origin
    - CORP: Declares which origins can load the resource
    
    Full cross-origin isolation requires:
    - Cross-Origin-Opener-Policy: same-origin
    - Cross-Origin-Embedder-Policy: require-corp
    """
    
    HEADER_NAME = "Cross-Origin-Opener-Policy"  # Primary header
    CATEGORY = HeaderCategory.ISOLATION
    
    ADDITIONAL_HEADERS = [
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Resource-Policy"
    ]
    
    # Valid values for each header
    VALID_COOP_VALUES = {
        "unsafe-none",           # No isolation (default)
        "same-origin-allow-popups",  # Partial isolation
        "same-origin",           # Full isolation
    }
    
    VALID_COEP_VALUES = {
        "unsafe-none",           # No restrictions (default)
        "require-corp",          # Require CORP or CORS
        "credentialless",        # Load without credentials
    }
    
    VALID_CORP_VALUES = {
        "same-site",             # Same site only
        "same-origin",           # Same origin only
        "cross-origin",          # Any origin (with CORS)
    }
    
    # CVE mappings for XS-Leaks/Spectre related issues
    CVE_MAPPINGS = {
        "missing_coop": ["CWE-200"],  # Information Disclosure
        "xs_search": ["CWE-203"],     # Observable Timing Discrepancy
    }

    def analyze(self) -> List[Finding]:
        """
        Analyze cross-origin isolation headers.
        
        Returns:
            List of findings for COOP, COEP, and CORP configuration
        """
        findings = []
        
        # Get all relevant headers
        coop = self.get_header("Cross-Origin-Opener-Policy")
        coep = self.get_header("Cross-Origin-Embedder-Policy")
        corp = self.get_header("Cross-Origin-Resource-Policy")
        
        logger.info(f"[CrossOrigin] Analyzing for {self.url}")
        logger.debug(f"[CrossOrigin] COOP={coop}, COEP={coep}, CORP={corp}")
        
        # Check COOP
        findings.extend(self._check_coop(coop))
        
        # Check COEP
        findings.extend(self._check_coep(coep))
        
        # Check CORP
        findings.extend(self._check_corp(corp))
        
        # Check cross-origin isolation status
        findings.extend(self._check_isolation_status(coop, coep))
        
        return findings

    def _check_coop(self, coop: Optional[str]) -> List[Finding]:
        """Check Cross-Origin-Opener-Policy configuration."""
        findings = []
        
        if not coop:
            logger.info("[CrossOrigin] COOP not set")
            findings.append(self.create_finding(
                severity=Severity.MEDIUM,
                title="Cross-Origin-Opener-Policy Not Set",
                description=(
                    "The Cross-Origin-Opener-Policy (COOP) header is not set. "
                    "Without COOP, the site may be vulnerable to XS-Leak attacks "
                    "where attackers can use window references to infer sensitive "
                    "information. Gmail enforced COOP on January 20, 2026 to "
                    "prevent XS-Search attacks."
                ),
                recommendation=(
                    "Set Cross-Origin-Opener-Policy to 'same-origin' for full "
                    "isolation, or 'same-origin-allow-popups' if you need to "
                    "open cross-origin popups."
                ),
                example_value="Cross-Origin-Opener-Policy: same-origin",
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
                current_value=None,
                cve_ids=self.CVE_MAPPINGS.get("missing_coop", [])
            ))
        else:
            # Parse the value (may have reporting directive)
            coop_value = coop.split(";")[0].strip().lower()
            
            # Check for valid value
            if coop_value not in self.VALID_COOP_VALUES:
                findings.append(self.create_finding(
                    severity=Severity.LOW,
                    title="Invalid COOP Value",
                    description=f"COOP value '{coop_value}' is not a standard value.",
                    recommendation="Use a valid COOP value: same-origin, same-origin-allow-popups, or unsafe-none.",
                    example_value="Cross-Origin-Opener-Policy: same-origin",
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
                    current_value=coop
                ))
            elif coop_value == "unsafe-none":
                # Explicitly set to unsafe-none (same as not set)
                findings.append(self.create_finding(
                    severity=Severity.LOW,
                    title="COOP Set to unsafe-none",
                    description=(
                        "COOP is explicitly set to 'unsafe-none' which provides "
                        "no isolation. Consider upgrading to 'same-origin' or "
                        "'same-origin-allow-popups'."
                    ),
                    recommendation="Consider setting COOP to 'same-origin' for better isolation.",
                    example_value="Cross-Origin-Opener-Policy: same-origin",
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
                    current_value=coop
                ))
            elif coop_value == "same-origin-allow-popups":
                # Partial isolation - info level
                findings.append(self.create_finding(
                    severity=Severity.INFO,
                    title="COOP Allows Popups",
                    description=(
                        "COOP is set to 'same-origin-allow-popups' which provides "
                        "partial isolation. This is acceptable if you need to open "
                        "cross-origin popups (OAuth, payment flows)."
                    ),
                    recommendation="Consider 'same-origin' if popup functionality is not required.",
                    example_value="Cross-Origin-Opener-Policy: same-origin",
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
                    current_value=coop
                ))
            else:
                # same-origin - good configuration
                logger.debug("[CrossOrigin] COOP correctly configured as same-origin")
        
        return findings

    def _check_coep(self, coep: Optional[str]) -> List[Finding]:
        """Check Cross-Origin-Embedder-Policy configuration."""
        findings = []
        
        if not coep:
            logger.info("[CrossOrigin] COEP not set")
            findings.append(self.create_finding(
                severity=Severity.MEDIUM,
                title="Cross-Origin-Embedder-Policy Not Set",
                description=(
                    "The Cross-Origin-Embedder-Policy (COEP) header is not set. "
                    "COEP is required for cross-origin isolation and access to "
                    "APIs like SharedArrayBuffer. Without COEP, cross-origin "
                    "resources can be loaded without explicit permission."
                ),
                recommendation=(
                    "Set Cross-Origin-Embedder-Policy to 'require-corp' for full "
                    "isolation, or 'credentialless' for a more permissive policy "
                    "that still provides some protection."
                ),
                example_value="Cross-Origin-Embedder-Policy: require-corp",
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
                current_value=None
            ))
        else:
            coep_value = coep.split(";")[0].strip().lower()
            
            if coep_value not in self.VALID_COEP_VALUES:
                findings.append(self.create_finding(
                    severity=Severity.LOW,
                    title="Invalid COEP Value",
                    description=f"COEP value '{coep_value}' is not a standard value.",
                    recommendation="Use a valid COEP value: require-corp, credentialless, or unsafe-none.",
                    example_value="Cross-Origin-Embedder-Policy: require-corp",
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
                    current_value=coep
                ))
            elif coep_value == "unsafe-none":
                findings.append(self.create_finding(
                    severity=Severity.LOW,
                    title="COEP Set to unsafe-none",
                    description="COEP is explicitly set to 'unsafe-none' which provides no restrictions.",
                    recommendation="Consider setting COEP to 'require-corp' for cross-origin isolation.",
                    example_value="Cross-Origin-Embedder-Policy: require-corp",
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
                    current_value=coep
                ))
            elif coep_value == "credentialless":
                findings.append(self.create_finding(
                    severity=Severity.INFO,
                    title="COEP Using credentialless",
                    description=(
                        "COEP is set to 'credentialless' which loads cross-origin "
                        "resources without credentials. This is more permissive "
                        "than 'require-corp' but still enables cross-origin isolation."
                    ),
                    recommendation="Consider 'require-corp' for stricter isolation if compatible.",
                    example_value="Cross-Origin-Embedder-Policy: require-corp",
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
                    current_value=coep
                ))
        
        return findings

    def _check_corp(self, corp: Optional[str]) -> List[Finding]:
        """Check Cross-Origin-Resource-Policy configuration."""
        findings = []
        
        if not corp:
            # CORP is more of a resource-level header, less critical for main page
            findings.append(self.create_finding(
                severity=Severity.LOW,
                title="Cross-Origin-Resource-Policy Not Set",
                description=(
                    "The Cross-Origin-Resource-Policy (CORP) header is not set. "
                    "CORP declares which origins can embed this resource. For "
                    "HTML pages, this is less critical than for sub-resources, "
                    "but setting it provides defense-in-depth."
                ),
                recommendation=(
                    "Set Cross-Origin-Resource-Policy to 'same-origin' or 'same-site' "
                    "to prevent cross-origin embedding of this resource."
                ),
                example_value="Cross-Origin-Resource-Policy: same-origin",
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
                current_value=None
            ))
        else:
            corp_value = corp.strip().lower()
            
            if corp_value not in self.VALID_CORP_VALUES:
                findings.append(self.create_finding(
                    severity=Severity.LOW,
                    title="Invalid CORP Value",
                    description=f"CORP value '{corp_value}' is not a standard value.",
                    recommendation="Use a valid CORP value: same-origin, same-site, or cross-origin.",
                    example_value="Cross-Origin-Resource-Policy: same-origin",
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
                    current_value=corp
                ))
            elif corp_value == "cross-origin":
                # cross-origin is permissive but valid
                findings.append(self.create_finding(
                    severity=Severity.INFO,
                    title="CORP Allows Cross-Origin",
                    description=(
                        "CORP is set to 'cross-origin' which allows any origin "
                        "to embed this resource. This is appropriate for public "
                        "resources but consider 'same-origin' for sensitive content."
                    ),
                    recommendation="Use 'same-origin' for sensitive resources.",
                    example_value="Cross-Origin-Resource-Policy: same-origin",
                    reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
                    current_value=corp
                ))
        
        return findings

    def _check_isolation_status(
        self,
        coop: Optional[str],
        coep: Optional[str]
    ) -> List[Finding]:
        """
        Check if cross-origin isolation is achievable.
        
        Cross-origin isolation requires:
        - COOP: same-origin
        - COEP: require-corp (or credentialless)
        """
        findings = []
        
        # Parse values
        coop_value = (coop.split(";")[0].strip().lower() if coop else None)
        coep_value = (coep.split(";")[0].strip().lower() if coep else None)
        
        # Check for full isolation
        coop_isolated = coop_value == "same-origin"
        coep_isolated = coep_value in ("require-corp", "credentialless")
        
        if coop_isolated and coep_isolated:
            logger.info("[CrossOrigin] Full cross-origin isolation achieved")
            findings.append(self.create_finding(
                severity=Severity.PASS,
                title="Cross-Origin Isolation Enabled",
                description=(
                    "This page is cross-origin isolated. It has access to "
                    "SharedArrayBuffer, high-precision timers, and is protected "
                    "from Spectre-class attacks."
                ),
                recommendation="No action needed. Cross-origin isolation is correctly configured.",
                example_value="COOP: same-origin + COEP: require-corp",
                reference_url="https://web.dev/coop-coep/",
                current_value=f"COOP: {coop}, COEP: {coep}"
            ))
        elif coop or coep:
            # Partial configuration
            missing = []
            if not coop_isolated:
                missing.append("COOP: same-origin")
            if not coep_isolated:
                missing.append("COEP: require-corp")
            
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Partial Cross-Origin Isolation",
                description=(
                    f"Cross-origin isolation is partially configured. "
                    f"Missing: {', '.join(missing)}. Full isolation requires "
                    "both COOP: same-origin and COEP: require-corp."
                ),
                recommendation=f"Add {' and '.join(missing)} for full cross-origin isolation.",
                example_value="COOP: same-origin\nCOEP: require-corp",
                reference_url="https://web.dev/coop-coep/",
                current_value=f"COOP: {coop or 'not set'}, COEP: {coep or 'not set'}"
            ))
        
        return findings


class OriginAgentClusterAnalyzer(BaseAnalyzer):
    """
    Analyzer for Origin-Agent-Cluster header.
    
    Origin-Agent-Cluster requests that the browser allocate this origin
    to an origin-keyed agent cluster, providing stronger isolation.
    This is useful for Spectre mitigations and improved security boundaries.
    """
    
    HEADER_NAME = "Origin-Agent-Cluster"
    CATEGORY = HeaderCategory.ISOLATION

    def analyze(self) -> List[Finding]:
        """Analyze Origin-Agent-Cluster header."""
        findings = []
        
        oac = self.get_header(self.HEADER_NAME)
        
        if not oac:
            findings.append(self.create_finding(
                severity=Severity.INFO,
                title="Origin-Agent-Cluster Not Set",
                description=(
                    "The Origin-Agent-Cluster header is not set. This header "
                    "requests origin-keyed agent clusters for stronger process "
                    "isolation. It provides additional Spectre mitigations."
                ),
                recommendation="Consider adding Origin-Agent-Cluster: ?1 for enhanced isolation.",
                example_value="Origin-Agent-Cluster: ?1",
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin-Agent-Cluster",
                current_value=None
            ))
        elif oac.strip() == "?1":
            findings.append(self.create_finding(
                severity=Severity.PASS,
                title="Origin-Agent-Cluster Enabled",
                description="Origin-Agent-Cluster is enabled for enhanced process isolation.",
                recommendation="No action needed.",
                example_value="Origin-Agent-Cluster: ?1",
                reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin-Agent-Cluster",
                current_value=oac
            ))
        
        return findings


class DocumentPolicyAnalyzer(BaseAnalyzer):
    """
    Analyzer for Document-Policy header (experimental).
    
    Document-Policy provides fine-grained control over document features,
    similar to Permissions-Policy but for document-level features.
    """
    
    HEADER_NAME = "Document-Policy"
    CATEGORY = HeaderCategory.ISOLATION

    def analyze(self) -> List[Finding]:
        """Analyze Document-Policy header."""
        findings = []
        
        dp = self.get_header(self.HEADER_NAME)
        
        # Document-Policy is experimental, so just note if it's present
        if dp:
            logger.debug(f"[DocumentPolicy] Found: {dp}")
            findings.append(self.create_finding(
                severity=Severity.PASS,
                title="Document-Policy Configured",
                description=(
                    "Document-Policy header is set. This experimental feature "
                    "provides fine-grained control over document features."
                ),
                recommendation="No action needed. Document-Policy is configured.",
                example_value=dp[:100],
                reference_url="https://wicg.github.io/document-policy/",
                current_value=dp
            ))
        
        # Not finding Document-Policy is not an issue since it's experimental
        return findings
