"""
Base analyzer class for all header analyzers.

Each analyzer inherits from this class and implements the analyze() method.
All analyzers must define HEADER_NAME and CATEGORY class variables.

Features:
- Case-insensitive header lookup
- Standardized finding creation
- CVE and compliance mapping support
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, ClassVar
import logging

from ..models import Finding, Severity, HeaderCategory, CVECorrelation, ComplianceMapping

logger = logging.getLogger(__name__)


class BaseAnalyzer(ABC):
    """Abstract base class for header analyzers."""

    # Subclasses must define these class variables
    HEADER_NAME: ClassVar[str] = ""
    CATEGORY: ClassVar[HeaderCategory] = HeaderCategory.CONTENT
    
    # Optional: Additional headers this analyzer checks
    ADDITIONAL_HEADERS: ClassVar[List[str]] = []
    
    # Optional: CVE mappings for common misconfigurations
    CVE_MAPPINGS: ClassVar[Dict[str, List[str]]] = {}
    
    # Optional: Compliance framework mappings
    COMPLIANCE_MAPPINGS: ClassVar[Dict[str, Dict[str, str]]] = {}

    def __init__(self, headers: Dict[str, str], url: str):
        """
        Initialize analyzer with response headers.

        Args:
            headers: Dict of response headers (case-insensitive keys)
            url: The target URL being analyzed
        """
        self.headers = headers
        self.url = url
        # Normalize header keys to lowercase for consistent lookup
        self._headers_lower = {k.lower(): v for k, v in headers.items()}

    def get_header(self, name: str) -> Optional[str]:
        """Get header value by name (case-insensitive)."""
        return self._headers_lower.get(name.lower())

    def has_header(self, name: str) -> bool:
        """Check if header exists."""
        return name.lower() in self._headers_lower

    @abstractmethod
    def analyze(self) -> List[Finding]:
        """
        Analyze the header and return findings.

        Returns:
            List of Finding objects (may be empty if header is good)
        """
        pass

    def create_finding(
        self,
        severity: Severity,
        title: str,
        description: str,
        recommendation: str,
        example_value: str,
        reference_url: str,
        current_value: Optional[str] = None,
        cve_ids: Optional[List[str]] = None,
        compliance_ids: Optional[Dict[str, str]] = None
    ) -> Finding:
        """
        Helper to create a Finding object with CVE and compliance mappings.
        
        Args:
            severity: Finding severity level
            title: Short descriptive title
            description: Detailed explanation
            recommendation: What should be done to fix
            example_value: Example of correct configuration
            reference_url: Link to documentation
            current_value: Current header value (None if missing)
            cve_ids: Optional list of related CVE/CWE IDs
            compliance_ids: Optional dict of framework -> requirement_id
        """
        # Build CVE correlations
        cve_correlations = []
        if cve_ids:
            for cve_id in cve_ids:
                cve_correlations.append(CVECorrelation(
                    cve_id=cve_id,
                    cvss_score=0.0,
                    description="",
                    in_cisa_kev=False
                ))
        
        # Build compliance mappings
        compliance_mappings = []
        if compliance_ids:
            for framework, req_id in compliance_ids.items():
                compliance_mappings.append(ComplianceMapping(
                    framework=framework,
                    requirement_id=req_id,
                    requirement_name="",
                    status="FAIL"
                ))
        
        return Finding(
            header=self.HEADER_NAME,
            category=self.CATEGORY,
            severity=severity,
            title=title,
            description=description,
            current_value=current_value,
            recommendation=recommendation,
            example_value=example_value,
            reference_url=reference_url,
            cve_correlations=cve_correlations,
            compliance_mappings=compliance_mappings
        )

    def create_pass_finding(self, current_value: str) -> Finding:
        """Create a PASS finding for correctly configured header."""
        return Finding(
            header=self.HEADER_NAME,
            category=self.CATEGORY,
            severity=Severity.PASS,
            title=f"{self.HEADER_NAME} Configured",
            description=f"Header is present and correctly configured.",
            current_value=current_value,
            recommendation="No action needed.",
            example_value=current_value,
            reference_url=""
        )

