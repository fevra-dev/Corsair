"""
Compliance Framework Mappings.

Maps security findings to various compliance frameworks:
- OWASP Top 10 2025
- PCI-DSS 4.0
- SOC 2 Type II
- HIPAA
- EU AI Act (Article 50)
"""

from typing import Dict, List, Optional
from dataclasses import dataclass

from ..models import Finding, ComplianceMapping, Severity
from ..utils.logger import get_logger

logger = get_logger(__name__)


# OWASP Top 10 2025 mapping
OWASP_TOP_10_2025 = {
    "A01": {
        "id": "A01:2025",
        "name": "Broken Access Control",
        "description": "Restrictions on authenticated users are not enforced",
        "headers": ["Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy"]
    },
    "A02": {
        "id": "A02:2025",
        "name": "Security Misconfiguration",
        "description": "Missing security hardening, improper configurations",
        "headers": [
            "Content-Security-Policy", "Strict-Transport-Security",
            "X-Frame-Options", "X-Content-Type-Options",
            "Referrer-Policy", "Permissions-Policy"
        ]
    },
    "A03": {
        "id": "A03:2025",
        "name": "Injection",
        "description": "User-supplied data not validated/sanitized",
        "headers": ["Content-Security-Policy"]
    },
    "A04": {
        "id": "A04:2025",
        "name": "Insecure Design",
        "description": "Missing or ineffective security controls",
        "headers": []
    },
    "A05": {
        "id": "A05:2025",
        "name": "Vulnerable and Outdated Components",
        "description": "Using components with known vulnerabilities",
        "headers": ["Server", "X-Powered-By"]  # Info disclosure
    },
    "A06": {
        "id": "A06:2025",
        "name": "Identification and Authentication Failures",
        "description": "Weak authentication mechanisms",
        "headers": ["Set-Cookie"]  # Cookie security
    },
    "A07": {
        "id": "A07:2025",
        "name": "Software and Data Integrity Failures",
        "description": "Integrity not verified for software/data",
        "headers": ["Content-Security-Policy"]  # SRI via CSP
    },
    "A08": {
        "id": "A08:2025",
        "name": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging and monitoring",
        "headers": ["NEL", "Reporting-Endpoints"]
    },
    "A09": {
        "id": "A09:2025",
        "name": "Server-Side Request Forgery",
        "description": "Fetching remote resources without validation",
        "headers": []
    },
    "A10": {
        "id": "A10:2025",
        "name": "Insufficient Attack Protection",
        "description": "Lack of runtime attack detection/response",
        "headers": ["Content-Security-Policy", "Permissions-Policy"]
    }
}

# PCI-DSS 4.0 mapping
PCI_DSS_4 = {
    "6.4.2": {
        "id": "6.4.2",
        "name": "Automated Technical Security Testing",
        "description": "Automated technical security testing is performed regularly",
        "headers": []
    },
    "6.4.3": {
        "id": "6.4.3",
        "name": "CSP for Payment Pages",
        "description": "CSP controls scripts/resources on payment pages",
        "headers": ["Content-Security-Policy"]
    },
    "4.2.1": {
        "id": "4.2.1",
        "name": "Strong Cryptography for Transmission",
        "description": "Strong cryptography protects PAN during transmission",
        "headers": ["Strict-Transport-Security"]
    }
}

# SOC 2 Type II mapping (relevant controls)
SOC2_TYPE_II = {
    "CC6.1": {
        "id": "CC6.1",
        "name": "Logical Access Security",
        "description": "Logical access security software/infrastructure",
        "headers": ["Cross-Origin-Opener-Policy", "Permissions-Policy"]
    },
    "CC6.6": {
        "id": "CC6.6",
        "name": "Security Measures Against Threats",
        "description": "Protection against external threats",
        "headers": ["Content-Security-Policy", "X-Frame-Options"]
    },
    "CC6.7": {
        "id": "CC6.7",
        "name": "Transmission Security",
        "description": "Protect information during transmission",
        "headers": ["Strict-Transport-Security"]
    }
}

# EU AI Act (relevant for AI-generated content)
EU_AI_ACT = {
    "Article50": {
        "id": "Article 50",
        "name": "Transparency for AI Content",
        "description": "AI-generated content must be machine-detectable",
        "headers": ["X-AI-Generated", "AI-Content-Declaration"]
    }
}

# Combined compliance frameworks
COMPLIANCE_FRAMEWORKS = {
    "OWASP_TOP_10_2025": OWASP_TOP_10_2025,
    "PCI_DSS_4": PCI_DSS_4,
    "SOC2_TYPE_II": SOC2_TYPE_II,
    "EU_AI_ACT": EU_AI_ACT
}


def get_framework_requirements(framework: str) -> Dict:
    """Get all requirements for a compliance framework."""
    return COMPLIANCE_FRAMEWORKS.get(framework, {})


def get_applicable_frameworks(header: str) -> List[Dict]:
    """
    Get compliance frameworks applicable to a header.
    
    Args:
        header: Header name
        
    Returns:
        List of applicable framework requirements
    """
    applicable = []
    
    for framework_name, requirements in COMPLIANCE_FRAMEWORKS.items():
        for req_id, req_data in requirements.items():
            if header in req_data.get("headers", []):
                applicable.append({
                    "framework": framework_name,
                    "requirement_id": req_id,
                    "requirement_name": req_data["name"],
                    "description": req_data["description"]
                })
    
    return applicable


class ComplianceMapper:
    """
    Maps findings to compliance frameworks.
    
    Usage:
        mapper = ComplianceMapper()
        mapped_finding = mapper.map_finding(finding)
        summary = mapper.generate_summary(findings)
    """
    
    def __init__(
        self,
        frameworks: Optional[List[str]] = None
    ):
        """
        Initialize compliance mapper.
        
        Args:
            frameworks: List of framework names to check.
                       Defaults to all frameworks.
        """
        self.frameworks = frameworks or list(COMPLIANCE_FRAMEWORKS.keys())
        logger.info(f"[Compliance] Mapper initialized with {len(self.frameworks)} frameworks")
    
    def map_finding(self, finding: Finding) -> Finding:
        """
        Add compliance mappings to a finding.
        
        Args:
            finding: Finding to map
            
        Returns:
            Finding with compliance_mappings populated
        """
        mappings = []
        
        for framework in self.frameworks:
            framework_reqs = COMPLIANCE_FRAMEWORKS.get(framework, {})
            
            for req_id, req_data in framework_reqs.items():
                if finding.header in req_data.get("headers", []):
                    # Determine status based on severity
                    if finding.severity == Severity.PASS:
                        status = "PASS"
                    elif finding.severity in (Severity.CRITICAL, Severity.HIGH):
                        status = "FAIL"
                    else:
                        status = "PARTIAL"
                    
                    mappings.append(ComplianceMapping(
                        framework=framework,
                        requirement_id=req_id,
                        requirement_name=req_data["name"],
                        status=status
                    ))
        
        finding.compliance_mappings = mappings
        return finding
    
    def map_all_findings(self, findings: List[Finding]) -> List[Finding]:
        """Map compliance for all findings."""
        return [self.map_finding(f) for f in findings]
    
    def generate_summary(
        self,
        findings: List[Finding]
    ) -> Dict[str, Dict[str, str]]:
        """
        Generate compliance summary from findings.
        
        Args:
            findings: List of findings with compliance mappings
            
        Returns:
            Dict of framework -> requirement -> status
        """
        summary = {}
        
        for framework in self.frameworks:
            summary[framework] = {}
            
            framework_reqs = COMPLIANCE_FRAMEWORKS.get(framework, {})
            for req_id, req_data in framework_reqs.items():
                # Find findings that map to this requirement
                req_findings = []
                for f in findings:
                    for m in f.compliance_mappings:
                        if m.framework == framework and m.requirement_id == req_id:
                            req_findings.append(m)
                
                if not req_findings:
                    # No findings for this requirement
                    if req_data.get("headers"):
                        # Check if we have PASS findings for the headers
                        pass_headers = {
                            f.header for f in findings
                            if f.severity == Severity.PASS
                        }
                        if all(h in pass_headers for h in req_data["headers"]):
                            summary[framework][req_id] = "PASS"
                        else:
                            summary[framework][req_id] = "NOT_TESTED"
                    else:
                        summary[framework][req_id] = "NOT_APPLICABLE"
                else:
                    # Aggregate status (worst case wins)
                    statuses = [m.status for m in req_findings]
                    if "FAIL" in statuses:
                        summary[framework][req_id] = "FAIL"
                    elif "PARTIAL" in statuses:
                        summary[framework][req_id] = "PARTIAL"
                    else:
                        summary[framework][req_id] = "PASS"
        
        return summary
    
    def get_failed_requirements(
        self,
        findings: List[Finding]
    ) -> List[Dict]:
        """Get list of failed compliance requirements."""
        failed = []
        
        for f in findings:
            for m in f.compliance_mappings:
                if m.status == "FAIL":
                    failed.append({
                        "framework": m.framework,
                        "requirement_id": m.requirement_id,
                        "requirement_name": m.requirement_name,
                        "header": f.header,
                        "issue": f.title
                    })
        
        return failed
