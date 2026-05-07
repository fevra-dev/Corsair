"""
Corsair data models.

Defines all data structures used throughout the application including:
- Finding severity levels and header categories
- CVE correlations and compliance mappings
- Fingerprint results and historical comparisons
- Scan results and reports

All models use dataclasses for clean serialization and type safety.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime
import json


class Severity(Enum):
    """
    Finding severity levels aligned with CVSS scoring.

    Used to prioritize security issues and calculate overall scores.
    """

    CRITICAL = "CRITICAL"  # CVSS 9.0-10.0 - Immediate action required
    HIGH = "HIGH"  # CVSS 7.0-8.9 - High priority fix
    MEDIUM = "MEDIUM"  # CVSS 4.0-6.9 - Should be addressed
    LOW = "LOW"  # CVSS 0.1-3.9 - Minor issue
    INFO = "INFO"  # Informational - Best practice suggestion
    PASS = "PASS"  # Header correctly configured


class HeaderCategory(Enum):
    """
    Header categories for grouping and reporting.

    Organizes findings by security domain for easier analysis.
    """

    TRANSPORT = "transport"  # HSTS, upgrade-insecure-requests
    CONTENT = "content"  # CSP, X-Content-Type-Options
    FRAMING = "framing"  # X-Frame-Options, frame-ancestors
    ISOLATION = "isolation"  # COOP, COEP, CORP, Origin-Agent-Cluster
    PRIVACY = "privacy"  # Referrer-Policy, Client Hints
    PERMISSIONS = "permissions"  # Permissions-Policy (50+ features)
    CORS = "cors"  # CORS headers
    COOKIES = "cookies"  # Cookie security flags
    CACHING = "caching"  # Cache-Control security
    REPORTING = "reporting"  # NEL, Reporting-Endpoints, Report-To
    INTEGRITY = "integrity"  # Integrity-Policy, SRI
    H3 = "h3"  # HTTP/3, QUIC, 0-RTT, H1/H3 header drift, LSQUIC fingerprint
    FINGERPRINT = "fingerprint"  # Server, X-Powered-By (info disclosure)
    DEPRECATED = "deprecated"  # HPKP, X-XSS-Protection, Expect-CT


@dataclass
class CVECorrelation:
    """
    CVE correlation for a security finding.

    Links header misconfigurations to known vulnerabilities
    and provides threat intelligence context.

    Attributes:
        cve_id: CVE identifier (e.g., "CVE-2025-55182")
        cvss_score: CVSS v3 score (0.0-10.0)
        description: Vulnerability description
        in_cisa_kev: Whether CVE is in CISA Known Exploited Vulnerabilities
        ransomware_associated: Whether associated with ransomware campaigns
        mitigation: Recommended mitigation steps
    """

    cve_id: str
    cvss_score: float
    description: str
    in_cisa_kev: bool = False
    ransomware_associated: bool = False
    mitigation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "in_cisa_kev": self.in_cisa_kev,
            "ransomware_associated": self.ransomware_associated,
            "mitigation": self.mitigation,
        }


@dataclass
class ComplianceMapping:
    """
    Compliance framework mapping for a finding.

    Maps security issues to regulatory and standards requirements.

    Attributes:
        framework: Framework identifier (e.g., "OWASP_TOP_10_2025")
        requirement_id: Requirement ID (e.g., "A02")
        requirement_name: Human-readable name (e.g., "Security Misconfiguration")
        status: Compliance status ("PASS", "FAIL", "PARTIAL")
    """

    framework: str
    requirement_id: str
    requirement_name: str
    status: str  # "PASS", "FAIL", "PARTIAL"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "framework": self.framework,
            "requirement_id": self.requirement_id,
            "requirement_name": self.requirement_name,
            "status": self.status,
        }


@dataclass
class Finding:
    """
    A single security finding from header analysis.

    Core data structure representing a security issue or pass condition.
    Includes CVE correlations, compliance mappings, and remediation code.

    Attributes:
        header: Header name being analyzed
        category: Header category for grouping
        severity: Finding severity level
        title: Short descriptive title
        description: Detailed explanation of the issue
        current_value: Current header value (None if missing)
        recommendation: What should be done to fix
        example_value: Example of correct configuration
        reference_url: Link to documentation
        cve_correlations: Related CVE entries
        compliance_mappings: Compliance framework mappings
        remediation_code: Framework-specific fix code snippets
    """

    header: str
    category: HeaderCategory
    severity: Severity
    title: str
    description: str
    current_value: Optional[str]
    recommendation: str
    example_value: str
    reference_url: str
    # Enhanced fields
    cve_correlations: List[CVECorrelation] = field(default_factory=list)
    compliance_mappings: List[ComplianceMapping] = field(default_factory=list)
    remediation_code: Optional[Dict[str, str]] = None  # Framework -> code snippet

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "header": self.header,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "current_value": self.current_value,
            "recommendation": self.recommendation,
            "example_value": self.example_value,
            "reference_url": self.reference_url,
            "cve_correlations": [c.to_dict() for c in self.cve_correlations],
            "compliance_mappings": [m.to_dict() for m in self.compliance_mappings],
            "remediation_code": self.remediation_code,
        }


@dataclass
class HeaderInfo:
    """
    Information about a specific header.

    Simple container for header presence and value.
    """

    name: str
    value: Optional[str]
    present: bool


@dataclass
class FingerprintResult:
    """
    Technology fingerprinting result.

    Represents detected server, CDN, WAF, or framework technology.

    Attributes:
        category: Detection category ("server", "cdn", "waf", "framework")
        name: Technology name (e.g., "nginx", "cloudflare")
        version: Detected version if available
        confidence: Detection confidence (0.0-1.0)
        evidence: Header/value that triggered the match
    """

    category: str
    name: str
    version: Optional[str]
    confidence: float
    evidence: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "category": self.category,
            "name": self.name,
            "version": self.version,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class HistoricalComparison:
    """
    Comparison with previous scan results.

    Used for drift detection and trend analysis.

    Attributes:
        previous_scan_date: ISO timestamp of previous scan
        previous_score: Score from previous scan
        score_delta: Change in score (positive = improvement)
        new_issues: Issues found in current but not previous
        resolved_issues: Issues in previous but not current
        unchanged_issues: Issues present in both scans
    """

    previous_scan_date: str
    previous_score: int
    score_delta: int
    new_issues: List[str]
    resolved_issues: List[str]
    unchanged_issues: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "previous_scan_date": self.previous_scan_date,
            "previous_score": self.previous_score,
            "score_delta": self.score_delta,
            "new_issues": self.new_issues,
            "resolved_issues": self.resolved_issues,
            "unchanged_issues": self.unchanged_issues,
        }

    @property
    def trend(self) -> str:
        """Get trend direction based on score delta."""
        if self.score_delta > 0:
            return "improving"
        elif self.score_delta < 0:
            return "declining"
        return "stable"


@dataclass
class TargetResult:
    """
    Analysis result for a single target URL.

    Contains all findings, fingerprints, and metadata for one scan.

    Attributes:
        url: Original target URL
        final_url: Final URL after redirects
        status_code: HTTP response status code
        headers: All response headers
        findings: Security findings from analysis
        fingerprints: Technology detection results
        score: Security score (0-100)
        grade: Letter grade (A-F)
        scan_time_ms: Scan duration in milliseconds
        historical_comparison: Comparison with previous scan
        error: Error message if scan failed
    """

    url: str
    final_url: str
    status_code: int
    headers: Dict[str, str]
    findings: List[Finding]
    fingerprints: List[FingerprintResult] = field(default_factory=list)
    score: int = 0
    grade: str = "F"
    scan_time_ms: int = 0
    historical_comparison: Optional[HistoricalComparison] = None
    error: Optional[str] = None

    @property
    def critical_count(self) -> int:
        """Count of CRITICAL severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of HIGH severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Count of MEDIUM severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Count of LOW severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def pass_count(self) -> int:
        """Count of PASS (correctly configured) findings."""
        return sum(1 for f in self.findings if f.severity == Severity.PASS)

    @property
    def issue_count(self) -> int:
        """Count of actual issues (excluding PASS and INFO)."""
        return sum(1 for f in self.findings if f.severity not in (Severity.PASS, Severity.INFO))

    @property
    def cve_count(self) -> int:
        """Count of unique CVEs correlated with findings."""
        cves = set()
        for f in self.findings:
            for cve in f.cve_correlations:
                cves.add(cve.cve_id)
        return len(cves)

    @property
    def kev_count(self) -> int:
        """Count of findings with CISA KEV entries."""
        return sum(1 for f in self.findings for cve in f.cve_correlations if cve.in_cisa_kev)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "headers": self.headers,
            "score": self.score,
            "grade": self.grade,
            "scan_time_ms": self.scan_time_ms,
            "summary": {
                "findings_count": len(self.findings),
                "critical_count": self.critical_count,
                "high_count": self.high_count,
                "medium_count": self.medium_count,
                "low_count": self.low_count,
                "pass_count": self.pass_count,
                "cve_count": self.cve_count,
                "kev_count": self.kev_count,
            },
            "findings": [f.to_dict() for f in self.findings],
            "fingerprints": [fp.to_dict() for fp in self.fingerprints],
            "historical_comparison": (
                self.historical_comparison.to_dict() if self.historical_comparison else None
            ),
            "error": self.error,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class ScanReport:
    """
    Complete scan report for all targets.

    Aggregates results from scanning multiple URLs.

    Attributes:
        targets_scanned: Number of URLs scanned
        average_score: Average security score across all targets
        scan_start: ISO timestamp when scan started
        scan_end: ISO timestamp when scan completed
        scan_duration_ms: Total scan duration
        results: Individual target results
        compliance_summary: Aggregated compliance status by framework
    """

    targets_scanned: int
    average_score: float
    scan_start: str
    scan_end: str
    scan_duration_ms: int
    results: List[TargetResult]
    compliance_summary: Dict[str, Dict[str, str]] = field(default_factory=dict)

    @property
    def average_grade(self) -> str:
        """Calculate average grade from average score."""
        if self.average_score >= 90:
            return "A"
        elif self.average_score >= 80:
            return "B"
        elif self.average_score >= 70:
            return "C"
        elif self.average_score >= 60:
            return "D"
        return "F"

    @property
    def total_findings(self) -> int:
        """Total findings across all targets."""
        return sum(len(r.findings) for r in self.results)

    @property
    def total_issues(self) -> int:
        """Total issues (non-PASS/INFO) across all targets."""
        return sum(r.issue_count for r in self.results)

    @property
    def total_cves(self) -> int:
        """Total unique CVEs across all targets."""
        cves = set()
        for r in self.results:
            for f in r.findings:
                for cve in f.cve_correlations:
                    cves.add(cve.cve_id)
        return len(cves)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "metadata": {
                "targets_scanned": self.targets_scanned,
                "average_score": round(self.average_score, 1),
                "average_grade": self.average_grade,
                "scan_start": self.scan_start,
                "scan_end": self.scan_end,
                "scan_duration_ms": self.scan_duration_ms,
                "total_findings": self.total_findings,
                "total_issues": self.total_issues,
                "total_cves": self.total_cves,
            },
            "results": [r.to_dict() for r in self.results],
            "compliance_summary": self.compliance_summary,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


# Severity weight mappings for scoring
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 0,
    Severity.PASS: 0,
}

# Grade thresholds
GRADE_THRESHOLDS = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
]
