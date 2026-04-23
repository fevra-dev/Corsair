"""
Corsair - HTTP Security Header Scanner & Analyzer.

A next-generation security header analysis platform with:
- 60+ header checks matching/exceeding industry standards
- 1,200+ fingerprinting signatures for technology detection
- AI-powered remediation via MCP/FastMCP integration
- CVE correlation with CISA KEV integration
- Historical tracking with drift detection
- Compliance mapping (OWASP Top 10 2025, PCI-DSS 4.0)
- Multiple export formats (SARIF, PDF, XLSX, JUnit XML)

Usage:
    # CLI
    corsair scan https://example.com

    # Python API
    from corsair import HeadScanner
    scanner = HeadScanner()
    result = scanner.scan_target("https://example.com")
    print(f"Score: {result.score}/100 ({result.grade})")

GitHub: https://github.com/fevra-dev/Corsair
License: MIT
"""

__version__ = "0.5.0"
__author__ = "Fevra"
__license__ = "MIT"
__app_name__ = "Corsair"
__description__ = "HTTP Security Header Scanner & Analyzer"
__url__ = "https://github.com/fevra-dev/Corsair"

# Core exports
from .scanner import HeadScanner
from .models import (
    Severity,
    HeaderCategory,
    Finding,
    TargetResult,
    ScanReport,
    CVECorrelation,
    ComplianceMapping,
    FingerprintResult,
    HistoricalComparison,
)

__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__license__",
    "__app_name__",
    "__description__",
    "__url__",
    # Core classes
    "HeadScanner",
    # Data models
    "Severity",
    "HeaderCategory",
    "Finding",
    "TargetResult",
    "ScanReport",
    "CVECorrelation",
    "ComplianceMapping",
    "FingerprintResult",
    "HistoricalComparison",
]
