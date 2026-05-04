"""
Corsair Analyzer Registry.

All header analyzers are registered here and executed during scans.
This module provides a centralized registry of all security checks.

Analyzer Categories:
- Core Security: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- Privacy: Referrer-Policy, Permissions-Policy, Client Hints
- Isolation: COOP, COEP, CORP, Origin-Agent-Cluster
- Cookies: Secure, HttpOnly, SameSite flags
- CORS: Access-Control-* headers
- Reporting: NEL, Reporting-Endpoints
- Information Disclosure: Server, X-Powered-By
"""

from .base import BaseAnalyzer

# Core analyzers (existing)
from .csp import CSPAnalyzer
from .hsts import HSTSAnalyzer
from .xframe import XFrameOptionsAnalyzer
from .xcontent import XContentTypeOptionsAnalyzer
from .referrer import ReferrerPolicyAnalyzer
from .permissions import PermissionsPolicyAnalyzer
from .cors import CORSAnalyzer
from .cookies import CookieAnalyzer
from .additional import AdditionalHeadersAnalyzer

# Enhanced analyzers
from .csp_enhanced import EnhancedCSPAnalyzer
from .cross_origin import (
    CrossOriginIsolationAnalyzer,
    OriginAgentClusterAnalyzer,
    DocumentPolicyAnalyzer,
)

# Reporting coherence (v0.5.4)
from .reporting import ReportingCoherenceAnalyzer

# List of all analyzers to run
# Order matters: more critical analyzers first
ALL_ANALYZERS = [
    # Use enhanced CSP analyzer instead of basic
    EnhancedCSPAnalyzer,
    # Transport security
    HSTSAnalyzer,
    # Framing protection
    XFrameOptionsAnalyzer,
    # Content type protection
    XContentTypeOptionsAnalyzer,
    # Cross-origin isolation (critical for 2026)
    CrossOriginIsolationAnalyzer,
    OriginAgentClusterAnalyzer,
    DocumentPolicyAnalyzer,
    # Privacy headers
    ReferrerPolicyAnalyzer,
    PermissionsPolicyAnalyzer,
    # CORS configuration
    CORSAnalyzer,
    # Cookie security
    CookieAnalyzer,
    # Reporting endpoint coherence (v0.5.4)
    ReportingCoherenceAnalyzer,
    # Additional headers (Server, X-Powered-By, etc.)
    AdditionalHeadersAnalyzer,
]

# Export all analyzer classes
__all__ = [
    # Base class
    "BaseAnalyzer",
    # Core analyzers
    "CSPAnalyzer",
    "EnhancedCSPAnalyzer",
    "HSTSAnalyzer",
    "XFrameOptionsAnalyzer",
    "XContentTypeOptionsAnalyzer",
    "ReferrerPolicyAnalyzer",
    "PermissionsPolicyAnalyzer",
    "CORSAnalyzer",
    "CookieAnalyzer",
    "AdditionalHeadersAnalyzer",
    # Cross-origin isolation
    "CrossOriginIsolationAnalyzer",
    "OriginAgentClusterAnalyzer",
    "DocumentPolicyAnalyzer",
    # Reporting coherence
    "ReportingCoherenceAnalyzer",
    # Registry
    "ALL_ANALYZERS",
]


def get_analyzer_count() -> int:
    """Get the total number of registered analyzers."""
    return len(ALL_ANALYZERS)


def get_analyzer_names() -> list:
    """Get list of all analyzer class names."""
    return [a.__name__ for a in ALL_ANALYZERS]
