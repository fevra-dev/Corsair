"""
Reporting-Endpoints Coherence Analyzer.

Cross-references endpoint-name references in policy headers (CSP, CSP-RO, COOP,
COOP-RO, COEP, COEP-RO, DIP, NEL, Integrity-Policy, Integrity-Policy-RO) against
endpoint-name definitions in Reporting-Endpoints and Report-To. Browsers silently
discard reports for unresolved names, so an orphaned reference is a complete
loss of security violation visibility with no surface signal.

Pure static analysis. No new HTTP requests.

Spec: docs/superpowers/specs/2026-05-03-reporting-endpoints-coherence-design.md
"""

import copy
import json
import re
from typing import Dict, List, Optional, Set

from .base import BaseAnalyzer
from ..models import (
    ComplianceMapping,
    CVECorrelation,
    Finding,
    HeaderCategory,
    Severity,
)
from ..cache.oracle import fingerprint_cdn
from ..utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

DEFINITION_HEADERS = ("reporting-endpoints", "report-to")

REFERENCE_HEADERS_CSP_STYLE = (
    "content-security-policy",
    "content-security-policy-report-only",
)

REFERENCE_HEADERS_PARAM_STYLE = (
    "cross-origin-opener-policy",
    "cross-origin-opener-policy-report-only",
    "cross-origin-embedder-policy",
    "cross-origin-embedder-policy-report-only",
    "document-isolation-policy",
)

REFERENCE_HEADERS_NEL = ("nel",)

REFERENCE_HEADERS_INTEGRITY = (
    "integrity-policy",
    "integrity-policy-report-only",
)

NAVIGATION_CONTENT_TYPES = (
    "text/html",
    "application/xhtml+xml",
    "application/xml",
    "text/xml",
)

PLACEHOLDER_NAMES = frozenset({"none", "todo", "dummy", "test", "placeholder"})

REFERENCE_URL = "https://www.w3.org/TR/reporting-1/"
