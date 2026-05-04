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


# ---------------------------------------------------------------------------
# Parser helpers — definitions
# ---------------------------------------------------------------------------

# RFC 8941 dictionary key: starts with lowercase alpha or asterisk, followed
# by lowercase alphanumeric, '_', '-', '.', or '*'. Value is either a quoted
# string or a token until the next comma at depth 0.
_REPORTING_ENDPOINTS_KEY_RE = re.compile(
    r'(?P<key>[a-z*][a-z0-9_.*\-]*)\s*=\s*(?:"[^"]*"|[^,]+)'
)


def _parse_reporting_endpoints(value: str) -> Set[str]:
    """Parse an RFC 8941 Structured Fields Dictionary, returning the key set.

    The Reporting-Endpoints header has the form:
        main-endpoint="https://reports.example.com/main", backup="https://b/r"

    Returns a set of lowercased endpoint names. Returns an empty set on empty
    or malformed input.
    """
    if not value:
        return set()
    try:
        return {m.group("key") for m in _REPORTING_ENDPOINTS_KEY_RE.finditer(value.lower())}
    except Exception:  # defensive — regex shouldn't raise on str input
        return set()


def _parse_report_to(value: str) -> Set[str]:
    """Parse a legacy Report-To JSON header, returning group names.

    The Report-To header is a JSON array of objects, but some implementations
    send a bare object. This parser auto-wraps a bare object so both forms
    work. Group names are lowercased on extraction.

    Returns an empty set on empty or malformed input.
    """
    if not value:
        return set()

    raw = value.strip()
    if not raw.startswith("["):
        raw = f"[{raw}]"

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return set()

    if not isinstance(data, list):
        return set()

    groups: Set[str] = set()
    for entry in data:
        if not isinstance(entry, dict):
            continue
        group_name = entry.get("group", "default")
        if isinstance(group_name, str):
            groups.add(group_name.lower())
    return groups


# ---------------------------------------------------------------------------
# Parser helpers — references
# ---------------------------------------------------------------------------

_CSP_REPORT_TO_RE = re.compile(r"report-to\s+([a-z0-9_.\-*]+)", re.IGNORECASE)


def _extract_csp_report_to(value: str) -> Optional[str]:
    """Extract the report-to token from a CSP/CSP-RO directive value.

    CSP form: 'default-src 'self'; report-to my-endpoint'
    Returns the lowercased token or None if no report-to directive is present.
    """
    if not value:
        return None
    m = _CSP_REPORT_TO_RE.search(value)
    return m.group(1).lower() if m else None


def _extract_param_report_to(value: str) -> Optional[str]:
    """Extract the report-to parameter from semicolon-delimited isolation headers.

    Format: 'same-origin; report-to="my-endpoint"' (also accepts unquoted names).
    Used by COOP, COOP-RO, COEP, COEP-RO, DIP.

    Returns the lowercased name or None if no report-to parameter is present.
    """
    if not value or "report-to" not in value.lower():
        return None
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("report-to") and "=" in part:
            _, name = part.split("=", 1)
            return name.strip().strip('"').strip("'")
    return None


def _extract_nel_report_to(value: str) -> Optional[str]:
    """Extract the report_to field from a Network-Error-Logging JSON header.

    Format: '{"report_to": "nel-endpoint", "max_age": 86400}'
    Returns the lowercased name or None if missing or malformed.
    """
    if not value:
        return None
    try:
        data = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    name = data.get("report_to")
    return name.lower() if isinstance(name, str) else None


_INTEGRITY_ENDPOINTS_RE = re.compile(r"endpoints\s*=\s*\(([^)]*)\)", re.IGNORECASE)


def _extract_integrity_endpoints(value: str) -> Set[str]:
    """Extract endpoint names from an Integrity-Policy or Integrity-Policy-RO header.

    Format: 'blocked-destinations=(script), endpoints=(ep1 ep2)'
    The endpoints parameter is an RFC 8941 Inner List of tokens.

    Returns a set of lowercased names (empty if missing or malformed).
    """
    if not value:
        return set()
    m = _INTEGRITY_ENDPOINTS_RE.search(value)
    if not m:
        return set()
    inner = m.group(1).strip().lower()
    if not inner:
        return set()
    return {tok for tok in inner.split() if tok}


# ---------------------------------------------------------------------------
# Discriminator
# ---------------------------------------------------------------------------

def _is_navigation_response(headers: Dict[str, str]) -> bool:
    """Return True if the response Content-Type indicates a navigation context.

    Navigation context = Reporting-Endpoints / Report-To definitions are
    expected on this response. Restricts the coherence check to top-level
    document responses (HTML/XHTML/XML), suppressing false positives on
    sub-resources where definitions live on the originating HTML response.

    Missing or empty Content-Type defaults to True (analyze) since many origins
    serving HTML omit it in practice.
    """
    # Case-insensitive header lookup.
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = (v or "").strip().lower()
            break
    if not ct:
        return True
    # Strip parameters: 'text/html; charset=utf-8' -> 'text/html'
    main = ct.split(";", 1)[0].strip()
    return main in NAVIGATION_CONTENT_TYPES
