"""Parse Integrity-Policy / Integrity-Policy-Report-Only header values.

RFC 9651 Structured Fields Dictionary; SRI §3.8.
"""

import re
from typing import Dict, List


# Recognized destination tokens per SRI §3.8.
RECOGNIZED_DESTINATIONS = frozenset({"script", "style"})

# HTML-class Content-Type values that justify a body GET for IP-006.
HTML_CONTENT_TYPES = frozenset({
    "text/html",
    "application/xhtml+xml",
    "application/xml",
    "text/xml",
})

# Matches one SF dictionary member: <key>=(<inner-list>)
_SF_DICT_MEMBER_RE = re.compile(
    r"(?:^|,)\s*([\w][\w\-]*)\s*=\s*\(([^)]*)\)",
    re.IGNORECASE,
)


def _parse_integrity_policy(value: str) -> Dict:
    """Parse an Integrity-Policy or IP-Report-Only header value.

    Returns a dict with keys:
      - blocked_destinations: list[str] — lowercased tokens (recognized or unknown)
      - sources: list[str] — lowercased tokens; defaults to ['inline'] per SRI §3.8
      - endpoints: list[str] — lowercased tokens
      - parse_error: bool — True if no SF dict members were found at all
    """
    parsed = {
        "blocked_destinations": [],
        "sources": ["inline"],
        "endpoints": [],
        "parse_error": False,
    }
    if not value or not value.strip():
        parsed["parse_error"] = True
        return parsed

    members = list(_SF_DICT_MEMBER_RE.finditer(value))
    if not members:
        parsed["parse_error"] = True
        return parsed

    sources_seen = False
    for m in members:
        key = m.group(1).strip().lower()
        inner = m.group(2).strip()
        tokens = [t.strip().lower() for t in inner.split() if t.strip()]
        if key == "blocked-destinations":
            parsed["blocked_destinations"] = tokens
        elif key == "sources":
            parsed["sources"] = tokens
            sources_seen = True
        elif key == "endpoints":
            parsed["endpoints"] = tokens

    if not sources_seen:
        parsed["sources"] = ["inline"]
    return parsed


def _is_html_response(headers: Dict[str, str]) -> bool:
    """Return True iff the Content-Type indicates an HTML-class document.

    Empty / missing Content-Type returns False — stricter than reporting.py
    because body fetching costs a round-trip; only do it when the server
    explicitly advertises HTML.
    """
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v or ""
            break
    if not ct:
        return False
    base = ct.split(";", 1)[0].strip().lower()
    return base in HTML_CONTENT_TYPES
