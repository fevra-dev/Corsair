"""Body fetch + cross-origin script extraction for Integrity-Policy IP-006.

Sync httpx GET capped at 1 MB; regex-based <script> tag scan against an
exact (scheme, host, port) origin tuple.
"""

import logging
import re
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

import httpx


logger = logging.getLogger(__name__)


ONE_MEGABYTE = 1024 * 1024  # body cap


# Default ports per scheme — applied when port is omitted.
_DEFAULT_PORTS = {"http": 80, "https": 443}


# Match opening <script ...> tag (NOT closing </script>). DOTALL so multi-line
# tags match. Capture inner attributes as group 1.
_SCRIPT_TAG_RE = re.compile(
    r"<script\b([^>]*?)>",
    re.IGNORECASE | re.DOTALL,
)

# Attribute extractors. Independent regexes — order-agnostic within the tag.
_SRC_ATTR_RE = re.compile(
    r"""\bsrc\s*=\s*(?P<q>["'])(?P<val>.*?)(?P=q)""",
    re.IGNORECASE | re.DOTALL,
)
_INTEGRITY_ATTR_RE = re.compile(
    r"""\bintegrity\s*=\s*(?P<q>["'])(?P<val>.*?)(?P=q)""",
    re.IGNORECASE | re.DOTALL,
)


def _origin_tuple(url: str) -> Optional[Tuple[str, str, int]]:
    """Return (scheme, host, port) tuple for the URL, or None on failure."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        return None
    port = parts.port if parts.port is not None else _DEFAULT_PORTS.get(scheme, 0)
    return (scheme, host, port)


def _resolve_src(src: str, doc_url: str) -> Optional[str]:
    """Resolve src against doc_url. Skip data:, javascript:, blob:, empty."""
    if not src:
        return None
    s = src.strip()
    if not s:
        return None
    lower = s.lower()
    if lower.startswith(("data:", "javascript:", "blob:", "about:", "mailto:")):
        return None
    # Protocol-relative: //host/path -> resolve scheme from doc_url.
    if s.startswith("//"):
        doc_origin = _origin_tuple(doc_url)
        if doc_origin is None:
            return None
        return f"{doc_origin[0]}:{s}"
    # Absolute URL: keep as-is.
    if "://" in s:
        return s
    # Relative URL: same-origin by definition; caller treats None as same-origin.
    return None


def _extract_cross_origin_scripts(body: str, doc_url: str) -> List[str]:
    """Return cross-origin script src URLs that lack an integrity attribute.

    Cross-origin = different (scheme, host, port) from doc_url. Subdomains are
    cross-origin (exact tuple match, not eTLD+1).

    False positives accepted: HTML-comment-wrapped scripts and <noscript>
    subtree scripts are matched by the regex. Documented in the IP-006 finding.
    """
    if not body:
        return []
    doc_origin = _origin_tuple(doc_url)
    if doc_origin is None:
        return []

    flagged: List[str] = []
    for tag_match in _SCRIPT_TAG_RE.finditer(body):
        attrs = tag_match.group(1)
        src_match = _SRC_ATTR_RE.search(attrs)
        if src_match is None:
            continue
        raw_src = src_match.group("val")
        resolved = _resolve_src(raw_src, doc_url)
        if resolved is None:
            continue
        script_origin = _origin_tuple(resolved)
        if script_origin is None or script_origin == doc_origin:
            continue
        # Cross-origin script. Flag if no integrity attribute.
        if _INTEGRITY_ATTR_RE.search(attrs) is None:
            flagged.append(resolved)
    return flagged


def _fetch_body(
    url: str, timeout: int, user_agent: str
) -> Tuple[str, Optional[str]]:
    """GET url with the supplied User-Agent. Return (body_text, error_or_None).

    Honors timeout. Caps body at 1 MB (truncates the rest). Treats non-2xx
    as a soft failure: returns ("", "HTTP <status>"). Network exceptions
    return ("", "<exception class>: <message>").
    """
    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            verify=True,
        ) as client:
            response = client.get(
                url,
                headers={"User-Agent": user_agent, "Accept": "text/html, */*"},
            )
    except httpx.TimeoutException:
        return ("", "Request timeout")
    except httpx.ConnectError as e:
        return ("", f"Connection error: {e}")
    except httpx.TooManyRedirects:
        return ("", "Too many redirects")
    except Exception as e:  # broad: TLS handshake, brotli decode, etc.
        return ("", f"{type(e).__name__}: {e}")

    if not (200 <= response.status_code < 300):
        return ("", f"HTTP {response.status_code}")

    raw = response.content or b""
    truncated = raw[:ONE_MEGABYTE]
    try:
        body_text = truncated.decode(response.encoding or "utf-8", errors="replace")
    except (LookupError, TypeError):
        body_text = truncated.decode("utf-8", errors="replace")
    return (body_text, None)
