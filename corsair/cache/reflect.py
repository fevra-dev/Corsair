"""
Reflection detection for cache poisoning canary values.

Classifies where a canary string appears in an HTTP response,
ranked by security impact. Returns the most severe context found.
"""

import re
from typing import Optional

_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']*)', re.I)
_LINK_HREF = re.compile(r'<link[^>]+href=["\']([^"\']*)', re.I)
_CANONICAL = re.compile(
    r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']*)', re.I
)
_META_REFRESH = re.compile(
    r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\';\s]*)', re.I
)
_IMG_SRC = re.compile(r'<(?:img|iframe|embed)[^>]+src=["\']([^"\']*)', re.I)
_JS_VARIABLE = re.compile(
    r'(?:var\s+\w+|let\s+\w+|const\s+\w+|window\.\w+)\s*=\s*["\']([^"\']+)["\']', re.I
)

HEADER_CONTEXTS: list[tuple[str, str]] = [
    ("content-security-policy", "csp_header"),
    ("location", "location_header"),
    ("access-control-allow-origin", "cors_header"),
    ("link", "link_header"),
    ("set-cookie", "other_header"),
]

BODY_CONTEXTS: list[tuple[re.Pattern, str]] = [
    (_SCRIPT_SRC, "script_src"),
    (_CANONICAL, "canonical_href"),
    (_META_REFRESH, "meta_refresh"),
    (_LINK_HREF, "link_href"),
    (_IMG_SRC, "img_src"),
    (_JS_VARIABLE, "js_variable"),
]

CONTEXT_SEVERITY_ORDER: list[str] = [
    "script_src",
    "csp_header",
    "location_header",
    "link_href",
    "meta_refresh",
    "cors_header",
    "js_variable",
    "canonical_href",
    "img_src",
    "body_text",
    "other_header",
]


def detect_reflection(
    response, canary: str
) -> tuple[bool, Optional[str]]:
    found_contexts: list[str] = []

    headers = response.headers or {}
    for header_name, context_id in HEADER_CONTEXTS:
        for key, value in headers.items():
            if key.lower() == header_name and canary in value:
                found_contexts.append(context_id)
                break

    body = getattr(response, "text", "") or ""
    if canary in body:
        body_matches: list[str] = []
        for pattern, context_id in BODY_CONTEXTS:
            for match in pattern.finditer(body):
                if canary in match.group(1):
                    body_matches.append(context_id)
                    break

        # Canonical is a more specific form of link_href; prefer it when both match.
        if "canonical_href" in body_matches and "link_href" in body_matches:
            body_matches.remove("link_href")

        found_contexts.extend(body_matches)

        if not body_matches and all(
            c in ("other_header",) for c in found_contexts
        ):
            found_contexts.append("body_text")
        elif not body_matches and not found_contexts:
            found_contexts.append("body_text")

    if not found_contexts:
        return False, None

    for ctx in CONTEXT_SEVERITY_ORDER:
        if ctx in found_contexts:
            return True, ctx

    return True, found_contexts[0]
