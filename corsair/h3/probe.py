"""Pure-logic helpers for HTTP/3 probing.

derive_h3_target: parse Alt-Svc and pick the first h3* entry as the probe target.
is_lsquic_fingerprint: passive Server-header heuristic for CVE-2025-54939.

No httpx, no aioquic, no network I/O. Reuses corsair.cache.altsvc.parse_alt_svc.
"""

import re
from typing import Mapping, Optional, Tuple

from corsair.cache.altsvc import parse_alt_svc

# Word-boundary regex prevents false positives on "LiteSpeedAdapter" (Apache
# module). \b matches before a transition between word and non-word chars.
_LSQUIC_RE = re.compile(r"\b(litespeed|openlitespeed)\b", re.IGNORECASE)


def _case_insensitive_get(headers: Mapping[str, str], name: str) -> Optional[str]:
    """Look up a header case-insensitively. Returns None if missing."""
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return None


def derive_h3_target(
    headers: Mapping[str, str],
    fallback_host: str,
) -> Optional[Tuple[str, int]]:
    """Parse Alt-Svc and return (host, port) for the first h3* entry, or None.

    - Returns None when Alt-Svc is absent, empty, "clear", malformed, or has no
      h3* protocol-id entry.
    - When the Alt-Svc entry omits the host (e.g., 'h3=":443"'), uses
      fallback_host for the host and the entry's port.
    """
    alt_svc = _case_insensitive_get(headers, "alt-svc")
    if not alt_svc:
        return None

    entries = parse_alt_svc(alt_svc)
    for entry in entries:
        # Match h3, h3-29, h3-32, etc. Lowercased for tolerance.
        if entry.protocol_id.lower().startswith("h3"):
            host = entry.host or fallback_host
            return (host, entry.port)

    return None


def is_lsquic_fingerprint(
    headers: Mapping[str, str],
    has_h3_advertisement: bool,
) -> bool:
    """Return True iff the Server header identifies as LiteSpeed/OpenLiteSpeed
    AND the response advertised h3 in Alt-Svc.

    The has_h3_advertisement guard is the key: an Apache server with an
    "OpenLiteSpeed-Backend" string in its Server header is not vulnerable to
    LSQUIC CVE-2025-54939 unless QUIC is actually being served.
    """
    if not has_h3_advertisement:
        return False
    server = _case_insensitive_get(headers, "server")
    if not server:
        return False
    return bool(_LSQUIC_RE.search(server))
