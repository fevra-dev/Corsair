"""
Alt-Svc grammar, canary detection, passive analysis, and CDN pre-check.

Pure logic over strings and fingerprint tags. No httpx, no I/O.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import List, Mapping, Optional


@dataclass(frozen=True)
class AltSvcEntry:
    protocol_id: str
    host: Optional[str]
    port: int
    ma: Optional[int]
    persist: bool


_ENTRY_RE = re.compile(
    r'\s*([A-Za-z0-9\-]+)\s*=\s*"([^"]*)"\s*((?:;\s*[A-Za-z0-9_\-]+\s*=\s*[^;,]+\s*)*)'
)
_PARAM_RE = re.compile(r"([A-Za-z0-9_\-]+)\s*=\s*([^;,]+)")


def parse_alt_svc(value: str) -> List[AltSvcEntry]:
    """
    Parse an Alt-Svc header value into AltSvcEntry instances.

    Returns [] for "clear", empty input, or malformed input. Never raises.
    """
    if value is None:
        return []
    stripped = value.strip()
    if not stripped or stripped.lower() == "clear":
        return []

    entries: List[AltSvcEntry] = []
    for match in _ENTRY_RE.finditer(stripped):
        protocol_id = match.group(1)
        authority = match.group(2)
        params_str = match.group(3) or ""

        if ":" not in authority:
            continue
        host_part, _, port_part = authority.rpartition(":")
        try:
            port = int(port_part)
        except ValueError:
            continue
        host = host_part if host_part else None

        ma: Optional[int] = None
        persist = False
        for p in _PARAM_RE.finditer(params_str):
            key = p.group(1).lower()
            val = p.group(2).strip().strip('"')
            if key == "ma":
                try:
                    ma = int(val)
                except ValueError:
                    pass
            elif key == "persist" and val == "1":
                persist = True

        entries.append(
            AltSvcEntry(protocol_id=protocol_id, host=host, port=port, ma=ma, persist=persist)
        )
    return entries


def detect_alt_svc_canary(value: str, canary: str) -> bool:
    """
    Alt-authority-anchored canary detection.

    Returns True only when the canary appears inside a quoted alt-authority value.
    Returns False for "clear", empty, or canary-absent input.
    """
    if not value:
        return False
    stripped = value.strip()
    if not stripped or stripped.lower() == "clear":
        return False
    pattern = re.compile(
        r'=\s*"[^"]*' + re.escape(canary) + r'[^"]*"',
        re.IGNORECASE,
    )
    return bool(pattern.search(value))
