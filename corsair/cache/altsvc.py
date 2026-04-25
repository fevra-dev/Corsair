"""
Alt-Svc grammar, canary detection, passive analysis, and CDN pre-check.

Pure logic over strings and fingerprint tags. No httpx, no I/O.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import List, Mapping, Optional

import tldextract

_RESERVED_PSEUDO_TLDS = (".local", ".internal", ".invalid", ".localhost", ".test", ".example")
_THIRTY_DAYS_SECONDS = 30 * 24 * 60 * 60  # 2_592_000


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


def _is_private_host(host: str) -> bool:
    """True if host is a private/loopback IP, reserved pseudo-TLD, or bare hostname."""
    # IPv6 literals arrive in [bracketed] form from authority parsing.
    candidate = host.strip("[]")
    try:
        ip = ipaddress.ip_address(candidate)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass

    lowered = host.lower()
    for suffix in _RESERVED_PSEUDO_TLDS:
        if lowered.endswith(suffix):
            return True

    extracted = tldextract.extract(host)
    if extracted.suffix == "":
        return True
    return False


def analyze_alt_svc_suspicious(value: str, target_hostname: str) -> List[str]:
    """
    Run all three passive analyzers against an Alt-Svc value.

    Returns a list of finding IDs (subset of WCP_ALT_SVC_CROSS_DOMAIN,
    WCP_ALT_SVC_PRIVATE_HOST, WCP_ALT_SVC_EXCESSIVE_PERSISTENCE).
    Each finding emits at most once even when multiple entries qualify.
    """
    findings: List[str] = []
    entries = parse_alt_svc(value)
    if not entries:
        return findings

    target_domain = tldextract.extract(target_hostname).registered_domain.lower()

    cross_domain = False
    private_host = False
    excessive = False

    for entry in entries:
        if entry.host:
            entry_domain = tldextract.extract(entry.host).registered_domain.lower()
            if (
                entry_domain
                and target_domain
                and entry_domain != target_domain
                and entry.host.lower() != target_hostname.lower()
            ):
                cross_domain = True
            if _is_private_host(entry.host):
                private_host = True
        if entry.ma is not None and entry.ma > _THIRTY_DAYS_SECONDS and entry.persist:
            excessive = True

    if cross_domain:
        findings.append("WCP_ALT_SVC_CROSS_DOMAIN")
    if private_host:
        findings.append("WCP_ALT_SVC_PRIVATE_HOST")
    if excessive:
        findings.append("WCP_ALT_SVC_EXCESSIVE_PERSISTENCE")

    return findings
