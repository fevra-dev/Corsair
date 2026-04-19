"""
Active canary injection protocol and CPDoS probes.

Implements the 3-phase canary injection protocol:
Phase 1: Origin baseline (send header with canary, check reflection)
Phase 2: Key isolation (same buster, no header, check if canary persists)
Phase 3: Negative correlation (clean request, verify no pollution)
"""

import asyncio
from dataclasses import dataclass
from typing import Optional

from .oracle import (
    CacheOracle,
    CacheStatus,
    build_buster_headers,
    build_buster_params,
    fingerprint_cdn,
    make_buster,
    read_cache_status,
)
from .reflect import detect_reflection


def _resolve_cache_status(response, oracle: CacheOracle) -> CacheStatus:
    """Read cache status, re-fingerprinting the CDN from the response if needed.

    The oracle may not have a cdn_fingerprint set (e.g. when the caller builds
    a CacheOracle directly, or when CDN headers appear only on probe responses).
    Falling back to fingerprinting the actual response ensures CDN-specific
    headers like cf-cache-status are honored.
    """
    headers = dict(response.headers)
    cdn = oracle.cdn_fingerprint or fingerprint_cdn(headers)
    return read_cache_status(headers, cdn)


@dataclass
class CanaryResult:
    header_name: str
    canary: str
    reflected_in_baseline: bool = False
    reflected_in_isolation: bool = False
    reflection_context: Optional[str] = None
    confirmed_unkeyed: bool = False
    severity: str = "NONE"
    finding_id: str = ""
    detail: str = ""


PROBE_HEADERS: list[tuple[str, str]] = [
    ("X-Forwarded-Host", "{canary}.corsair-canary.invalid"),
    ("X-Host", "{canary}.corsair-canary.invalid"),
    ("Forwarded", "host={canary}.corsair-canary.invalid"),
    ("X-Forwarded-Proto", "http-{canary}"),
    ("X-Forwarded-Port", "80{canary}"),
    ("X-Original-URL", "/{canary}"),
    ("X-Rewrite-URL", "/{canary}"),
    ("X-Override-URL", "/{canary}"),
    ("X-HTTP-Method-Override", "POST-{canary}"),
    ("X-Method-Override", "POST-{canary}"),
    ("X-Forwarded-For", "1.2.3.{canary}"),
    ("True-Client-IP", "1.2.3.{canary}"),
    ("CF-Connecting-IP", "1.2.3.{canary}"),
    ("X-Forwarded-Prefix", "/{canary}"),
    ("X-Forwarded-Path", "/{canary}"),
    ("X-Forwarded-Scheme", "http-{canary}"),
]


CONTEXT_TO_SEVERITY: dict[str, tuple[str, str]] = {
    "script_src": ("CRITICAL", "WCP_UNKEYED_HEADER_CRITICAL"),
    "csp_header": ("CRITICAL", "WCP_UNKEYED_HEADER_CRITICAL"),
    "alt_svc_header": ("HIGH", "WCP_ALT_SVC_POISONING"),
    "location_header": ("HIGH", "WCP_UNKEYED_HEADER_HIGH"),
    "link_href": ("HIGH", "WCP_UNKEYED_HEADER_HIGH"),
    "link_header": ("HIGH", "WCP_UNKEYED_HEADER_HIGH"),
    "meta_refresh": ("HIGH", "WCP_UNKEYED_HEADER_HIGH"),
    "cors_header": ("HIGH", "WCP_UNKEYED_HEADER_HIGH"),
    "js_variable": ("HIGH", "WCP_UNKEYED_HEADER_HIGH"),
    "canonical_href": ("MEDIUM", "WCP_UNKEYED_HEADER_MEDIUM"),
    "img_src": ("MEDIUM", "WCP_UNKEYED_HEADER_MEDIUM"),
    "body_text": ("LOW", "WCP_UNKEYED_HEADER_LOW"),
    "other_header": ("LOW", "WCP_UNKEYED_HEADER_LOW"),
}


def classify_finding(header_name: str, context: Optional[str]) -> tuple[str, str]:
    if context is None:
        return "INFO", "WCP_UNKEYED_HEADER_NO_REFLECT"
    return CONTEXT_TO_SEVERITY.get(context, ("LOW", "WCP_UNKEYED_HEADER_LOW"))


async def probe_single_header(
    client,
    oracle: CacheOracle,
    header_name: str,
    value_template: str,
    timeout: float = 10.0,
    abort_event: Optional[asyncio.Event] = None,
) -> CanaryResult:
    if oracle.buster_strategy == "none":
        return CanaryResult(
            header_name=header_name,
            canary="",
            detail="Skipped: no safe cache buster available for this target",
        )

    canary = make_buster()
    value = value_template.format(canary=canary)
    result = CanaryResult(header_name=header_name, canary=canary)

    buster = make_buster()
    buster_params = build_buster_params(oracle, buster)
    buster_headers = build_buster_headers(oracle, buster)

    # Phase 1: Origin Baseline
    r1 = await client.get(
        oracle.url,
        params={**buster_params},
        headers={**buster_headers, header_name: value},
        timeout=timeout,
    )
    reflected, context = detect_reflection(r1, canary)
    result.reflected_in_baseline = reflected
    result.reflection_context = context

    if not reflected:
        return result

    if abort_event and abort_event.is_set():
        return result

    # Phase 2: Key Isolation
    await asyncio.sleep(0.2)
    r2 = await client.get(
        oracle.url,
        params={**buster_params},
        headers={**buster_headers},
        timeout=timeout,
    )
    cache_status = _resolve_cache_status(r2, oracle)
    reflected2, _ = detect_reflection(r2, canary)
    result.reflected_in_isolation = reflected2

    if cache_status == CacheStatus.HIT and reflected2:
        result.confirmed_unkeyed = True

    if abort_event and abort_event.is_set():
        return result

    # Phase 3: Negative Correlation
    await asyncio.sleep(0.15)
    r3 = await client.get(oracle.url, timeout=timeout)
    reflected3, _ = detect_reflection(r3, canary)

    if reflected3:
        result.confirmed_unkeyed = True
        result.severity = "CRITICAL"
        result.finding_id = "WCP_LIVE_CACHE_POISONED"
        result.detail = (
            f"OPERATIONAL ALERT: Canary '{canary}' confirmed in clean (no-buster) "
            f"response. Live cache has been poisoned. Header: {header_name}: {value}"
        )
        if abort_event:
            abort_event.set()
        return result

    if result.confirmed_unkeyed:
        result.severity, result.finding_id = classify_finding(header_name, context)
        result.detail = f"Header {header_name} is unkeyed and reflected in {context} context"

    return result


async def probe_cpdos_oversize(
    client,
    oracle: CacheOracle,
    timeout: float = 10.0,
    abort_event: Optional[asyncio.Event] = None,
) -> CanaryResult:
    result = CanaryResult(header_name="X-Oversized-Header", canary="")

    if oracle.buster_strategy == "none":
        result.detail = "Skipped: no safe cache buster available"
        return result

    buster = make_buster()
    buster_params = build_buster_params(oracle, buster)
    buster_headers = build_buster_headers(oracle, buster)

    oversized_value = "A" * 8192

    # Phase 1: Send oversized header
    r1 = await client.get(
        oracle.url,
        params={**buster_params},
        headers={**buster_headers, "X-Oversized-Header": oversized_value},
        timeout=timeout,
    )

    if r1.status_code not in (400, 413, 431):
        return result

    if abort_event and abort_event.is_set():
        return result

    # Phase 2: Check if error is cached
    await asyncio.sleep(0.2)
    r2 = await client.get(
        oracle.url,
        params={**buster_params},
        headers={**buster_headers},
        timeout=timeout,
    )
    cache_status = _resolve_cache_status(r2, oracle)

    if cache_status == CacheStatus.HIT and r2.status_code in (400, 413, 431):
        result.confirmed_unkeyed = True
        result.severity = "HIGH"
        result.finding_id = "WCP_CPDOS_OVERSIZE"
        result.detail = f"Cached {r2.status_code} error from oversized header"

    # Phase 3: Negative correlation
    await asyncio.sleep(0.15)
    r3 = await client.get(oracle.url, timeout=timeout)
    if r3.status_code in (400, 413, 431):
        result.confirmed_unkeyed = True
        result.severity = "CRITICAL"
        result.finding_id = "WCP_LIVE_CACHE_POISONED"
        result.detail = "Live cache poisoned with error response from oversized header"
        if abort_event:
            abort_event.set()

    return result


async def probe_cpdos_malformed(
    client,
    oracle: CacheOracle,
    timeout: float = 10.0,
    abort_event: Optional[asyncio.Event] = None,
) -> CanaryResult:
    result = CanaryResult(header_name="X-Malformed-Header", canary="")

    if oracle.buster_strategy == "none":
        result.detail = "Skipped: no safe cache buster available"
        return result

    buster = make_buster()
    buster_params = build_buster_params(oracle, buster)
    buster_headers = build_buster_headers(oracle, buster)

    # Phase 1: Send malformed header
    try:
        r1 = await client.get(
            oracle.url,
            params={**buster_params},
            headers={**buster_headers, "X-Malformed-Header": "val\x00ue"},
            timeout=timeout,
        )
    except Exception:
        return result

    if r1.status_code != 400:
        return result

    if abort_event and abort_event.is_set():
        return result

    # Phase 2: Check if error is cached
    await asyncio.sleep(0.2)
    r2 = await client.get(
        oracle.url,
        params={**buster_params},
        headers={**buster_headers},
        timeout=timeout,
    )
    cache_status = _resolve_cache_status(r2, oracle)

    if cache_status == CacheStatus.HIT and r2.status_code == 400:
        result.confirmed_unkeyed = True
        result.severity = "HIGH"
        result.finding_id = "WCP_CPDOS_MALFORMED"
        result.detail = "Cached 400 error from malformed header"

    # Phase 3: Negative correlation
    await asyncio.sleep(0.15)
    r3 = await client.get(oracle.url, timeout=timeout)
    if r3.status_code == 400:
        result.confirmed_unkeyed = True
        result.severity = "CRITICAL"
        result.finding_id = "WCP_LIVE_CACHE_POISONED"
        result.detail = "Live cache poisoned with error response from malformed header"
        if abort_event:
            abort_event.set()

    return result


async def probe_cpdos_method_override(
    client,
    oracle: CacheOracle,
    timeout: float = 10.0,
    abort_event: Optional[asyncio.Event] = None,
) -> CanaryResult:
    result = CanaryResult(header_name="X-HTTP-Method-Override", canary="")

    if oracle.buster_strategy == "none":
        result.detail = "Skipped: no safe cache buster available"
        return result

    buster = make_buster()
    buster_params = build_buster_params(oracle, buster)
    buster_headers = build_buster_headers(oracle, buster)

    # Phase 1: GET with method override to POST
    r1 = await client.get(
        oracle.url,
        params={**buster_params},
        headers={**buster_headers, "X-HTTP-Method-Override": "POST"},
        timeout=timeout,
    )

    # Phase 1b: GET without override for comparison
    r1b = await client.get(
        oracle.url,
        params={**buster_params},
        headers={**buster_headers},
        timeout=timeout,
    )

    if r1.status_code == r1b.status_code and r1.text == r1b.text:
        return result

    if abort_event and abort_event.is_set():
        return result

    # Phase 2: Check if overridden response is cached for normal GET
    await asyncio.sleep(0.2)
    r2 = await client.get(
        oracle.url,
        params={**buster_params},
        headers={**buster_headers},
        timeout=timeout,
    )
    cache_status = _resolve_cache_status(r2, oracle)

    if cache_status == CacheStatus.HIT and (
        r2.status_code != r1b.status_code or r2.text != r1b.text
    ):
        result.confirmed_unkeyed = True
        result.severity = "MEDIUM"
        result.finding_id = "WCP_CPDOS_METHOD_OVERRIDE"
        result.detail = "Method override header causes cached alternate response"

    # Phase 3: Negative correlation
    await asyncio.sleep(0.15)
    r3 = await client.get(oracle.url, timeout=timeout)
    if r3.status_code != r1b.status_code:
        result.confirmed_unkeyed = True
        result.severity = "CRITICAL"
        result.finding_id = "WCP_LIVE_CACHE_POISONED"
        result.detail = "Live cache poisoned with method-overridden response"
        if abort_event:
            abort_event.set()

    return result
