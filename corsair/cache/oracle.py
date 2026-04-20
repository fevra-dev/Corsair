"""
Cache oracle: CDN fingerprinting, cache status detection, and buster validation.

The oracle establishes caching behavior for a target URL before any
active probing begins. It determines which CDN is present, whether
responses are cached, and how to safely isolate probe requests.
"""

import asyncio
import uuid
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

import httpx


class CacheStatus(Enum):
    HIT = auto()
    MISS = auto()
    UNKNOWN = auto()


@dataclass
class CacheOracle:
    url: str
    is_cached: bool = False
    cdn_fingerprint: Optional[str] = None
    status_header: Optional[str] = None
    buster_strategy: str = "query_param"
    buster_param: str = "_cb"
    query_string_keyed: Optional[bool] = None
    age_increments: bool = False
    cache_control: Optional[str] = None
    vary_header: Optional[str] = None
    akamai_cache_key: Optional[str] = None


CDN_STATUS_HEADERS: dict[str, list[str]] = {
    "cloudflare": ["cf-cache-status"],
    "akamai": ["x-cache", "x-check-cacheable"],
    "fastly": ["x-cache", "x-cache-hits"],
    "varnish": ["x-varnish", "x-cache"],
    "nginx": ["x-cache-status"],
    "cloudfront": ["x-cache"],
    "generic": ["x-cache", "age"],
}

HIT_PATTERNS: dict[str, list[str]] = {
    "cf-cache-status": ["HIT"],
    "x-cache": ["HIT", "TCP_HIT", "TCP_MEM_HIT", "TCP_REFRESH_HIT"],
    "x-cache-status": ["HIT"],
    "x-check-cacheable": ["YES"],
}

MISS_PATTERNS: dict[str, list[str]] = {
    "cf-cache-status": ["BYPASS", "DYNAMIC", "MISS", "EXPIRED"],
    "x-cache": ["MISS", "BYPASS", "EXPIRED"],
    "x-cache-status": ["MISS", "BYPASS"],
}


def fingerprint_cdn(headers: dict[str, str]) -> Optional[str]:
    h = {k.lower(): v.lower() for k, v in headers.items()}

    if "cf-ray" in h or "cf-cache-status" in h:
        return "cloudflare"
    if "x-cache" in h and "akamai" in h.get("server", ""):
        return "akamai"
    if "x-check-cacheable" in h:
        return "akamai"
    if "x-served-by" in h or "x-cache-hits" in h:
        return "fastly"
    if "x-varnish" in h:
        return "varnish"
    if "x-amz-cf-id" in h or "x-amz-cf-pop" in h:
        return "cloudfront"
    if "x-cache-status" in h:
        return "nginx"
    if "via" in h:
        return "generic"
    return None


def read_cache_status(headers: dict[str, str], cdn: Optional[str]) -> CacheStatus:
    h = {k.lower(): v for k, v in headers.items()}
    check_headers = CDN_STATUS_HEADERS.get(cdn or "generic", ["x-cache", "age"])

    for hname in check_headers:
        val = h.get(hname, "").upper()
        if not val:
            continue
        for pattern in HIT_PATTERNS.get(hname, []):
            if val.startswith(pattern):
                return CacheStatus.HIT
        for pattern in MISS_PATTERNS.get(hname, []):
            if val.startswith(pattern):
                return CacheStatus.MISS

    xvarnish = h.get("x-varnish", "")
    if xvarnish and len(xvarnish.strip().split()) == 2:
        return CacheStatus.HIT
    if xvarnish and len(xvarnish.strip().split()) == 1:
        return CacheStatus.MISS

    age = h.get("age", "0")
    try:
        if int(age) > 0:
            return CacheStatus.HIT
    except ValueError:
        pass

    return CacheStatus.UNKNOWN


def make_buster() -> str:
    return uuid.uuid4().hex[:16]


def _akamai_qs_in_key(cache_key: Optional[str]) -> Optional[bool]:
    """Return whether an Akamai X-Cache-Key encodes the query string.

    Akamai format: '/L/TTL/RULE/hostname/path?qs/_metadata'
    A '?' before the '/_' trailer means the query string is part of the key.
    Returns None when the input is empty or None (caller treats this as
    undetermined).
    """
    if not cache_key:
        return None
    url_part = cache_key.split("/_", 1)[0]
    return "?" in url_part


def _resolve_buster_from_vary(oracle: CacheOracle) -> None:
    """Pick a buster strategy from Vary when QS is NOT part of the cache key.

    Mutates oracle.buster_strategy and oracle.buster_param. Sets
    buster_strategy to 'none' when Vary offers no useful header.
    """
    vary = (oracle.vary_header or "").lower()
    if "accept-language" in vary:
        oracle.buster_strategy = "accept_language"
        oracle.buster_param = "Accept-Language"
    elif "user-agent" in vary:
        oracle.buster_strategy = "user_agent"
        oracle.buster_param = "User-Agent"
    else:
        oracle.buster_strategy = "none"


def build_buster_params(oracle: CacheOracle, buster: str) -> dict[str, str]:
    if oracle.buster_strategy == "query_param":
        return {oracle.buster_param: buster}
    return {}


def build_buster_headers(oracle: CacheOracle, buster: str) -> dict[str, str]:
    if oracle.buster_strategy == "accept_language":
        return {"Accept-Language": f"en-{buster[:4]},en;q=0.9"}
    if oracle.buster_strategy == "user_agent":
        return {"User-Agent": f"Corsair/0.2.0 ({buster})"}
    return {}


async def establish_oracle(
    client: "httpx.AsyncClient",
    url: str,
    timeout: float = 10.0,
) -> CacheOracle:
    oracle = CacheOracle(url=url)
    buster = make_buster()

    r1 = await client.get(
        url,
        params={oracle.buster_param: buster},
        timeout=timeout,
    )
    r1_headers = {k.lower(): v for k, v in r1.headers.items()}
    oracle.cdn_fingerprint = fingerprint_cdn(r1_headers)
    oracle.cache_control = r1_headers.get("cache-control")
    oracle.vary_header = r1_headers.get("vary")
    s1 = read_cache_status(r1_headers, oracle.cdn_fingerprint)

    if oracle.cdn_fingerprint == "akamai":
        try:
            r_pragma = await client.get(
                url,
                params={oracle.buster_param: make_buster()},
                headers={"Pragma": "akamai-x-get-cache-key, akamai-x-check-cacheable"},
                timeout=timeout,
            )
            cache_key_hdr = r_pragma.headers.get("x-cache-key")
            if cache_key_hdr:
                oracle.akamai_cache_key = cache_key_hdr
        except (httpx.HTTPError, httpx.TimeoutException):
            pass

    await asyncio.sleep(0.3)
    r2 = await client.get(
        url,
        params={oracle.buster_param: buster},
        timeout=timeout,
    )
    r2_headers = {k.lower(): v for k, v in r2.headers.items()}
    s2 = read_cache_status(r2_headers, oracle.cdn_fingerprint)

    age1 = int(r1_headers.get("age", "0") or 0)
    age2 = int(r2_headers.get("age", "0") or 0)
    oracle.age_increments = age2 > age1

    oracle.is_cached = (s2 == CacheStatus.HIT) or oracle.age_increments

    if s1 == CacheStatus.HIT:
        oracle.query_string_keyed = False
        _resolve_buster_from_vary(oracle)
    elif s1 == CacheStatus.MISS and s2 == CacheStatus.HIT:
        oracle.query_string_keyed = True
    elif s2 == CacheStatus.HIT and oracle.akamai_cache_key:
        akamai_keyed = _akamai_qs_in_key(oracle.akamai_cache_key)
        if akamai_keyed is True:
            oracle.query_string_keyed = True
        elif akamai_keyed is False:
            oracle.query_string_keyed = False
            _resolve_buster_from_vary(oracle)

    return oracle
