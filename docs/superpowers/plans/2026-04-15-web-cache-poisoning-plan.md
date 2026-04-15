# Web Cache Poisoning Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a hybrid web cache poisoning detection module (`corsair/cache/`) that detects vulnerable caching configurations through passive header analysis and active canary injection probing.

**Architecture:** Three-phase pipeline (oracle -> passive checks -> concurrent active probes) in a new `corsair/cache/` module mirroring the `corsair/tls/` auditor pattern. Integrates into `HeadScanner.scan_target()` as a post-analysis phase. No new dependencies.

**Tech Stack:** Python 3.9+, httpx (existing dep), asyncio (stdlib), re (stdlib), uuid (stdlib)

---

## File Structure

**Create:**
- `corsair/cache/__init__.py` -- module init, exports CacheAuditor
- `corsair/cache/oracle.py` -- CacheOracle dataclass, CDN fingerprinting, cache status detection, oracle establishment
- `corsair/cache/reflect.py` -- `detect_reflection()` function, regex patterns for security-sensitive contexts
- `corsair/cache/findings.py` -- 16 Finding definitions (passive + active + CPDoS)
- `corsair/cache/probe.py` -- canary injection protocol, CPDoS probes, concurrent execution
- `corsair/cache/auditor.py` -- CacheAuditor orchestrator class
- `tests/test_cache_oracle.py` -- oracle unit tests
- `tests/test_cache_reflect.py` -- reflection detection unit tests
- `tests/test_cache_findings.py` -- finding definition validation tests
- `tests/test_cache_probe.py` -- canary injection protocol tests
- `tests/test_cache_auditor_unit.py` -- auditor orchestration tests
- `tests/test_scanner_cache_integration.py` -- scanner integration tests

**Modify:**
- `corsair/scanner.py` -- add cache audit phase after TLS audit
- `corsair/cli.py` -- add `--no-cache-probe` flag

---

### Task 1: Module Init and Cache Oracle Dataclass

**Files:**
- Create: `corsair/cache/__init__.py`
- Create: `corsair/cache/oracle.py`
- Test: `tests/test_cache_oracle.py`

- [ ] **Step 1: Write failing tests for CDN fingerprinting**

```python
# tests/test_cache_oracle.py
"""Test cache oracle: CDN fingerprinting and cache status detection."""

from corsair.cache.oracle import (
    CacheOracle,
    CacheStatus,
    fingerprint_cdn,
    read_cache_status,
    make_buster,
)


class TestCDNFingerprinting:
    def test_cloudflare_via_cf_ray(self):
        headers = {"cf-ray": "abc123", "content-type": "text/html"}
        assert fingerprint_cdn(headers) == "cloudflare"

    def test_cloudflare_via_cf_cache_status(self):
        headers = {"cf-cache-status": "HIT"}
        assert fingerprint_cdn(headers) == "cloudflare"

    def test_akamai_via_server(self):
        headers = {"x-cache": "TCP_HIT", "server": "AkamaiGHost"}
        assert fingerprint_cdn(headers) == "akamai"

    def test_akamai_via_check_cacheable(self):
        headers = {"x-check-cacheable": "YES"}
        assert fingerprint_cdn(headers) == "akamai"

    def test_fastly_via_served_by(self):
        headers = {"x-served-by": "cache-lax1234"}
        assert fingerprint_cdn(headers) == "fastly"

    def test_fastly_via_cache_hits(self):
        headers = {"x-cache-hits": "3"}
        assert fingerprint_cdn(headers) == "fastly"

    def test_varnish(self):
        headers = {"x-varnish": "123456 789012"}
        assert fingerprint_cdn(headers) == "varnish"

    def test_cloudfront(self):
        headers = {"x-amz-cf-id": "abc123"}
        assert fingerprint_cdn(headers) == "cloudfront"

    def test_cloudfront_via_pop(self):
        headers = {"x-amz-cf-pop": "IAD89-C1"}
        assert fingerprint_cdn(headers) == "cloudfront"

    def test_nginx(self):
        headers = {"x-cache-status": "HIT"}
        assert fingerprint_cdn(headers) == "nginx"

    def test_generic_via(self):
        headers = {"via": "1.1 proxy.example.com"}
        assert fingerprint_cdn(headers) == "generic"

    def test_no_cdn(self):
        headers = {"content-type": "text/html", "server": "Apache"}
        assert fingerprint_cdn(headers) is None


class TestCacheStatusDetection:
    def test_cloudflare_hit(self):
        headers = {"cf-cache-status": "HIT"}
        assert read_cache_status(headers, "cloudflare") == CacheStatus.HIT

    def test_cloudflare_miss(self):
        headers = {"cf-cache-status": "MISS"}
        assert read_cache_status(headers, "cloudflare") == CacheStatus.MISS

    def test_cloudflare_dynamic(self):
        headers = {"cf-cache-status": "DYNAMIC"}
        assert read_cache_status(headers, "cloudflare") == CacheStatus.MISS

    def test_xcache_tcp_hit(self):
        headers = {"x-cache": "TCP_HIT"}
        assert read_cache_status(headers, "akamai") == CacheStatus.HIT

    def test_xcache_tcp_mem_hit(self):
        headers = {"x-cache": "TCP_MEM_HIT"}
        assert read_cache_status(headers, "akamai") == CacheStatus.HIT

    def test_xcache_miss(self):
        headers = {"x-cache": "MISS"}
        assert read_cache_status(headers, "fastly") == CacheStatus.MISS

    def test_varnish_hit_two_ids(self):
        headers = {"x-varnish": "123456 789012"}
        assert read_cache_status(headers, "varnish") == CacheStatus.HIT

    def test_varnish_miss_one_id(self):
        headers = {"x-varnish": "123456"}
        assert read_cache_status(headers, "varnish") == CacheStatus.MISS

    def test_age_nonzero_is_hit(self):
        headers = {"age": "120"}
        assert read_cache_status(headers, "generic") == CacheStatus.HIT

    def test_age_zero_is_unknown(self):
        headers = {"age": "0"}
        assert read_cache_status(headers, "generic") == CacheStatus.UNKNOWN

    def test_no_cache_headers_is_unknown(self):
        headers = {"content-type": "text/html"}
        assert read_cache_status(headers, None) == CacheStatus.UNKNOWN


class TestMakeBuster:
    def test_returns_string(self):
        assert isinstance(make_buster(), str)

    def test_unique_values(self):
        busters = {make_buster() for _ in range(100)}
        assert len(busters) == 100

    def test_length(self):
        assert len(make_buster()) == 16
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/fevra/Apps/HeadScan && python -m pytest tests/test_cache_oracle.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'corsair.cache'`

- [ ] **Step 3: Create module init**

```python
# corsair/cache/__init__.py
"""
Corsair Web Cache Poisoning Detection module.

Detects cache poisoning vulnerabilities through passive header analysis
and active canary injection probing. No optional dependencies required.
"""
```

- [ ] **Step 4: Implement oracle.py**

```python
# corsair/cache/oracle.py
"""
Cache oracle: CDN fingerprinting, cache status detection, and buster validation.

The oracle establishes caching behavior for a target URL before any
active probing begins. It determines which CDN is present, whether
responses are cached, and how to safely isolate probe requests.
"""

import uuid
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional


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
    query_string_keyed: bool = True
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


def build_buster_params(oracle: CacheOracle, buster: str) -> dict:
    if oracle.buster_strategy == "query_param":
        return {oracle.buster_param: buster}
    return {}


def build_buster_headers(oracle: CacheOracle, buster: str) -> dict:
    if oracle.buster_strategy == "accept_language":
        return {"Accept-Language": f"en-{buster[:4]},en;q=0.9"}
    if oracle.buster_strategy == "user_agent":
        return {"User-Agent": f"Corsair/0.2.0 ({buster})"}
    return {}


async def establish_oracle(
    client,
    url: str,
    timeout: float = 10.0,
) -> CacheOracle:
    import asyncio

    oracle = CacheOracle(url=url)
    buster = make_buster()

    r1 = await client.get(
        url,
        params={oracle.buster_param: buster},
        timeout=timeout,
    )
    r1_headers = dict(r1.headers)
    oracle.cdn_fingerprint = fingerprint_cdn(r1_headers)
    oracle.cache_control = r1_headers.get("cache-control") or r1_headers.get("Cache-Control")
    oracle.vary_header = r1_headers.get("vary") or r1_headers.get("Vary")
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
        except Exception:
            pass

    await asyncio.sleep(0.3)
    r2 = await client.get(
        url,
        params={oracle.buster_param: buster},
        timeout=timeout,
    )
    r2_headers = dict(r2.headers)
    s2 = read_cache_status(r2_headers, oracle.cdn_fingerprint)

    oracle.is_cached = s2 == CacheStatus.HIT

    if s1 == CacheStatus.HIT:
        oracle.query_string_keyed = False
        vary = (oracle.vary_header or "").lower()
        if "accept-language" in vary:
            oracle.buster_strategy = "accept_language"
            oracle.buster_param = "Accept-Language"
        elif "user-agent" in vary:
            oracle.buster_strategy = "user_agent"
            oracle.buster_param = "User-Agent"
        else:
            oracle.buster_strategy = "none"

    age1 = int(r1_headers.get("age", "0") or 0)
    age2 = int(r2_headers.get("age", "0") or 0)
    oracle.age_increments = age2 > age1

    return oracle
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/fevra/Apps/HeadScan && python -m pytest tests/test_cache_oracle.py -v`
Expected: All 26 tests PASS

- [ ] **Step 6: Commit**

```bash
cd /Users/fevra/Apps/HeadScan
git add corsair/cache/__init__.py corsair/cache/oracle.py tests/test_cache_oracle.py
git commit -m "feat(cache): add cache oracle with CDN fingerprinting and status detection"
```

---

### Task 2: Reflection Detection

**Files:**
- Create: `corsair/cache/reflect.py`
- Test: `tests/test_cache_reflect.py`

- [ ] **Step 1: Write failing tests for reflection detection**

```python
# tests/test_cache_reflect.py
"""Test reflection detection across security-sensitive contexts."""

from unittest.mock import MagicMock
from corsair.cache.reflect import detect_reflection


def _mock_response(body: str = "", headers: dict = None) -> MagicMock:
    resp = MagicMock()
    resp.text = body
    resp.headers = headers or {}
    return resp


class TestHeaderReflection:
    def test_location_header(self):
        resp = _mock_response(headers={"Location": "https://abc123.corsair-canary.invalid/login"})
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "location_header"

    def test_csp_header(self):
        resp = _mock_response(
            headers={"Content-Security-Policy": "default-src 'self' abc123.corsair-canary.invalid"}
        )
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "csp_header"

    def test_cors_header(self):
        resp = _mock_response(
            headers={"Access-Control-Allow-Origin": "https://abc123.corsair-canary.invalid"}
        )
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "cors_header"

    def test_no_reflection_in_headers(self):
        resp = _mock_response(headers={"Content-Type": "text/html", "Server": "nginx"})
        found, ctx = detect_reflection(resp, "abc123")
        assert found is False
        assert ctx is None


class TestBodyReflection:
    def test_script_src(self):
        body = '<html><script src="https://abc123.corsair-canary.invalid/app.js"></script></html>'
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "script_src"

    def test_link_href(self):
        body = '<link rel="stylesheet" href="https://abc123.corsair-canary.invalid/style.css">'
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "link_href"

    def test_canonical_href(self):
        body = '<link rel="canonical" href="https://abc123.corsair-canary.invalid/page">'
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "canonical_href"

    def test_meta_refresh(self):
        body = '<meta http-equiv="refresh" content="0;url=https://abc123.corsair-canary.invalid">'
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "meta_refresh"

    def test_img_src(self):
        body = '<img src="https://abc123.corsair-canary.invalid/image.png">'
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "img_src"

    def test_js_variable(self):
        body = '<script>var baseUrl = "https://abc123.corsair-canary.invalid";</script>'
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "js_variable"

    def test_body_text_fallback(self):
        body = "<html><body>Your IP is 1.2.3.abc123</body></html>"
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "body_text"

    def test_no_reflection(self):
        body = "<html><body>Hello World</body></html>"
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is False
        assert ctx is None

    def test_partial_canary_no_match(self):
        body = "<html><body>abc12 is not abc123</body></html>"
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123xyz")
        assert found is False
        assert ctx is None


class TestSeverityPriority:
    def test_script_src_beats_body_text(self):
        body = '<html><script src="https://abc123.corsair-canary.invalid/x.js"></script><body>abc123</body></html>'
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "script_src"

    def test_csp_header_beats_body(self):
        body = "<html><body>abc123 appears here</body></html>"
        resp = _mock_response(
            body=body,
            headers={"Content-Security-Policy": "script-src abc123.example.com"},
        )
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "csp_header"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/fevra/Apps/HeadScan && python -m pytest tests/test_cache_reflect.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'corsair.cache.reflect'`

- [ ] **Step 3: Implement reflect.py**

```python
# corsair/cache/reflect.py
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
        for pattern, context_id in BODY_CONTEXTS:
            for match in pattern.finditer(body):
                if canary in match.group(1):
                    found_contexts.append(context_id)
                    break

        if not found_contexts or all(
            c in ("other_header",) for c in found_contexts
        ):
            found_contexts.append("body_text")

    if not found_contexts:
        return False, None

    for ctx in CONTEXT_SEVERITY_ORDER:
        if ctx in found_contexts:
            return True, ctx

    return True, found_contexts[0]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/fevra/Apps/HeadScan && python -m pytest tests/test_cache_reflect.py -v`
Expected: All 15 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/fevra/Apps/HeadScan
git add corsair/cache/reflect.py tests/test_cache_reflect.py
git commit -m "feat(cache): add reflection detection for canary values in security contexts"
```

---

### Task 3: Finding Definitions

**Files:**
- Create: `corsair/cache/findings.py`
- Test: `tests/test_cache_findings.py`

- [ ] **Step 1: Write failing tests for finding definitions**

```python
# tests/test_cache_findings.py
"""Test cache poisoning finding definitions are complete and consistent."""

from corsair.models import HeaderCategory, Severity
from corsair.cache.findings import ALL_CACHE_FINDINGS, get_finding


class TestCacheFindingDefinitions:
    def test_all_findings_use_caching_category(self):
        for finding_id, finding in ALL_CACHE_FINDINGS.items():
            assert (
                finding.category == HeaderCategory.CACHING
            ), f"{finding_id} has category {finding.category}, expected CACHING"

    def test_all_findings_have_required_fields(self):
        for finding_id, finding in ALL_CACHE_FINDINGS.items():
            assert finding.header, f"{finding_id} missing header"
            assert finding.title, f"{finding_id} missing title"
            assert finding.description, f"{finding_id} missing description"
            assert finding.recommendation, f"{finding_id} missing recommendation"
            assert finding.reference_url, f"{finding_id} missing reference_url"

    def test_all_findings_have_valid_severity(self):
        for finding_id, finding in ALL_CACHE_FINDINGS.items():
            assert finding.severity in Severity, f"{finding_id} has invalid severity"

    def test_finding_count(self):
        assert len(ALL_CACHE_FINDINGS) == 16

    def test_no_duplicate_ids(self):
        ids = list(ALL_CACHE_FINDINGS.keys())
        assert len(ids) == len(set(ids))

    def test_get_finding_returns_copy(self):
        f1 = get_finding("WCP_NOT_CACHED")
        f2 = get_finding("WCP_NOT_CACHED")
        assert f1 is not f2
        assert f1.title == f2.title

    def test_get_finding_unknown_returns_none(self):
        assert get_finding("NONEXISTENT") is None

    def test_passive_findings_exist(self):
        passive_ids = [
            "WCP_NOT_CACHED",
            "WCP_CDN_DETECTED",
            "WCP_PERMISSIVE_CACHE_CONTROL",
            "WCP_NO_VARY_ORIGIN",
            "WCP_CACHE_PUBLIC_SENSITIVE",
            "WCP_NO_CACHE_KEY_QS",
        ]
        for fid in passive_ids:
            assert fid in ALL_CACHE_FINDINGS, f"Missing passive finding: {fid}"

    def test_active_findings_exist(self):
        active_ids = [
            "WCP_UNKEYED_HEADER_CRITICAL",
            "WCP_UNKEYED_HEADER_HIGH",
            "WCP_UNKEYED_HEADER_MEDIUM",
            "WCP_UNKEYED_HEADER_LOW",
            "WCP_LIVE_CACHE_POISONED",
            "WCP_UNKEYED_HEADER_NO_REFLECT",
            "WCP_PROBE_SKIPPED",
        ]
        for fid in active_ids:
            assert fid in ALL_CACHE_FINDINGS, f"Missing active finding: {fid}"

    def test_cpdos_findings_exist(self):
        cpdos_ids = [
            "WCP_CPDOS_OVERSIZE",
            "WCP_CPDOS_MALFORMED",
            "WCP_CPDOS_METHOD_OVERRIDE",
        ]
        for fid in cpdos_ids:
            assert fid in ALL_CACHE_FINDINGS, f"Missing CPDoS finding: {fid}"

    def test_severity_assignments(self):
        assert ALL_CACHE_FINDINGS["WCP_NOT_CACHED"].severity == Severity.PASS
        assert ALL_CACHE_FINDINGS["WCP_CDN_DETECTED"].severity == Severity.INFO
        assert ALL_CACHE_FINDINGS["WCP_PERMISSIVE_CACHE_CONTROL"].severity == Severity.LOW
        assert ALL_CACHE_FINDINGS["WCP_NO_VARY_ORIGIN"].severity == Severity.MEDIUM
        assert ALL_CACHE_FINDINGS["WCP_NO_CACHE_KEY_QS"].severity == Severity.HIGH
        assert ALL_CACHE_FINDINGS["WCP_UNKEYED_HEADER_CRITICAL"].severity == Severity.CRITICAL
        assert ALL_CACHE_FINDINGS["WCP_LIVE_CACHE_POISONED"].severity == Severity.CRITICAL
        assert ALL_CACHE_FINDINGS["WCP_CPDOS_OVERSIZE"].severity == Severity.HIGH

    def test_compliance_mappings_present(self):
        for fid in ["WCP_NO_VARY_ORIGIN", "WCP_UNKEYED_HEADER_CRITICAL", "WCP_CPDOS_OVERSIZE"]:
            finding = ALL_CACHE_FINDINGS[fid]
            assert len(finding.compliance_mappings) > 0, f"{fid} missing compliance mappings"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/fevra/Apps/HeadScan && python -m pytest tests/test_cache_findings.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'corsair.cache.findings'`

- [ ] **Step 3: Implement findings.py**

```python
# corsair/cache/findings.py
"""
Web cache poisoning finding definitions.

All cache-related findings that the CacheAuditor can produce.
Each finding uses the existing Finding dataclass with HeaderCategory.CACHING.
"""

import copy
from typing import Optional

from ..models import (
    ComplianceMapping,
    CVECorrelation,
    Finding,
    HeaderCategory,
    Severity,
)


def _compliance(framework: str, req_id: str, req_name: str, status: str = "FAIL"):
    return ComplianceMapping(
        framework=framework,
        requirement_id=req_id,
        requirement_name=req_name,
        status=status,
    )


def _cwe(cwe_id: str, desc: str):
    return CVECorrelation(
        cve_id=cwe_id,
        cvss_score=0.0,
        description=desc,
    )


_OWASP_A05 = _compliance("OWASP_TOP_10_2025", "A05", "Security Misconfiguration")
_PCI_6_2 = _compliance("PCI_DSS_4_0", "6.2", "Secure Development")
_CWE_525 = _cwe("CWE-525", "Information Exposure Through Browser Caching")
_CWE_444 = _cwe("CWE-444", "Inconsistent Interpretation of HTTP Requests")

_REF_URL = "https://portswigger.net/research/practical-web-cache-poisoning"

# -- Passive findings --------------------------------------------------------

_WCP_NOT_CACHED = Finding(
    header="Cache-Control",
    category=HeaderCategory.CACHING,
    severity=Severity.PASS,
    title="Target is not cached",
    description="No caching layer was detected. The target is not vulnerable to web cache poisoning.",
    current_value=None,
    recommendation="No action required.",
    example_value="N/A",
    reference_url=_REF_URL,
)

_WCP_CDN_DETECTED = Finding(
    header="Cache-Control",
    category=HeaderCategory.CACHING,
    severity=Severity.INFO,
    title="CDN/cache layer detected",
    description="A caching layer was detected in front of the target. This is informational and indicates cache poisoning testing is relevant.",
    current_value=None,
    recommendation="Ensure cache configuration follows security best practices.",
    example_value="Vary: Origin, Accept-Encoding",
    reference_url=_REF_URL,
)

_WCP_PERMISSIVE_CACHE_CONTROL = Finding(
    header="Cache-Control",
    category=HeaderCategory.CACHING,
    severity=Severity.LOW,
    title="Overly permissive cache TTL",
    description="The cached response has a very long TTL (max-age or s-maxage > 86400 seconds) without no-store or private directives. Long TTLs amplify the impact of any cache poisoning vulnerability.",
    current_value=None,
    recommendation="Reduce cache TTL or add Cache-Control: private for sensitive content.",
    example_value="Cache-Control: public, max-age=3600",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_525],
)

_WCP_NO_VARY_ORIGIN = Finding(
    header="Vary",
    category=HeaderCategory.CACHING,
    severity=Severity.MEDIUM,
    title="Missing Vary: Origin on CORS-enabled cached response",
    description="The response includes Access-Control-Allow-Origin but the Vary header does not include Origin. This allows cache poisoning where a CORS response for one origin is served to requests from a different origin.",
    current_value=None,
    recommendation="Add Origin to the Vary header when Access-Control-Allow-Origin varies by request.",
    example_value="Vary: Origin, Accept-Encoding",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_525],
)

_WCP_CACHE_PUBLIC_SENSITIVE = Finding(
    header="Cache-Control",
    category=HeaderCategory.CACHING,
    severity=Severity.MEDIUM,
    title="Public caching of authenticated content",
    description="The response has Cache-Control: public but also sets Set-Cookie, indicating authenticated or personalized content is being publicly cached. Other users may receive cached responses containing session data.",
    current_value=None,
    recommendation="Use Cache-Control: private or no-store for responses that set cookies.",
    example_value="Cache-Control: private, no-store",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_525],
)

_WCP_NO_CACHE_KEY_QS = Finding(
    header="Cache-Control",
    category=HeaderCategory.CACHING,
    severity=Severity.HIGH,
    title="Query string excluded from cache key",
    description="The cache does not include the query string in its cache key. Any reflected XSS via query parameters becomes stored XSS through the cache, affecting all users.",
    current_value=None,
    recommendation="Configure the cache to include the full query string in the cache key.",
    example_value="Cache key includes: method + host + path + query string",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_444],
)

# -- Active findings: unkeyed header reflection ------------------------------

_WCP_UNKEYED_HEADER_CRITICAL = Finding(
    header="X-Forwarded-Host",
    category=HeaderCategory.CACHING,
    severity=Severity.CRITICAL,
    title="Critical cache poisoning via unkeyed header",
    description="An unkeyed request header is reflected in a security-critical context (script import or CSP header) of a cached response. An attacker can poison the cache to serve malicious scripts or weaken security policies for all users.",
    current_value=None,
    recommendation="Add the reflected header to the cache key, or strip it at the CDN/proxy layer before it reaches the application.",
    example_value="Vary: X-Forwarded-Host",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_444],
)

_WCP_UNKEYED_HEADER_HIGH = Finding(
    header="X-Forwarded-Host",
    category=HeaderCategory.CACHING,
    severity=Severity.HIGH,
    title="High-risk cache poisoning via unkeyed header",
    description="An unkeyed request header is reflected in a high-risk context (redirect, stylesheet, CORS header, or JavaScript variable) of a cached response. An attacker can poison the cache to redirect users, inject CSS, or manipulate client-side logic.",
    current_value=None,
    recommendation="Add the reflected header to the cache key, or strip it at the CDN/proxy layer.",
    example_value="Vary: X-Forwarded-Host",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_444],
)

_WCP_UNKEYED_HEADER_MEDIUM = Finding(
    header="X-Forwarded-Host",
    category=HeaderCategory.CACHING,
    severity=Severity.MEDIUM,
    title="Moderate cache poisoning via unkeyed header",
    description="An unkeyed request header is reflected in a moderate-risk context (canonical link or image/iframe source) of a cached response. This enables SEO poisoning or content injection attacks.",
    current_value=None,
    recommendation="Add the reflected header to the cache key, or strip it at the CDN/proxy layer.",
    example_value="Vary: X-Forwarded-Host",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_444],
)

_WCP_UNKEYED_HEADER_LOW = Finding(
    header="X-Forwarded-Host",
    category=HeaderCategory.CACHING,
    severity=Severity.LOW,
    title="Low-risk cache poisoning via unkeyed header",
    description="An unkeyed request header is reflected in a low-risk context (body text or non-security header) of a cached response. The direct impact is limited but may indicate broader misconfiguration.",
    current_value=None,
    recommendation="Review whether the header needs to be processed by the application. If not, strip it at the proxy layer.",
    example_value="Vary: X-Forwarded-Host",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_444],
)

_WCP_LIVE_CACHE_POISONED = Finding(
    header="Cache-Control",
    category=HeaderCategory.CACHING,
    severity=Severity.CRITICAL,
    title="Live cache poisoned during scan",
    description="A canary value injected during active probing was found in a clean (no cache buster) response. The live cache was inadvertently poisoned. This confirms the target is critically vulnerable and the poisoned entry will expire based on the cache TTL.",
    current_value=None,
    recommendation="Immediately purge the affected cache entry. Add the reflected header to the cache key or strip it at the proxy layer.",
    example_value="Vary: X-Forwarded-Host",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_444],
)

_WCP_UNKEYED_HEADER_NO_REFLECT = Finding(
    header="X-Forwarded-Host",
    category=HeaderCategory.CACHING,
    severity=Severity.INFO,
    title="Unkeyed header detected (not reflected)",
    description="A request header is excluded from the cache key but its value is not currently reflected in the response. While not directly exploitable, changes to the application could introduce reflection in the future.",
    current_value=None,
    recommendation="Consider adding the header to the cache key or stripping it at the proxy layer as a defense-in-depth measure.",
    example_value="Vary: X-Forwarded-Host",
    reference_url=_REF_URL,
)

_WCP_PROBE_SKIPPED = Finding(
    header="Cache-Control",
    category=HeaderCategory.CACHING,
    severity=Severity.INFO,
    title="Active cache poisoning probing skipped",
    description="Active probing was skipped because no safe cache buster strategy could be established. The query string is not part of the cache key and no alternative buster was available via the Vary header.",
    current_value=None,
    recommendation="Manual testing recommended. Review cache key configuration.",
    example_value="N/A",
    reference_url=_REF_URL,
)

# -- Active findings: CPDoS --------------------------------------------------

_WCP_CPDOS_OVERSIZE = Finding(
    header="X-Oversized-Header",
    category=HeaderCategory.CACHING,
    severity=Severity.HIGH,
    title="CPDoS via oversized header",
    description="An oversized request header causes the origin to return an error response (400/413/431) that the cache stores and serves to subsequent users. This is a Cache Poisoning Denial of Service (CPDoS) vulnerability.",
    current_value=None,
    recommendation="Configure the cache to not store error responses, or increase the origin's header size limit.",
    example_value="Cache-Control: no-store (on error responses)",
    reference_url="https://cpdos.org/",
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_444],
)

_WCP_CPDOS_MALFORMED = Finding(
    header="X-Malformed-Header",
    category=HeaderCategory.CACHING,
    severity=Severity.HIGH,
    title="CPDoS via malformed header",
    description="A malformed request header causes the origin to return an error response that the cache stores and serves to subsequent users. This is a Cache Poisoning Denial of Service (CPDoS) vulnerability.",
    current_value=None,
    recommendation="Configure the cache to not store error responses. Review origin error handling.",
    example_value="Cache-Control: no-store (on error responses)",
    reference_url="https://cpdos.org/",
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_444],
)

_WCP_CPDOS_METHOD_OVERRIDE = Finding(
    header="X-HTTP-Method-Override",
    category=HeaderCategory.CACHING,
    severity=Severity.MEDIUM,
    title="CPDoS via method override",
    description="The X-HTTP-Method-Override header is unkeyed and causes the origin to process a GET request as a different method (e.g., POST). The resulting response is cached and served to subsequent GET requests, potentially exposing error pages or different content.",
    current_value=None,
    recommendation="Strip method override headers at the proxy layer, or add them to the cache key.",
    example_value="Vary: X-HTTP-Method-Override",
    reference_url="https://cpdos.org/",
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_444],
)


# -- Registry -----------------------------------------------------------------

ALL_CACHE_FINDINGS: dict[str, Finding] = {
    # Passive
    "WCP_NOT_CACHED": _WCP_NOT_CACHED,
    "WCP_CDN_DETECTED": _WCP_CDN_DETECTED,
    "WCP_PERMISSIVE_CACHE_CONTROL": _WCP_PERMISSIVE_CACHE_CONTROL,
    "WCP_NO_VARY_ORIGIN": _WCP_NO_VARY_ORIGIN,
    "WCP_CACHE_PUBLIC_SENSITIVE": _WCP_CACHE_PUBLIC_SENSITIVE,
    "WCP_NO_CACHE_KEY_QS": _WCP_NO_CACHE_KEY_QS,
    # Active - reflection
    "WCP_UNKEYED_HEADER_CRITICAL": _WCP_UNKEYED_HEADER_CRITICAL,
    "WCP_UNKEYED_HEADER_HIGH": _WCP_UNKEYED_HEADER_HIGH,
    "WCP_UNKEYED_HEADER_MEDIUM": _WCP_UNKEYED_HEADER_MEDIUM,
    "WCP_UNKEYED_HEADER_LOW": _WCP_UNKEYED_HEADER_LOW,
    "WCP_LIVE_CACHE_POISONED": _WCP_LIVE_CACHE_POISONED,
    "WCP_UNKEYED_HEADER_NO_REFLECT": _WCP_UNKEYED_HEADER_NO_REFLECT,
    "WCP_PROBE_SKIPPED": _WCP_PROBE_SKIPPED,
    # Active - CPDoS
    "WCP_CPDOS_OVERSIZE": _WCP_CPDOS_OVERSIZE,
    "WCP_CPDOS_MALFORMED": _WCP_CPDOS_MALFORMED,
    "WCP_CPDOS_METHOD_OVERRIDE": _WCP_CPDOS_METHOD_OVERRIDE,
}


def get_finding(finding_id: str) -> Optional[Finding]:
    template = ALL_CACHE_FINDINGS.get(finding_id)
    if template is None:
        return None
    return copy.deepcopy(template)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/fevra/Apps/HeadScan && python -m pytest tests/test_cache_findings.py -v`
Expected: All 11 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/fevra/Apps/HeadScan
git add corsair/cache/findings.py tests/test_cache_findings.py
git commit -m "feat(cache): add 16 cache poisoning finding definitions"
```

---

### Task 4: Canary Injection Probe

**Files:**
- Create: `corsair/cache/probe.py`
- Test: `tests/test_cache_probe.py`

- [ ] **Step 1: Write failing tests for probe logic**

```python
# tests/test_cache_probe.py
"""Test canary injection protocol and CPDoS probes."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from corsair.cache.oracle import CacheOracle, CacheStatus
from corsair.cache.probe import (
    PROBE_HEADERS,
    CanaryResult,
    probe_single_header,
    probe_cpdos_oversize,
    classify_finding,
)


def _mock_response(body: str = "", headers: dict = None, status_code: int = 200):
    resp = MagicMock()
    resp.text = body
    resp.headers = headers or {}
    resp.status_code = status_code
    return resp


class TestProbeHeaders:
    def test_probe_headers_count(self):
        assert len(PROBE_HEADERS) == 16

    def test_first_probe_is_x_forwarded_host(self):
        assert PROBE_HEADERS[0][0] == "X-Forwarded-Host"


class TestCanaryResult:
    def test_default_values(self):
        r = CanaryResult(header_name="X-Test", canary="abc123")
        assert r.reflected_in_baseline is False
        assert r.confirmed_unkeyed is False
        assert r.severity == "NONE"


class TestProbeSingleHeader:
    def test_not_reflected_exits_early(self):
        oracle = CacheOracle(url="https://example.com", is_cached=True)
        client = AsyncMock()
        client.get.return_value = _mock_response(body="<html>no canary</html>")

        result = asyncio.run(
            probe_single_header(
                client, oracle, "X-Forwarded-Host", "{canary}.corsair-canary.invalid"
            )
        )
        assert result.reflected_in_baseline is False
        assert result.confirmed_unkeyed is False
        assert client.get.call_count == 1

    def test_reflected_and_cached_confirms_unkeyed(self):
        oracle = CacheOracle(url="https://example.com", is_cached=True)
        client = AsyncMock()

        phase1_resp = _mock_response(
            body='<script src="https://testcanary.corsair-canary.invalid/x.js"></script>',
        )
        phase2_resp = _mock_response(
            body='<script src="https://testcanary.corsair-canary.invalid/x.js"></script>',
            headers={"cf-cache-status": "HIT"},
        )
        phase3_resp = _mock_response(body="<html>clean page</html>")

        client.get.side_effect = [phase1_resp, phase2_resp, phase3_resp]

        with patch("corsair.cache.probe.make_buster", return_value="testcanary"):
            result = asyncio.run(
                probe_single_header(
                    client,
                    oracle,
                    "X-Forwarded-Host",
                    "{canary}.corsair-canary.invalid",
                )
            )

        assert result.reflected_in_baseline is True
        assert result.confirmed_unkeyed is True
        assert result.reflection_context == "script_src"
        assert client.get.call_count == 3

    def test_buster_strategy_none_skips(self):
        oracle = CacheOracle(
            url="https://example.com", is_cached=True, buster_strategy="none"
        )
        client = AsyncMock()

        result = asyncio.run(
            probe_single_header(
                client, oracle, "X-Forwarded-Host", "{canary}.corsair-canary.invalid"
            )
        )
        assert "Skipped" in result.detail
        assert client.get.call_count == 0

    def test_live_cache_poisoned_on_phase3(self):
        oracle = CacheOracle(url="https://example.com", is_cached=True)
        client = AsyncMock()

        canary_body = '<script src="https://testcanary.corsair-canary.invalid/x.js"></script>'
        phase1_resp = _mock_response(body=canary_body)
        phase2_resp = _mock_response(body=canary_body, headers={"cf-cache-status": "HIT"})
        phase3_resp = _mock_response(body=canary_body)

        client.get.side_effect = [phase1_resp, phase2_resp, phase3_resp]

        with patch("corsair.cache.probe.make_buster", return_value="testcanary"):
            result = asyncio.run(
                probe_single_header(
                    client,
                    oracle,
                    "X-Forwarded-Host",
                    "{canary}.corsair-canary.invalid",
                )
            )

        assert result.confirmed_unkeyed is True
        assert result.severity == "CRITICAL"
        assert result.finding_id == "WCP_LIVE_CACHE_POISONED"


class TestClassifyFinding:
    def test_script_src_is_critical(self):
        severity, finding_id = classify_finding("X-Forwarded-Host", "script_src")
        assert severity == "CRITICAL"
        assert finding_id == "WCP_UNKEYED_HEADER_CRITICAL"

    def test_csp_header_is_critical(self):
        severity, finding_id = classify_finding("X-Forwarded-Host", "csp_header")
        assert severity == "CRITICAL"
        assert finding_id == "WCP_UNKEYED_HEADER_CRITICAL"

    def test_location_header_is_high(self):
        severity, finding_id = classify_finding("X-Forwarded-Host", "location_header")
        assert severity == "HIGH"
        assert finding_id == "WCP_UNKEYED_HEADER_HIGH"

    def test_canonical_is_medium(self):
        severity, finding_id = classify_finding("X-Forwarded-Host", "canonical_href")
        assert severity == "MEDIUM"
        assert finding_id == "WCP_UNKEYED_HEADER_MEDIUM"

    def test_body_text_is_low(self):
        severity, finding_id = classify_finding("X-Forwarded-Host", "body_text")
        assert severity == "LOW"
        assert finding_id == "WCP_UNKEYED_HEADER_LOW"


class TestCPDoSOversize:
    def test_cached_error_confirms_cpdos(self):
        oracle = CacheOracle(url="https://example.com", is_cached=True)
        client = AsyncMock()

        phase1_resp = _mock_response(status_code=431, body="Request Header Fields Too Large")
        phase2_resp = _mock_response(
            status_code=431,
            body="Request Header Fields Too Large",
            headers={"cf-cache-status": "HIT"},
        )
        phase3_resp = _mock_response(status_code=200, body="<html>OK</html>")

        client.get.side_effect = [phase1_resp, phase2_resp, phase3_resp]

        result = asyncio.run(probe_cpdos_oversize(client, oracle))
        assert result.confirmed_unkeyed is True
        assert result.finding_id == "WCP_CPDOS_OVERSIZE"

    def test_no_error_response_no_cpdos(self):
        oracle = CacheOracle(url="https://example.com", is_cached=True)
        client = AsyncMock()

        client.get.return_value = _mock_response(status_code=200, body="OK")

        result = asyncio.run(probe_cpdos_oversize(client, oracle))
        assert result.confirmed_unkeyed is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/fevra/Apps/HeadScan && python -m pytest tests/test_cache_probe.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'corsair.cache.probe'`

- [ ] **Step 3: Implement probe.py**

```python
# corsair/cache/probe.py
"""
Active canary injection protocol and CPDoS probes.

Implements the 3-phase canary injection protocol:
Phase 1: Origin baseline (send header with canary, check reflection)
Phase 2: Key isolation (same buster, no header, check if canary persists)
Phase 3: Negative correlation (clean request, verify no pollution)
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional

from .oracle import (
    CacheOracle,
    CacheStatus,
    build_buster_headers,
    build_buster_params,
    make_buster,
    read_cache_status,
)
from .reflect import detect_reflection


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
    "location_header": ("HIGH", "WCP_UNKEYED_HEADER_HIGH"),
    "link_href": ("HIGH", "WCP_UNKEYED_HEADER_HIGH"),
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
    cache_status = read_cache_status(dict(r2.headers), oracle.cdn_fingerprint)
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
        result.detail = (
            f"Header {header_name} is unkeyed and reflected in {context} context"
        )

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
    cache_status = read_cache_status(dict(r2.headers), oracle.cdn_fingerprint)

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
    cache_status = read_cache_status(dict(r2.headers), oracle.cdn_fingerprint)

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
    cache_status = read_cache_status(dict(r2.headers), oracle.cdn_fingerprint)

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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/fevra/Apps/HeadScan && python -m pytest tests/test_cache_probe.py -v`
Expected: All 12 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/fevra/Apps/HeadScan
git add corsair/cache/probe.py tests/test_cache_probe.py
git commit -m "feat(cache): add canary injection protocol and CPDoS probes"
```

---

### Task 5: CacheAuditor Orchestrator

**Files:**
- Create: `corsair/cache/auditor.py`
- Modify: `corsair/cache/__init__.py`
- Test: `tests/test_cache_auditor_unit.py`

- [ ] **Step 1: Write failing tests for auditor orchestration**

```python
# tests/test_cache_auditor_unit.py
"""Test CacheAuditor orchestration logic."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from corsair.cache.auditor import CacheAuditor
from corsair.cache.oracle import CacheOracle
from corsair.models import Severity


def _mock_oracle(is_cached=True, cdn="cloudflare", buster_strategy="query_param"):
    return CacheOracle(
        url="https://example.com",
        is_cached=is_cached,
        cdn_fingerprint=cdn,
        buster_strategy=buster_strategy,
        cache_control="public, max-age=3600",
        vary_header="Accept-Encoding",
    )


class TestCacheAuditorPassive:
    def test_not_cached_returns_pass(self):
        auditor = CacheAuditor(active=False)
        with patch(
            "corsair.cache.auditor.establish_oracle",
            new_callable=lambda: lambda: AsyncMock(
                return_value=_mock_oracle(is_cached=False)
            ),
        ):
            findings = auditor.audit("https://example.com", {})
        pass_findings = [f for f in findings if f.severity == Severity.PASS]
        assert len(pass_findings) >= 1

    def test_cdn_detected_returns_info(self):
        auditor = CacheAuditor(active=False)
        with patch(
            "corsair.cache.auditor.establish_oracle",
            new_callable=lambda: lambda: AsyncMock(
                return_value=_mock_oracle(is_cached=True, cdn="cloudflare")
            ),
        ):
            findings = auditor.audit("https://example.com", {})
        info_findings = [f for f in findings if f.severity == Severity.INFO]
        assert any("CDN" in f.title for f in info_findings)

    def test_no_vary_origin_detected(self):
        auditor = CacheAuditor(active=False)
        oracle = _mock_oracle(is_cached=True)
        oracle.vary_header = "Accept-Encoding"
        headers = {"Access-Control-Allow-Origin": "https://example.com"}

        with patch(
            "corsair.cache.auditor.establish_oracle",
            new_callable=lambda: lambda: AsyncMock(return_value=oracle),
        ):
            findings = auditor.audit("https://example.com", headers)
        assert any(f.title == "Missing Vary: Origin on CORS-enabled cached response" for f in findings)

    def test_cache_public_sensitive_detected(self):
        auditor = CacheAuditor(active=False)
        oracle = _mock_oracle(is_cached=True)
        oracle.cache_control = "public, max-age=3600"
        headers = {"Set-Cookie": "session=abc123", "Cache-Control": "public, max-age=3600"}

        with patch(
            "corsair.cache.auditor.establish_oracle",
            new_callable=lambda: lambda: AsyncMock(return_value=oracle),
        ):
            findings = auditor.audit("https://example.com", headers)
        assert any("authenticated content" in f.title.lower() or "Public caching" in f.title for f in findings)


class TestCacheAuditorActiveSkip:
    def test_active_false_skips_probing(self):
        auditor = CacheAuditor(active=False)
        with patch(
            "corsair.cache.auditor.establish_oracle",
            new_callable=lambda: lambda: AsyncMock(
                return_value=_mock_oracle(is_cached=True)
            ),
        ):
            with patch("corsair.cache.auditor.probe_single_header") as mock_probe:
                findings = auditor.audit("https://example.com", {})
                mock_probe.assert_not_called()

    def test_not_cached_skips_probing(self):
        auditor = CacheAuditor(active=True)
        with patch(
            "corsair.cache.auditor.establish_oracle",
            new_callable=lambda: lambda: AsyncMock(
                return_value=_mock_oracle(is_cached=False)
            ),
        ):
            with patch("corsair.cache.auditor.probe_single_header") as mock_probe:
                findings = auditor.audit("https://example.com", {})
                mock_probe.assert_not_called()

    def test_no_buster_skips_probing(self):
        auditor = CacheAuditor(active=True)
        with patch(
            "corsair.cache.auditor.establish_oracle",
            new_callable=lambda: lambda: AsyncMock(
                return_value=_mock_oracle(is_cached=True, buster_strategy="none")
            ),
        ):
            with patch("corsair.cache.auditor.probe_single_header") as mock_probe:
                findings = auditor.audit("https://example.com", {})
                mock_probe.assert_not_called()
        assert any("skipped" in f.title.lower() or "Skipped" in f.title for f in findings)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/fevra/Apps/HeadScan && python -m pytest tests/test_cache_auditor_unit.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'corsair.cache.auditor'`

- [ ] **Step 3: Implement auditor.py**

```python
# corsair/cache/auditor.py
"""
CacheAuditor -- orchestrates cache poisoning detection for Corsair.

Main entry point: CacheAuditor.audit(url, headers) -> list[Finding]
Called by HeadScanner.scan_target() for all targets.
"""

import asyncio
import logging
import re
from typing import List

import httpx

from ..models import Finding
from .findings import get_finding
from .oracle import CacheOracle, establish_oracle
from .probe import (
    PROBE_HEADERS,
    CanaryResult,
    probe_cpdos_malformed,
    probe_cpdos_method_override,
    probe_cpdos_oversize,
    probe_single_header,
)

logger = logging.getLogger(__name__)


class CacheAuditor:
    def __init__(
        self,
        timeout: int = 10,
        max_concurrency: int = 5,
        active: bool = True,
    ):
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.active = active

    def audit(self, url: str, headers: dict[str, str]) -> List[Finding]:
        try:
            return asyncio.run(self._audit_async(url, headers))
        except Exception as e:
            logger.error(f"Cache audit failed for {url}: {e}")
            return []

    async def _audit_async(self, url: str, headers: dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        async with httpx.AsyncClient(
            follow_redirects=True,
            verify=True,
        ) as client:
            # Phase 1: Establish oracle
            oracle = await establish_oracle(client, url, timeout=self.timeout)
            logger.info(
                f"Cache oracle: cached={oracle.is_cached}, "
                f"cdn={oracle.cdn_fingerprint}, "
                f"buster={oracle.buster_strategy}"
            )

            # Phase 2: Passive checks
            findings.extend(self._passive_checks(oracle, headers))

            # Phase 3: Active probing
            if not self.active:
                return findings

            if not oracle.is_cached:
                return findings

            if oracle.buster_strategy == "none":
                skipped = get_finding("WCP_PROBE_SKIPPED")
                if skipped:
                    findings.append(skipped)
                return findings

            active_findings = await self._active_probes(client, oracle)
            findings.extend(active_findings)

        return findings

    def _passive_checks(
        self, oracle: CacheOracle, headers: dict[str, str]
    ) -> List[Finding]:
        findings: List[Finding] = []
        h = {k.lower(): v for k, v in headers.items()}

        if not oracle.is_cached:
            finding = get_finding("WCP_NOT_CACHED")
            if finding:
                findings.append(finding)
            return findings

        if oracle.cdn_fingerprint:
            finding = get_finding("WCP_CDN_DETECTED")
            if finding:
                finding.current_value = oracle.cdn_fingerprint
                findings.append(finding)

        # Check for unkeyed query string
        if not oracle.query_string_keyed:
            finding = get_finding("WCP_NO_CACHE_KEY_QS")
            if finding:
                findings.append(finding)

        # Check Vary: Origin
        acao = h.get("access-control-allow-origin")
        if acao and acao != "*":
            vary = (oracle.vary_header or "").lower()
            if "origin" not in vary:
                finding = get_finding("WCP_NO_VARY_ORIGIN")
                if finding:
                    finding.current_value = f"ACAO: {acao}, Vary: {oracle.vary_header or 'absent'}"
                    findings.append(finding)

        # Check Cache-Control: public with Set-Cookie
        cc = (oracle.cache_control or "").lower()
        if "public" in cc and "set-cookie" in h:
            finding = get_finding("WCP_CACHE_PUBLIC_SENSITIVE")
            if finding:
                finding.current_value = f"Cache-Control: {oracle.cache_control}"
                findings.append(finding)

        # Check permissive TTL
        if cc and "no-store" not in cc and "private" not in cc:
            max_age_match = re.search(r"(?:s-)?max-age=(\d+)", cc)
            if max_age_match and int(max_age_match.group(1)) > 86400:
                finding = get_finding("WCP_PERMISSIVE_CACHE_CONTROL")
                if finding:
                    finding.current_value = f"Cache-Control: {oracle.cache_control}"
                    findings.append(finding)

        return findings

    async def _active_probes(
        self, client: httpx.AsyncClient, oracle: CacheOracle
    ) -> List[Finding]:
        findings: List[Finding] = []
        abort_event = asyncio.Event()
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def limited_probe(header_name, value_template):
            async with semaphore:
                if abort_event.is_set():
                    return CanaryResult(header_name=header_name, canary="", detail="Aborted")
                return await probe_single_header(
                    client, oracle, header_name, value_template,
                    timeout=self.timeout, abort_event=abort_event,
                )

        async def limited_cpdos(probe_func):
            async with semaphore:
                if abort_event.is_set():
                    return CanaryResult(header_name="CPDoS", canary="", detail="Aborted")
                return await probe_func(
                    client, oracle, timeout=self.timeout, abort_event=abort_event,
                )

        tasks = []
        for header_name, value_template in PROBE_HEADERS:
            tasks.append(limited_probe(header_name, value_template))

        tasks.append(limited_cpdos(probe_cpdos_oversize))
        tasks.append(limited_cpdos(probe_cpdos_malformed))
        tasks.append(limited_cpdos(probe_cpdos_method_override))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception):
                logger.warning(f"Probe failed: {r}")
                continue
            if not r.confirmed_unkeyed:
                continue

            finding = get_finding(r.finding_id)
            if finding:
                finding.header = r.header_name
                finding.current_value = r.detail
                findings.append(finding)

        return findings
```

- [ ] **Step 4: Update module init to export CacheAuditor**

```python
# corsair/cache/__init__.py
"""
Corsair Web Cache Poisoning Detection module.

Detects cache poisoning vulnerabilities through passive header analysis
and active canary injection probing. No optional dependencies required.
"""

from .auditor import CacheAuditor

__all__ = ["CacheAuditor"]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/fevra/Apps/HeadScan && python -m pytest tests/test_cache_auditor_unit.py -v`
Expected: All 7 tests PASS

- [ ] **Step 6: Run all cache tests together**

Run: `cd /Users/fevra/Apps/HeadScan && python -m pytest tests/test_cache_oracle.py tests/test_cache_reflect.py tests/test_cache_findings.py tests/test_cache_probe.py tests/test_cache_auditor_unit.py -v`
Expected: All tests PASS

- [ ] **Step 7: Commit**

```bash
cd /Users/fevra/Apps/HeadScan
git add corsair/cache/auditor.py corsair/cache/__init__.py tests/test_cache_auditor_unit.py
git commit -m "feat(cache): add CacheAuditor orchestrator with passive checks and concurrent active probing"
```

---

### Task 6: Scanner Integration

**Files:**
- Modify: `corsair/scanner.py:152-165`
- Modify: `corsair/scanner.py:25-31`
- Test: `tests/test_scanner_cache_integration.py`

- [ ] **Step 1: Write failing tests for scanner integration**

```python
# tests/test_scanner_cache_integration.py
"""Test scanner integration with cache poisoning detection."""

from unittest.mock import patch, MagicMock

from corsair.scanner import HeadScanner
from corsair.models import Severity


class TestScannerCacheIntegration:
    def _mock_fetch_headers(self, url):
        return (
            200,
            {
                "Content-Type": "text/html",
                "Cache-Control": "public, max-age=3600",
                "Server": "nginx",
            },
            url,
            None,
        )

    def test_scan_target_calls_cache_auditor(self):
        scanner = HeadScanner()
        with patch.object(scanner, "_fetch_headers", side_effect=self._mock_fetch_headers):
            with patch("corsair.scanner.CacheAuditor") as MockAuditor:
                mock_instance = MockAuditor.return_value
                mock_instance.audit.return_value = []
                result = scanner.scan_target("https://example.com")
                mock_instance.audit.assert_called_once()

    def test_cache_findings_appear_in_results(self):
        from corsair.cache.findings import get_finding

        scanner = HeadScanner()
        cache_finding = get_finding("WCP_CDN_DETECTED")
        cache_finding.current_value = "cloudflare"

        with patch.object(scanner, "_fetch_headers", side_effect=self._mock_fetch_headers):
            with patch("corsair.scanner.CacheAuditor") as MockAuditor:
                mock_instance = MockAuditor.return_value
                mock_instance.audit.return_value = [cache_finding]
                result = scanner.scan_target("https://example.com")
                assert any("CDN" in f.title for f in result.findings)

    def test_cache_probe_false_disables_active(self):
        scanner = HeadScanner(cache_probe=False)
        with patch.object(scanner, "_fetch_headers", side_effect=self._mock_fetch_headers):
            with patch("corsair.scanner.CacheAuditor") as MockAuditor:
                mock_instance = MockAuditor.return_value
                mock_instance.audit.return_value = []
                result = scanner.scan_target("https://example.com")
                MockAuditor.assert_called_once_with(
                    timeout=scanner.timeout, active=False
                )

    def test_cache_audit_failure_does_not_crash(self):
        scanner = HeadScanner()
        with patch.object(scanner, "_fetch_headers", side_effect=self._mock_fetch_headers):
            with patch("corsair.scanner.CacheAuditor") as MockAuditor:
                mock_instance = MockAuditor.return_value
                mock_instance.audit.side_effect = Exception("boom")
                result = scanner.scan_target("https://example.com")
                assert result.error is None
                assert result.score >= 0

    def test_cache_findings_affect_score(self):
        from corsair.cache.findings import get_finding

        scanner = HeadScanner()
        critical_finding = get_finding("WCP_UNKEYED_HEADER_CRITICAL")

        with patch.object(scanner, "_fetch_headers", side_effect=self._mock_fetch_headers):
            with patch("corsair.scanner.CacheAuditor") as MockAuditor:
                mock_instance = MockAuditor.return_value
                mock_instance.audit.return_value = [critical_finding]
                result = scanner.scan_target("https://example.com")
                assert result.score < 100
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/fevra/Apps/HeadScan && python -m pytest tests/test_scanner_cache_integration.py -v`
Expected: FAIL (CacheAuditor not imported in scanner.py, cache_probe param not defined)

- [ ] **Step 3: Modify scanner.py -- add import**

Add to the imports section of `corsair/scanner.py` (after line 17, the TLS imports):

```python
from .cache.auditor import CacheAuditor
```

- [ ] **Step 4: Modify scanner.py -- add cache_probe parameter to __init__**

In `corsair/scanner.py`, modify the `__init__` method to add the `cache_probe` parameter. Change lines 25-45:

```python
    def __init__(
        self,
        timeout: int = 10,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        user_agent: str = "HeadScan/1.0 (Security Header Analyzer)",
        cache_probe: bool = True,
    ):
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self.cache_probe = cache_probe

        logger.info(
            f"Scanner initialized: timeout={timeout}s, "
            f"follow_redirects={follow_redirects}"
        )
```

- [ ] **Step 5: Modify scanner.py -- add cache audit phase**

In `corsair/scanner.py`, add the cache audit phase after the TLS audit block (after line 163 `logger.error(f"TLS audit failed: {e}")`). Insert before the `# Calculate score` comment:

```python
        # Cache poisoning audit
        try:
            cache_auditor = CacheAuditor(timeout=self.timeout, active=self.cache_probe)
            cache_findings = cache_auditor.audit(final_url, headers)
            findings.extend(cache_findings)
        except Exception as e:
            logger.error(f"Cache audit failed: {e}")
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd /Users/fevra/Apps/HeadScan && python -m pytest tests/test_scanner_cache_integration.py -v`
Expected: All 5 tests PASS

- [ ] **Step 7: Run full test suite to check for regressions**

Run: `cd /Users/fevra/Apps/HeadScan && python -m pytest tests/ -v --ignore=tests/test_tls_auditor.py -m "not slow"`
Expected: All tests PASS

- [ ] **Step 8: Commit**

```bash
cd /Users/fevra/Apps/HeadScan
git add corsair/scanner.py tests/test_scanner_cache_integration.py
git commit -m "feat(cache): integrate CacheAuditor into HeadScanner.scan_target()"
```

---

### Task 7: CLI Flag

**Files:**
- Modify: `corsair/cli.py:169-171`
- Modify: `corsair/cli.py:189-229`

- [ ] **Step 1: Add --no-cache-probe flag to scan command**

In `corsair/cli.py`, add the flag after the `--fingerprint/--no-fingerprint` line (line 170). Add this option:

```python
@click.option("--cache-probe/--no-cache-probe", default=True, help="Run cache poisoning detection")
```

- [ ] **Step 2: Add cache_probe parameter to scan function signature**

In the `scan()` function definition (around line 172), add `cache_probe: bool,` to the parameter list after `correlate_cve: bool,`.

- [ ] **Step 3: Pass cache_probe to HeadScanner**

In the scanner creation block (around line 224), change:

```python
    scanner = HeadScanner(
        timeout=timeout,
        follow_redirects=follow_redirects,
        max_redirects=max_redirects,
        user_agent=user_agent,
        cache_probe=cache_probe,
    )
```

- [ ] **Step 4: Run CLI smoke test**

Run: `cd /Users/fevra/Apps/HeadScan && python -m corsair.cli scan --help | grep cache`
Expected: Shows `--cache-probe / --no-cache-probe  Run cache poisoning detection`

- [ ] **Step 5: Commit**

```bash
cd /Users/fevra/Apps/HeadScan
git add corsair/cli.py
git commit -m "feat(cli): add --no-cache-probe flag to disable active cache probing"
```

---

### Task 8: Lint and Format

**Files:**
- All new and modified files

- [ ] **Step 1: Run black formatting**

Run: `cd /Users/fevra/Apps/HeadScan && python -m black corsair/cache/ tests/test_cache_*.py tests/test_scanner_cache_integration.py`
Expected: Files reformatted (or already formatted)

- [ ] **Step 2: Run ruff linting**

Run: `cd /Users/fevra/Apps/HeadScan && python -m ruff check corsair/cache/ tests/test_cache_*.py tests/test_scanner_cache_integration.py --fix`
Expected: No errors (or auto-fixed)

- [ ] **Step 3: Run full test suite**

Run: `cd /Users/fevra/Apps/HeadScan && python -m pytest tests/ -v --ignore=tests/test_tls_auditor.py -m "not slow"`
Expected: All tests PASS

- [ ] **Step 4: Commit if changes were made**

```bash
cd /Users/fevra/Apps/HeadScan
git add -u
git commit -m "style: apply black formatting and ruff fixes to cache module"
```

---

### Task 9: Live Integration Tests

**Files:**
- Create: `tests/test_cache_auditor_live.py`

- [ ] **Step 1: Write live tests**

```python
# tests/test_cache_auditor_live.py
"""Live integration tests for cache oracle against real targets.

These tests hit external services and are skipped by default.
Run with: pytest -m slow
"""

import pytest
from corsair.cache.auditor import CacheAuditor
from corsair.models import Severity


@pytest.mark.slow
class TestCacheAuditorLive:
    def test_cdn_cached_asset_detects_caching(self):
        """Test against a known CDN-cached static asset."""
        auditor = CacheAuditor(active=False)
        findings = auditor.audit("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js", {})
        cdn_findings = [f for f in findings if "CDN" in f.title]
        assert len(cdn_findings) >= 1
        assert cdn_findings[0].current_value is not None

    def test_uncached_endpoint_returns_pass(self):
        """Test against a dynamic endpoint unlikely to be cached."""
        auditor = CacheAuditor(active=False)
        findings = auditor.audit("https://httpbin.org/get", {})
        pass_findings = [f for f in findings if f.severity == Severity.PASS]
        has_pass_or_cdn = len(pass_findings) >= 1 or any(
            f.severity == Severity.INFO for f in findings
        )
        assert has_pass_or_cdn

    def test_oracle_does_not_crash_on_timeout(self):
        """Test that oracle handles slow targets gracefully."""
        auditor = CacheAuditor(timeout=3, active=False)
        findings = auditor.audit("https://httpbin.org/delay/1", {})
        assert isinstance(findings, list)
```

- [ ] **Step 2: Run live tests (optional)**

Run: `cd /Users/fevra/Apps/HeadScan && python -m pytest tests/test_cache_auditor_live.py -v -m slow`
Expected: All 3 tests PASS (requires network)

- [ ] **Step 3: Commit**

```bash
cd /Users/fevra/Apps/HeadScan
git add tests/test_cache_auditor_live.py
git commit -m "test(cache): add live integration tests for cache oracle"
```

---

### Task 10: README Update

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README features list**

In `README.md`, add a bullet to the Features section (after the TLS/SSL Auditing line):

```markdown
- **Web Cache Poisoning Detection** - CDN fingerprinting, unkeyed header probing, CPDoS detection, and cache oracle analysis
```

- [ ] **Step 2: Add Web Cache Poisoning section**

After the "TLS/SSL Auditing" section in `README.md`, add:

```markdown
## Web Cache Poisoning Detection

Corsair automatically tests for web cache poisoning vulnerabilities on all targets. 16 checks across three categories:

**Passive**: Missing `Vary: Origin`, public caching of authenticated content, unkeyed query strings, permissive cache TTLs

**Active (Canary Injection)**: Probes 16 unkeyed headers (X-Forwarded-Host, X-Original-URL, etc.) using a 3-phase canary injection protocol that safely detects whether injected values persist in cached responses

**CPDoS**: Tests for Cache Poisoning Denial of Service via oversized headers, malformed headers, and method override headers

Active probing uses cache busters to isolate test requests and includes a safety abort if any canary leaks into the live cache. Disable active probing with `--no-cache-probe`.
```

- [ ] **Step 3: Commit**

```bash
cd /Users/fevra/Apps/HeadScan
git add README.md
git commit -m "docs: add web cache poisoning detection to README"
```
