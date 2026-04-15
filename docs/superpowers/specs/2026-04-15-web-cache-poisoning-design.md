# Web Cache Poisoning Detection - Design Specification

**Version:** 0.4.0
**Date:** 2026-04-15
**Status:** Approved

## Goal

Add a hybrid web cache poisoning detection module to Corsair that identifies vulnerable caching configurations through passive header analysis and active canary injection probing.

## Architecture

A new `corsair/cache/` module implements a three-phase detection pipeline: cache oracle establishment, passive header checks, and concurrent active canary probing. The module follows the same auditor pattern as `corsair/tls/`, integrating into `HeadScanner.scan_target()` as a post-analysis phase. No new dependencies -- everything uses httpx.

**Approach:** Sequential oracle + concurrent active probes. The oracle and passive checks run sequentially, then active probes run concurrently via `asyncio.gather()` with a semaphore limiting to 5 simultaneous probes.

**Scope (v0.4.0):** Unkeyed header reflection and CPDoS (Cache Poisoning Denial of Service). Path normalization poisoning, fat GET body poisoning, and HTTP/2 pseudo-header poisoning are deferred to future versions.

**Safety model:** Balanced. Fallback buster strategies (Accept-Language, User-Agent) when query string is unkeyed. Hard abort on all active probing if a canary leaks into a clean (no-buster) response.

---

## Module Structure

```
corsair/cache/
    __init__.py      - Exports CacheAuditor
    oracle.py        - Cache oracle: CDN fingerprinting, cache status detection, buster validation
    probe.py         - Active canary injection protocol with concurrent execution
    reflect.py       - Reflection detection: classifies canary location in response
    findings.py      - All 16 finding definitions (passive + active)
    auditor.py       - CacheAuditor orchestrator: oracle -> passive -> active pipeline
```

---

## Section 1: Cache Oracle (oracle.py)

### CacheOracle Dataclass

Fields:
- `url: str` - target URL
- `is_cached: bool` - whether target is behind a functioning cache
- `cdn_fingerprint: Optional[str]` - cloudflare, akamai, fastly, varnish, cloudfront, nginx, generic, or None
- `status_header: Optional[str]` - which header determined cache status
- `buster_strategy: str` - query_param (default), accept_language, user_agent, or none
- `buster_param: str` - cache buster key name (default: "_cb")
- `query_string_keyed: bool` - whether query string is part of cache key (default: True)
- `age_increments: bool` - secondary HIT confirmation
- `cache_control: Optional[str]` - raw Cache-Control value
- `vary_header: Optional[str]` - raw Vary value
- `akamai_cache_key: Optional[str]` - leaked via Pragma probe

### CDN Fingerprinting

Uses response headers from oracle requests. Detection rules:

- Cloudflare: `CF-Ray` or `CF-Cache-Status` present
- Akamai: `X-Cache` + `Server: AkamaiGHost`, or `X-Check-Cacheable` present
- Fastly: `X-Served-By` or `X-Cache-Hits` present
- Varnish: `X-Varnish` present
- CloudFront: `X-Amz-Cf-Id` or `X-Amz-Cf-Pop` present
- Nginx: `X-Cache-Status` present
- Generic: `Via` present

### Cache Status Detection

CDN-specific header parsing to determine HIT vs MISS:

- `CF-Cache-Status`: HIT values = HIT; MISS values = BYPASS, DYNAMIC, MISS
- `X-Cache`: HIT values = HIT, TCP_HIT, TCP_MEM_HIT, TCP_REFRESH_HIT; MISS values = MISS, BYPASS, EXPIRED
- `X-Cache-Status`: HIT = HIT
- `X-Varnish`: single integer = MISS, two integers = HIT
- `Age`: non-zero and incrementing between requests = HIT

### Oracle Establishment Protocol (2-3 requests)

1. Send GET with unique query param cache buster (`?_cb=<uuid_hex_16>`). Record response headers. Fingerprint CDN. Expected: MISS.
2. If CDN is Akamai, send a separate request with `Pragma: akamai-x-get-cache-key, akamai-x-check-cacheable`. Best-effort -- store leaked `X-Cache-Key` if returned.
3. Send GET with same buster as step 1. If HIT, target is cached.
4. If step 1 was already a HIT, the query string is unkeyed. Check `Vary` header for fallback buster candidates (Accept-Language, User-Agent). If no fallback exists, set `buster_strategy = "none"`.
5. Compare `Age` header between step 1 and step 3. If Age increments, set `age_increments = True`.

---

## Section 2: Passive Checks

Run immediately after oracle establishment using headers already fetched. Zero additional requests.

### Passive Finding Definitions

| ID | Severity | Condition |
|----|----------|-----------|
| `WCP_NOT_CACHED` | PASS | Oracle confirms no caching layer |
| `WCP_CDN_DETECTED` | INFO | CDN fingerprint identified |
| `WCP_PERMISSIVE_CACHE_CONTROL` | LOW | Cached target with max-age or s-maxage > 86400 and no no-store/private |
| `WCP_NO_VARY_ORIGIN` | MEDIUM | Cached target returns ACAO but Vary header does not include Origin |
| `WCP_CACHE_PUBLIC_SENSITIVE` | MEDIUM | Cache-Control: public on response that also sets Set-Cookie |
| `WCP_NO_CACHE_KEY_QS` | HIGH | Oracle detected query string is unkeyed |

### Logic

Passive checks examine `oracle.cache_control`, `oracle.vary_header`, and the pre-fetched response headers passed from `scanner.py`. The `WCP_NOT_CACHED` PASS finding is emitted when `oracle.is_cached` is False -- gives positive confirmation and causes active probing to be skipped.

---

## Section 3: Active Canary Probing (probe.py)

### Probe Headers (16 total, priority order)

URL generation (highest risk):
- `X-Forwarded-Host: {canary}.corsair-canary.invalid`
- `X-Host: {canary}.corsair-canary.invalid`
- `Forwarded: host={canary}.corsair-canary.invalid`

Protocol/port manipulation:
- `X-Forwarded-Proto: http-{canary}`
- `X-Forwarded-Port: 80{canary}`

Path override:
- `X-Original-URL: /{canary}`
- `X-Rewrite-URL: /{canary}`
- `X-Override-URL: /{canary}`

Method override (CPDoS vector):
- `X-HTTP-Method-Override: POST-{canary}`
- `X-Method-Override: POST-{canary}`

IP/source reflection:
- `X-Forwarded-For: 1.2.3.{canary}`
- `True-Client-IP: 1.2.3.{canary}`
- `CF-Connecting-IP: 1.2.3.{canary}`

Path prefix:
- `X-Forwarded-Prefix: /{canary}`
- `X-Forwarded-Path: /{canary}`

Canary domain uses `.corsair-canary.invalid` (RFC 2606 reserved TLD -- can never resolve).

### Canary Injection Protocol (3 phases per header)

Each probe uses a unique cache buster (separate from all other probes).

Phase 1 -- Origin Baseline: Send GET with probe header containing canary + cache buster. Call `detect_reflection()` on the response. If canary is not reflected, the application does not use this header -- stop probing this header.

Phase 2 -- Key Isolation: Send GET with same cache buster but without the probe header. If the response is a cache HIT and canary is still present, the header is unkeyed and reflected -- confirmed cache poisoning vulnerability.

Phase 3 -- Negative Correlation: Send GET to the live URL (no buster, no probe header). If canary appears, the live cache has been poisoned. Emit `WCP_LIVE_CACHE_POISONED` (CRITICAL) and cancel all remaining probes via cancellation event.

### Concurrency Model

- `asyncio.gather()` with `asyncio.Semaphore(max_concurrency)` (default 5)
- Each probe has its own unique cache buster -- no interference between parallel probes
- `asyncio.Event` for abort signal -- when negative correlation triggers, all probes check the event and exit early
- 200ms delay between phases within each probe (CDN propagation time)

### CPDoS Probes (3 types)

Different detection pattern -- checks for cached error responses rather than canary reflection:

- Oversized header: `X-Oversized-Header` with ~8KB value. Phase 1: send with buster, expect 400/413/431. Phase 2: send without header + same buster, check if error response was cached. Phase 3: negative correlation -- clean request to live URL to verify no pollution.
- Malformed header: Header with illegal characters. Phase 1: send with buster, expect 400. Phase 2: check if error cached. Phase 3: negative correlation.
- Method override: `X-HTTP-Method-Override: POST` on GET. Phase 1: send with buster, observe different content or 405. Phase 2: check if wrong content cached for GET. Phase 3: negative correlation.

### Request Budget

- Oracle: 2-3 requests
- Canary probes: 16 headers x 3 requests = 48 requests (worst case)
- CPDoS probes: 3 types x 3 requests = 9 requests
- Total: ~60 requests max
- With 5-way concurrency and 200ms phase delays: ~12-15 seconds

---

## Section 4: Reflection Detection (reflect.py)

### API

```python
def detect_reflection(
    response: httpx.Response, canary: str
) -> tuple[bool, Optional[str]]:
```

Returns (found, context_id). context_id is the most severe context if multiple matches.

### Reflection Contexts (severity order)

| Context ID | Location | Severity implication |
|------------|----------|---------------------|
| `script_src` | `<script src="...canary...">` | CRITICAL -- full XSS |
| `csp_header` | `Content-Security-Policy: ...canary...` | CRITICAL -- attacker whitelists domain |
| `location_header` | `Location: ...canary...` | HIGH -- cached open redirect |
| `link_href` | `<link href="...canary...">` | HIGH -- CSS injection |
| `meta_refresh` | `<meta http-equiv="refresh" content="url=...canary...">` | HIGH -- cached redirect |
| `cors_header` | `Access-Control-Allow-Origin: ...canary...` | HIGH -- CORS bypass |
| `js_variable` | `var x = "...canary..."` in inline script | HIGH -- DOM XSS |
| `canonical_href` | `<link rel="canonical" href="...canary...">` | MEDIUM -- SEO poisoning |
| `img_src` | `<img src="...canary...">` / `<iframe src="...canary...">` | MEDIUM -- content injection |
| `body_text` | Canary in visible page text | LOW -- info disclosure |
| `other_header` | Canary in non-security response header | LOW -- limited impact |

### Detection Order

1. Response headers first (fast string match): check Location, Content-Security-Policy, Access-Control-Allow-Origin, Link, Set-Cookie header values for canary substring.
2. Response body second (regex): compiled patterns for script src, link href, link rel canonical, meta http-equiv refresh, img/iframe/embed src, inline JS variable assignments, document.write, import statements.
3. Fallback: plain substring search on body text.

If canary appears in multiple contexts, the most severe (highest in table) is returned.

---

## Section 5: Finding Definitions (findings.py)

### Complete Registry (16 findings)

Passive (6):

| ID | Severity | Title |
|----|----------|-------|
| `WCP_NOT_CACHED` | PASS | Target is not cached |
| `WCP_CDN_DETECTED` | INFO | CDN/cache layer detected |
| `WCP_PERMISSIVE_CACHE_CONTROL` | LOW | Overly permissive cache TTL |
| `WCP_NO_VARY_ORIGIN` | MEDIUM | Missing Vary: Origin on CORS-enabled cached response |
| `WCP_CACHE_PUBLIC_SENSITIVE` | MEDIUM | Public caching of authenticated content |
| `WCP_NO_CACHE_KEY_QS` | HIGH | Query string excluded from cache key |

Active -- Unkeyed Header Reflection (7):

| ID | Severity | Trigger |
|----|----------|---------|
| `WCP_UNKEYED_HEADER_CRITICAL` | CRITICAL | Unkeyed header reflected in script_src or csp_header |
| `WCP_UNKEYED_HEADER_HIGH` | HIGH | Reflected in location_header, link_href, meta_refresh, cors_header, or js_variable |
| `WCP_UNKEYED_HEADER_MEDIUM` | MEDIUM | Reflected in canonical_href or img_src |
| `WCP_UNKEYED_HEADER_LOW` | LOW | Reflected in body_text or other_header |
| `WCP_LIVE_CACHE_POISONED` | CRITICAL | Canary found in clean response -- live cache was poisoned |
| `WCP_UNKEYED_HEADER_NO_REFLECT` | INFO | Header is unkeyed but not reflected |
| `WCP_PROBE_SKIPPED` | INFO | Active probing skipped -- no safe cache buster available |

Active -- CPDoS (3):

| ID | Severity | Trigger |
|----|----------|---------|
| `WCP_CPDOS_OVERSIZE` | HIGH | Oversized header causes cached error |
| `WCP_CPDOS_MALFORMED` | HIGH | Malformed header causes cached error |
| `WCP_CPDOS_METHOD_OVERRIDE` | MEDIUM | Method override causes cached alternate response |

### Common Fields

All findings use:
- `category`: HeaderCategory.CACHING
- `header`: "Cache-Control" (passive) or the specific probed header name (active)
- `compliance_mappings`: OWASP A05 (Security Misconfiguration), PCI-DSS 4.0 Req 6.2
- `cve_correlations`: CWE-525 (passive), CWE-444 (active)
- `reference_url`: Links to PortSwigger Web Cache Poisoning research

### Scoring Impact

Standard deductions: CRITICAL = -25, HIGH = -15, MEDIUM = -10, LOW = -5. A target with a confirmed critical reflection + CPDoS vulnerability loses 40 points.

---

## Section 6: CacheAuditor Orchestrator (auditor.py)

### Interface

```python
class CacheAuditor:
    def __init__(
        self,
        timeout: int = 10,
        max_concurrency: int = 5,
        active: bool = True,
    ):
        ...

    def audit(self, url: str, headers: dict[str, str]) -> list[Finding]:
        """Sync entry point. Internally runs async pipeline."""
        ...

    async def _audit_async(
        self, url: str, headers: dict[str, str]
    ) -> list[Finding]:
        """Async pipeline: oracle -> passive -> active."""
        ...
```

### Pipeline

1. Establish oracle -- call `establish_oracle()` with `httpx.AsyncClient` (2-3 requests)
2. Run passive checks -- analyze oracle results + pre-fetched headers (0 requests)
3. Active probing gate -- skip if `not self.active`, `not oracle.is_cached`, or `oracle.buster_strategy == "none"`
4. Run active probes -- concurrent canary injection + CPDoS via `asyncio.gather()` with semaphore
5. Classify and return -- map probe results to findings, merge with passive findings, return

### Async/Sync Bridge

`audit()` is sync (matches TLSAuditor interface). Internally calls `asyncio.run(self._audit_async(...))`. When Corsair moves to async, `_audit_async()` can be called directly.

---

## Section 7: Scanner Integration

### scanner.py Changes

Import CacheAuditor and call after TLS audit phase:

```python
from .cache.auditor import CacheAuditor

# In scan_target(), after TLS audit:
try:
    cache_auditor = CacheAuditor(timeout=self.timeout)
    cache_findings = cache_auditor.audit(final_url, headers)
    findings.extend(cache_findings)
except Exception as e:
    logger.error(f"Cache audit failed: {e}")
```

No availability check needed -- unlike TLS, cache module has no optional dependencies.

### CLI Changes

Add `--no-cache-probe` flag to `corsair scan` command. Passes `active=False` to CacheAuditor. Passive checks still run.

### HeadScanner Constructor

Add `cache_probe: bool = True` parameter. Stored as `self.cache_probe`, passed to `CacheAuditor(active=self.cache_probe)`.

---

## Section 8: Testing Strategy

### Unit Tests (mocked, fast)

`tests/test_cache_oracle.py` (~10 tests):
- CDN fingerprinting: one test per CDN (7 CDNs + no-CDN case)
- Cache status detection: HIT/MISS/UNKNOWN for each header format
- Buster fallback logic when query string is unkeyed
- Oracle establishment with mocked httpx responses

`tests/test_cache_reflect.py` (~12 tests):
- One test per reflection context (11 contexts)
- Canary in multiple contexts returns most severe
- Canary not found returns (False, None)
- Partial canary match does not trigger

`tests/test_cache_probe.py` (~8 tests):
- Confirmed positive: MISS -> HIT-with-canary -> clean-without-canary
- Header not reflected: early exit after phase 1
- Buster strategy "none": returns WCP_PROBE_SKIPPED
- Negative correlation abort: canary in clean response triggers WCP_LIVE_CACHE_POISONED
- CPDoS: cached error detection for each type

`tests/test_cache_findings.py` (~5 tests):
- All 16 findings have required fields
- Correct severity assignments
- Valid compliance mappings
- No duplicate IDs
- get_finding() returns deep copies

`tests/test_cache_auditor_unit.py` (~6 tests):
- Passive-only mode (active=False)
- Active probing skipped when is_cached=False
- Active probing skipped when buster_strategy="none"
- Finding accumulation from all phases
- Error handling (oracle failure, probe failure)

### Integration Tests

`tests/test_scanner_cache_integration.py` (~5 tests):
- scan_target() calls cache auditor and includes cache findings
- --no-cache-probe disables active probing
- Cache findings affect score calculation
- Cache findings appear in JSON/SARIF output

### Live Tests (@pytest.mark.slow)

`tests/test_cache_auditor_live.py` (~3 tests):
- CDN-cached static asset: verify oracle detects caching + CDN fingerprint
- Dynamic uncached endpoint: verify WCP_NOT_CACHED PASS finding
- No live poisoning tests -- mocked unit tests cover active probing logic

Total: ~35-40 tests

---

## References

- PortSwigger: Practical Web Cache Poisoning (James Kettle, 2018)
- PortSwigger: Web Cache Entanglement (James Kettle, 2020)
- CWE-444: Inconsistent Interpretation of HTTP Requests
- CWE-525: Information Exposure Through Browser Caching
- OWASP Top 10 2025: A05 Security Misconfiguration
- RFC 2606: Reserved Top-Level DNS Names (.invalid TLD)
- RFC 7234: HTTP/1.1 Caching
- RFC 7239: Forwarded HTTP Extension
