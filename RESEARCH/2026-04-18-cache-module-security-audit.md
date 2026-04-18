# Corsair Cache Module — Security Audit

**Date:** 2026-04-18
**Scope:** `corsair/cache/{oracle,reflect,probe,findings,auditor}.py` as merged in v0.4.0
**Cross-references:**
- `docs/superpowers/specs/2026-04-15-web-cache-poisoning-design.md` (approved design)
- `RESEARCH/Corsair HTTP3 Research - Claude.md` (HTTP/3 vector research)
- `RESEARCH/Web Cache Poisoning Detection Research - Gemini.md` (WCP methodology)
- `docs/superpowers/specs/2026-04-09-tls-auditor-design.md` (architecture parallels)

---

## Executive Summary

v0.4.0 shipped cleanly against its declared scope (unkeyed header reflection + CPDoS), but the audit surfaces two high-severity detection gaps against the research corpus, three correctness bugs that can cause silent false negatives, and four safety/hygiene items. No exploitable vulnerabilities in the scanner code itself; the issues are detection blind spots and edge-case correctness.

---

## 🔴 Critical: Missed Research Vectors

### 1. Alt-Svc reflection is a blind spot (HIGH)
**File:** `corsair/cache/reflect.py:22-28`

`HEADER_CONTEXTS` does not include `alt-svc`. The HTTP/3 research doc identifies this as a HIGH-severity cross-protocol vector: `X-Forwarded-Host` reflected into the `Alt-Svc` response header lets an attacker pin victim browsers to a malicious QUIC endpoint via the HTTP/3 upgrade mechanism.

**Current behavior:** canary reflected into `Alt-Svc` is **not detected at all**. The header-scan loop only inspects the five names in `HEADER_CONTEXTS`, and there is no body-side fallback for response headers. The scan silently returns no finding.

**Fix:**
- Add `("alt-svc", "alt_svc_header")` to `HEADER_CONTEXTS`
- Add `"alt_svc_header": ("HIGH", "WCP_UNKEYED_HEADER_HIGH")` to `probe.py:72-85` `CONTEXT_TO_SEVERITY`
- Insert `alt_svc_header` in `reflect.py:39-52` severity order above `cors_header`
- Optionally add a dedicated finding `WCP_ALT_SVC_POISONING` for H3 cross-protocol framing

### 2. Set-Cookie reflection severity is wrong (HIGH)
**File:** `corsair/cache/reflect.py:27`, `corsair/cache/probe.py:84`

`set-cookie` is bucketed as `other_header` → **LOW** severity. The Gemini WCP research explicitly calls out Set-Cookie reflection as session-fixation-grade: a cached `Set-Cookie` from a poisoned response is delivered to every subsequent user, enabling session theft or fixation.

**Fix:** give `set-cookie` its own context id `set_cookie_header` with HIGH severity and a dedicated finding message describing the session-fixation risk.

---

## 🟠 Correctness Bugs That Affect Detection

### 3. `is_cached` ignores age-increment evidence
**File:** `corsair/cache/oracle.py:176`, `:190-192`

```python
oracle.is_cached = s2 == CacheStatus.HIT
# ...
age1 = int(r1_headers.get("age", "0") or 0)
age2 = int(r2_headers.get("age", "0") or 0)
oracle.age_increments = age2 > age1
```

If `s2` reads UNKNOWN but `age_increments` is True, the target IS cached — `Age` monotonically increasing across requests is strong evidence of cache persistence. We compute `age_increments` and never use it.

**Impact:** False negatives on CDNs that omit `X-Cache` headers (e.g. some bespoke edge setups, certain Varnish configs without `X-Varnish`). Target is marked `not_cached`, passive WCP_CDN_DETECTED fires, but all active probing is skipped.

**Fix:** `oracle.is_cached = (s2 == CacheStatus.HIT) or oracle.age_increments`.

### 4. `query_string_keyed` defaults True on ambiguous oracle
**File:** `corsair/cache/oracle.py:32`, `:178-188`

`query_string_keyed: bool = True` defaults True. It's only flipped to False when `s1 == HIT`. When `s1 == UNKNOWN` (common on first request to CDNs that skip headers on MISS), we confidently claim the QS is keyed.

**Impact:** suppresses the `WCP_NO_CACHE_KEY_QS` HIGH finding on every target we can't cleanly fingerprint on request #1.

**Fix:** require positive evidence. Add `query_string_keyed: Optional[bool] = None` and only mark True when the oracle sees `s1=MISS + s2=HIT` (buster demonstrably isolates). Emit a separate informational finding when the keying status is undetermined.

### 5. Dead code: Akamai `x-cache-key` Pragma probe
**File:** `corsair/cache/oracle.py:153-165`, `:36`

Fires an extra request on Akamai targets to retrieve `X-Cache-Key`, stores it in `oracle.akamai_cache_key`, but nothing reads this field. `_passive_checks` never references it.

**Fix options:**
- Remove the probe and the field (YAGNI)
- **OR** use the cache key authoritatively: parse it to verify whether the query string is part of the key (the whole reason Akamai returns it). This would strengthen finding #4.

Recommend the latter — delete-or-use, don't leave dead code.

---

## 🟡 Scanner Hygiene / Safety

### 6. Abort event is cooperative, not preemptive
**File:** `corsair/cache/auditor.py:128-165`

When a probe triggers `WCP_LIVE_CACHE_POISONED` and sets `abort_event`, `asyncio.gather` does **not** cancel pending or in-flight tasks. Each probe checks `abort_event.is_set()` only between its own phases. Up to 4 in-flight probes can still complete their Phase 3 clean observation requests after poisoning is confirmed.

**Impact:** the Phase 3 GETs are observation-only (no canary, no malicious headers), so they cannot *cause* further poisoning. But this contradicts the design spec's "abort immediately on live poisoning" guarantee and wastes time when the scanner should be surfacing the finding ASAP.

**Fix:** switch from `asyncio.gather` to `asyncio.TaskGroup` (Python 3.11+) or track task handles and call `.cancel()` on the pending set when abort fires.

### 7. Broad `except Exception` in auditor entry point
**File:** `corsair/cache/auditor.py:42-46`

```python
def audit(self, url: str, headers: dict[str, str]) -> List[Finding]:
    try:
        return asyncio.run(self._audit_async(url, headers))
    except Exception as e:
        logger.error(f"Cache audit failed for {url}: {e}")
        return []
```

Swallows KeyError, AttributeError, TypeError — bugs that should surface as failures get silently logged.

**Fix:** narrow to `(httpx.HTTPError, httpx.TimeoutException, OSError, asyncio.TimeoutError)`. Let programming errors propagate in dev/test; keep them only for network-layer failures.

### 8. No rate-limiting / per-host connection cap
**File:** `corsair/cache/auditor.py:51-54`

`httpx.AsyncClient(follow_redirects=True, verify=True)` uses the default connection pool. `Semaphore(5)` × 3-4 requests per probe × 19 probes (16 reflection + 3 CPDoS) = up to 20 concurrent connections. On small origins this looks like low-grade DoS traffic.

**Fix:** pass `httpx.Limits(max_connections=self.max_concurrency, max_keepalive_connections=self.max_concurrency)`. Add `httpx.Timeout(connect=5.0, read=self.timeout, write=5.0, pool=5.0)` for fine-grained limits.

### 9. No scanner User-Agent
**File:** `corsair/cache/auditor.py:51-54`, `corsair/cache/oracle.py:142-147`

httpx defaults to `python-httpx/<version>`. Issues:
1. Bot-aware CDNs may serve different responses or block us, skewing findings
2. No ethical signal to site operators that this is security scanning

**Fix:** `headers={"User-Agent": "Corsair/0.4.1 (+https://github.com/<org>/corsair; security-scanner)"}`. Apply consistently in both AsyncClient construction (auditor) and the oracle's httpx requests.

---

## 🟢 Non-Issues (verified safe)

| Item | Verdict |
|---|---|
| Canary entropy (`uuid4().hex[:16]`, 64 bits) | Safe for any realistic scan volume |
| Header injection in `value_template.format()` | Safe — canary is hex-only, no CRLF possible |
| Regex ReDoS in `reflect.py` | Safe — bounded `[^"']+` char classes, no catastrophic backtracking |
| Canary TLD `.corsair-canary.invalid` | Safe — RFC 2606 reserved |
| Deferred: path normalization, fat GET, HTTP/2 pseudo-headers | Correctly deferred per design spec §5 |

---

## Recommended v0.4.1 Priority

1. **Alt-Svc reflection detection** — correctness + HTTP/3 research gap
2. **Set-Cookie severity elevation** — session-fixation gap
3. **`is_cached` age-fallback + conservative `query_string_keyed` default** — false-negative correctness
4. **Preemptive abort via TaskGroup** — spec compliance
5. **Akamai dead code: delete or wire into QS-keyed confirmation** — hygiene
6. **Rate-limiting + User-Agent + narrowed exception handler** — scanner safety

Items 1–4 are detection correctness and should land together. Items 5–6 are hygiene and could ship as a follow-up.

---

## Out of Scope for v0.4.1

Explicitly deferred per design spec §5 and beyond audit scope:
- Path normalization (`//` vs `/`, URL encoding variants)
- Fat GET body poisoning
- HTTP/2 `:method`/`:path` pseudo-header poisoning
- Request smuggling (HTTP/1.1 / HTTP/2 desync)
- Second-request protocol switching (HTTP/3 upgrade timing)

These remain tracked for v0.5.0 and beyond.
