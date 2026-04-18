# Corsair v0.4.1 — Cache Module Hardening Design

**Status:** Approved
**Date:** 2026-04-18
**Release:** v0.4.1 (patch against v0.4.0)
**Scope:** Cache module correctness + spec-compliance fixes surfaced by audit
**Related docs:**
- `RESEARCH/2026-04-18-cache-module-security-audit.md` — source of priorities
- `docs/superpowers/specs/2026-04-15-web-cache-poisoning-design.md` — v0.4.0 parent spec
- `RESEARCH/Corsair HTTP3 Research - Claude.md` — Alt-Svc vector
- `RESEARCH/Web Cache Poisoning Detection Research - Gemini.md` — Set-Cookie angle

---

## 1. Executive Summary

v0.4.0 shipped clean against its declared scope. The follow-up audit surfaced two HIGH-severity detection gaps against the research corpus, two correctness bugs causing silent false negatives, and one spec-compliance gap in the abort mechanism. This release addresses all five priorities with in-place edits to the existing `corsair/cache/` module — no new modules, no CLI surface changes, no dependencies added.

Out of scope and deferred to v0.5.0: rate limiting, scanner User-Agent, narrowed exception handler, module restructuring. CORS DAST (its own v0.5.0 brainstorm/spec/plan cycle) will be the natural consumer of any cache-module refactoring, so we hold structural changes until there's a second caller to motivate them.

---

## 2. Problem Statement

### 2.1 Detection gaps (HIGH)

**Alt-Svc reflection is a blind spot.** The HTTP/3 research identifies Alt-Svc cache poisoning as a HIGH-severity cross-protocol vector: X-Forwarded-Host reflected into `Alt-Svc` pins victim browsers to an attacker-controlled QUIC endpoint. `HEADER_CONTEXTS` in `reflect.py:22-28` does not include `alt-svc`, and there is no body-side fallback for response-header reflections, so the scan silently returns no finding.

**Set-Cookie reflection is under-classified.** Set-Cookie is bucketed as `other_header` → LOW via the generic `WCP_UNKEYED_HEADER_LOW` finding. The Gemini WCP research explicitly calls out Set-Cookie reflection as session-fixation-grade: a cached Set-Cookie from a poisoned response is delivered to every subsequent user.

### 2.2 Correctness bugs (false negatives)

**`is_cached` ignores age-increment evidence.** `oracle.py:176` reads `s2 == CacheStatus.HIT`. If `s2` is UNKNOWN but `age_increments` is True (already computed on lines 190-192), the target IS cached. CDNs that omit X-Cache headers cause the scanner to mark the target not-cached and skip all active probing.

**`query_string_keyed` defaults True on ambiguous oracle.** `oracle.py:32` defaults `query_string_keyed: bool = True`, only flipped False when `s1 == HIT`. When `s1 == UNKNOWN` (common on first request to CDNs that skip status headers on MISS), the scanner silently claims the QS is keyed and suppresses `WCP_NO_CACHE_KEY_QS`.

### 2.3 Spec-compliance gap

**Abort event is cooperative, not preemptive.** `auditor.py:128-165` uses `asyncio.gather`, which does not cancel tasks when `abort_event` is set. The v0.4.0 design spec claims "abort immediately on live poisoning," but up to 4 in-flight probes can complete after poisoning is confirmed. The Phase 3 requests are observation-only so they cannot cause further poisoning; the gap is spec-language compliance and ASAP-surfacing.

### 2.4 Hygiene (bundled cheap win)

**Akamai dead code.** `oracle.py:153-165` fires a Pragma probe on Akamai targets to retrieve `X-Cache-Key`, stores it in `oracle.akamai_cache_key`, and never reads it. We wire this into the query_string_keyed decision — on Akamai targets the cache key tells us authoritatively whether the QS is in the key, avoiding the "undetermined" bucket for the largest CDN segment.

---

## 3. Goals and Non-Goals

### Goals
1. Detect Alt-Svc reflection at HIGH severity with a dedicated finding
2. Detect Set-Cookie reflection at HIGH severity with a dedicated finding
3. Widen `is_cached` to honor age-increment evidence when cache-status is UNKNOWN
4. Make `query_string_keyed` conservative (`Optional[bool]`); emit INFO finding when undetermined
5. Wire Akamai `X-Cache-Key` into `query_string_keyed` resolution
6. Cancel pending probes preemptively when live poisoning is confirmed

### Non-goals
- Rate limiting / connection pool limits (v0.5.0)
- Scanner User-Agent identification (v0.5.0)
- Narrowed exception handling in `CacheAuditor.audit` (v0.5.0)
- Module structure refactoring — oracle split, cache_key module extraction (v0.5.0 if CORS DAST needs it)
- Live cache-poisoning confirmation across additional vectors (explicitly deferred per v0.4.0 spec)
- Path normalization, fat GET, HTTP/2 pseudo-header probes (explicitly deferred per v0.4.0 spec)

---

## 4. Architecture

### 4.1 Release framing

Patch release. Target: `v0.4.0 → v0.4.1`. No new modules. No CLI surface changes. No new dependencies. Python compatibility unchanged (3.9+).

### 4.2 Files touched

| File | Change summary |
|---|---|
| `corsair/cache/reflect.py` | Add `alt_svc_header` and `set_cookie_header` contexts; update `HEADER_CONTEXTS` and `CONTEXT_SEVERITY_ORDER` |
| `corsair/cache/probe.py` | Route new context ids to new finding ids in `CONTEXT_TO_SEVERITY` |
| `corsair/cache/findings.py` | Add `WCP_ALT_SVC_POISONING` (HIGH), `WCP_SET_COOKIE_POISONING` (HIGH), `WCP_CACHE_KEYING_UNDETERMINED` (INFO) |
| `corsair/cache/oracle.py` | `is_cached` honors age-increment; `query_string_keyed: Optional[bool]`; parse Akamai `X-Cache-Key` into authoritative signal |
| `corsair/cache/auditor.py` | Preemptive task cancellation on abort; emit undetermined finding when `query_string_keyed is None` |
| `tests/test_cache_*.py` | New tests per fix; all 135 existing tests stay green |
| `pyproject.toml` | Version bump `0.2.0` → `0.4.1` (align stale version) |
| `README.md` | v0.4.1 changelog entry |

### 4.3 Public API impact

`CacheOracle.query_string_keyed` changes from `bool` (default `True`) to `Optional[bool]` (default `None`). Single consumer: `auditor._passive_checks`. Grep-confirmed no external callers.

`CacheOracle.is_cached` semantics widen. Strictly more detection, no false positives added (see §7.3 for justification).

---

## 5. Detection Logic

### 5.1 New contexts in `reflect.py`

```python
HEADER_CONTEXTS = [
    ("content-security-policy", "csp_header"),
    ("location", "location_header"),
    ("access-control-allow-origin", "cors_header"),
    ("link", "link_header"),
    ("alt-svc", "alt_svc_header"),       # NEW
    ("set-cookie", "set_cookie_header"), # NEW (was: "other_header")
]
```

`CONTEXT_SEVERITY_ORDER` gets `alt_svc_header` and `set_cookie_header` inserted above `cors_header`. When multiple contexts fire simultaneously, Alt-Svc and Set-Cookie win over other HIGH contexts because their exploitation primitives (H3 pinning, session fixation) are more powerful.

### 5.2 Finding routing in `probe.py`

```python
CONTEXT_TO_SEVERITY = {
    "script_src": ("CRITICAL", "WCP_UNKEYED_HEADER_CRITICAL"),
    "csp_header":  ("CRITICAL", "WCP_UNKEYED_HEADER_CRITICAL"),
    "alt_svc_header":    ("HIGH", "WCP_ALT_SVC_POISONING"),      # NEW
    "set_cookie_header": ("HIGH", "WCP_SET_COOKIE_POISONING"),   # NEW
    "location_header": ("HIGH", "WCP_UNKEYED_HEADER_HIGH"),
    "link_href":       ("HIGH", "WCP_UNKEYED_HEADER_HIGH"),
    "link_header":     ("HIGH", "WCP_UNKEYED_HEADER_HIGH"),
    "meta_refresh":    ("HIGH", "WCP_UNKEYED_HEADER_HIGH"),
    "cors_header":     ("HIGH", "WCP_UNKEYED_HEADER_HIGH"),
    "js_variable":     ("HIGH", "WCP_UNKEYED_HEADER_HIGH"),
    "canonical_href":  ("MEDIUM", "WCP_UNKEYED_HEADER_MEDIUM"),
    "img_src":         ("MEDIUM", "WCP_UNKEYED_HEADER_MEDIUM"),
    "body_text":       ("LOW", "WCP_UNKEYED_HEADER_LOW"),
    "other_header":    ("LOW", "WCP_UNKEYED_HEADER_LOW"),
}
```

### 5.3 New findings in `findings.py`

**`WCP_ALT_SVC_POISONING` (HIGH)**
- Header: `Alt-Svc`
- Title: "Alt-Svc cache poisoning via unkeyed header"
- Description: "An unkeyed request header is reflected into the cached Alt-Svc response header. This allows an attacker to poison the cache with an attacker-controlled HTTP/3 endpoint, pinning every subsequent victim browser to the attacker's QUIC server for the Alt-Svc TTL. The attack exploits HTTP/2-to-HTTP/3 protocol upgrade to redirect clients transparently."
- Recommendation: "Add the reflected header to the cache key, or strip it at the CDN/proxy layer. Consider shortening Alt-Svc max-age for defense-in-depth."
- Compliance: OWASP A05, PCI-DSS 4.0 R6.2; CWE-444
- Reference: portswigger.net/research/practical-web-cache-poisoning

**`WCP_SET_COOKIE_POISONING` (HIGH)**
- Header: `Set-Cookie`
- Title: "Set-Cookie cache poisoning via unkeyed header"
- Description: "An unkeyed request header is reflected into the cached Set-Cookie response header. A cached Set-Cookie from a poisoned response is delivered to every subsequent user, enabling session fixation or cookie injection attacks."
- Recommendation: "Responses that set cookies must be keyed by whatever influences the cookie value, or cached as private. Strip reflected headers at the CDN/proxy layer."
- Compliance: OWASP A05, PCI-DSS 4.0 R6.2; CWE-444, CWE-384

**`WCP_CACHE_KEYING_UNDETERMINED` (INFO)**
- Header: `Cache-Control`
- Title: "Cache keying could not be determined"
- Description: "The scanner could not conclusively determine whether the query string is part of the cache key. This occurs when the CDN does not expose cache status headers on the first request and does not provide a cache-key inspection mechanism. Manual testing is recommended."
- Recommendation: "Manually verify whether the query string is part of the cache key."

### 5.4 `oracle.is_cached` — age-increment fallback

```python
# Before (oracle.py:176):
oracle.is_cached = s2 == CacheStatus.HIT

# After:
oracle.is_cached = (s2 == CacheStatus.HIT) or oracle.age_increments
```

`oracle.age_increments` is already computed on `oracle.py:190-192`. Change is one boolean OR.

### 5.5 `oracle.query_string_keyed` — conservative with Akamai authoritative signal

**Dataclass change:**
```python
@dataclass
class CacheOracle:
    # ...
    query_string_keyed: Optional[bool] = None   # was: bool = True
```

**Decision table inside `establish_oracle`:**

| `s1` | `s2` | Akamai `X-Cache-Key` | `query_string_keyed` | `buster_strategy` resolution |
|------|------|----------------------|----------------------|------------------------------|
| `HIT` | any | not consulted | `False` | Vary fallback (`accept_language` / `user_agent` / `none`) |
| `MISS` | `HIT` | not consulted | `True` | `query_param` (QS demonstrably isolates) |
| `UNKNOWN` | `HIT` | contains `?` | `True` | `query_param` (authoritative: QS is in key) |
| `UNKNOWN` | `HIT` | no `?` | `False` | Vary fallback (same logic as `s1=HIT` branch) |
| `UNKNOWN` | `HIT` | absent | `None` | `none` — active probing skipped |
| any | `MISS`/`UNKNOWN` | — | `None` | `none` — active probing skipped |

**Vary fallback is shared between two branches** (`s1=HIT` and Akamai-confirms-False). Extract into a helper so both paths call the same code:

```python
def _resolve_buster_from_vary(oracle: CacheOracle) -> None:
    """Pick a buster strategy when QS is NOT in the cache key."""
    vary = (oracle.vary_header or "").lower()
    if "accept-language" in vary:
        oracle.buster_strategy = "accept_language"
        oracle.buster_param = "Accept-Language"
    elif "user-agent" in vary:
        oracle.buster_strategy = "user_agent"
        oracle.buster_param = "User-Agent"
    else:
        oracle.buster_strategy = "none"
```

Call from both the existing `s1 == HIT` branch and the new Akamai-confirms-False branch.

**Akamai `X-Cache-Key` parser:**

```python
def _akamai_qs_in_key(cache_key: str) -> Optional[bool]:
    """
    Akamai X-Cache-Key format: '/L/TTL/RULE/hostname/path?qs/_metadata'
    Returns True if '?' appears in the URL portion (before /_), False otherwise.
    Returns None only if input is empty or malformed beyond recovery.
    """
    if not cache_key:
        return None
    url_part = cache_key.split("/_", 1)[0]
    return "?" in url_part
```

### 5.5.1 Active-probing gate (safety-critical)

Active probing sends canary values through the cache. If our buster does not actually isolate, the canary **poisons the live cache**. Gate active probing on three conditions, all of which must hold:

```python
should_run_active_probes = (
    oracle.is_cached
    and oracle.query_string_keyed is not None   # undetermined → bail
    and oracle.buster_strategy != "none"        # no isolation mechanism → bail
)
```

The middle predicate is new. When `query_string_keyed is None` we do not know whether the QS buster isolates, and we do not have a Vary-based fallback either. Probing in that state could inadvertently poison the target's live cache. We emit `WCP_CACHE_KEYING_UNDETERMINED` (INFO) instead and skip all active probes.

### 5.6 Auditor — preemptive abort (Python 3.9-compatible)

```python
async def _active_probes(self, client, oracle):
    findings: List[Finding] = []
    abort_event = asyncio.Event()
    semaphore = asyncio.Semaphore(self.max_concurrency)
    tasks: list[asyncio.Task] = []

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

    for header_name, value_template in PROBE_HEADERS:
        tasks.append(asyncio.create_task(limited_probe(header_name, value_template)))
    for cpdos_func in (probe_cpdos_oversize, probe_cpdos_malformed, probe_cpdos_method_override):
        tasks.append(asyncio.create_task(limited_cpdos(cpdos_func)))

    async def abort_watcher():
        await abort_event.wait()
        for t in tasks:
            if not t.done():
                t.cancel()

    watcher = asyncio.create_task(abort_watcher())
    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        watcher.cancel()

    for r in results:
        if isinstance(r, asyncio.CancelledError):
            continue
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

TaskGroup (3.11+) would be cleaner; we ship 3.9-compatible manual cancellation for now.

### 5.7 Undetermined finding emission in `_passive_checks`

```python
if oracle.query_string_keyed is False:
    finding = get_finding("WCP_NO_CACHE_KEY_QS")
    if finding:
        findings.append(finding)
elif oracle.query_string_keyed is None:
    finding = get_finding("WCP_CACHE_KEYING_UNDETERMINED")
    if finding:
        findings.append(finding)
# True → no finding (good case)
```

---

## 6. Data Flow

The overall flow is unchanged from v0.4.0. Only oracle establishment gains branches; only active probing gains preemptive cancellation.

```
CacheAuditor.audit(url, headers)
  │
  ▼
establish_oracle(client, url)
  │  1. GET with buster #1 → r1, s1, headers; fingerprint CDN
  │  2. if CDN == akamai → Pragma probe → X-Cache-Key into oracle.akamai_cache_key
  │  3. GET with buster #1 again → r2, s2
  │  4. Compute is_cached = (s2==HIT) OR age_increments
  │  5. Resolve query_string_keyed via decision table §5.5
  │
  ▼
_passive_checks(oracle, headers)
  │  - WCP_NOT_CACHED if not is_cached (early return)
  │  - WCP_CDN_DETECTED
  │  - WCP_NO_CACHE_KEY_QS              if query_string_keyed is False
  │  - WCP_CACHE_KEYING_UNDETERMINED    if query_string_keyed is None   ← NEW
  │  - WCP_NO_VARY_ORIGIN
  │  - WCP_CACHE_PUBLIC_SENSITIVE
  │  - WCP_PERMISSIVE_CACHE_CONTROL
  │
  ▼ (skip if not active, or not cached, or buster_strategy == "none",
      or query_string_keyed is None — see §5.5.1 safety gate)
_active_probes(client, oracle)
  │  - Spawn 19 tasks (16 reflection + 3 CPDoS) as asyncio.Tasks
  │  - abort_watcher concurrently awaits abort_event; cancels pending on set
  │  - gather(..., return_exceptions=True); filter CancelledError
  │  - For each confirmed_unkeyed result:
  │      Alt-Svc context    → emit WCP_ALT_SVC_POISONING        ← NEW
  │      Set-Cookie context → emit WCP_SET_COOKIE_POISONING     ← NEW
  │      else               → emit via CONTEXT_TO_SEVERITY map
  │
  ▼
return findings  (list[Finding])
```

---

## 7. Error Handling & Edge Cases

### 7.1 CancelledError propagation
Cancelled tasks raise `asyncio.CancelledError`; `gather(return_exceptions=True)` returns them as values. Filter at the result-loop level. The probe that set `abort_event` has already completed with its finding, so the user-visible result is unaffected.

### 7.2 Akamai edge cases
- **Missing X-Cache-Key header** — `akamai_cache_key` remains `None`; decision table resolves to undetermined
- **Malformed cache key** — `_akamai_qs_in_key` falls back to whole-string check; worst case classifies undetermined
- **Pragma probe network failure** — existing `try/except` in `oracle.py:153-165` handles this; no change required

### 7.3 `is_cached` widening — false-positive analysis
Concern: servers that send monotonically increasing `Age` without actually caching (e.g., proxy rewriting).

Mitigation: `age_increments` requires `age2 > age1` across two nearly-simultaneous requests. Proxies that rewrite `Age` statically send the same value. A proxy that rewrites to real elapsed time would still not be caching — active probing on such a target would detect no reflection because the buster isolates perfectly. Worst case: one extraneous `WCP_CDN_DETECTED` finding on a non-cached target. No false-positive reflection findings.

### 7.4 `query_string_keyed` type change impact
Grep confirms one consumer (`auditor._passive_checks` line 97). Updated as shown in §5.7. No other reads in the codebase.

### 7.5 Safety gate on undetermined keying
When `query_string_keyed is None` and `is_cached is True` (via age fallback), the target is cached but we cannot prove our buster isolates. Active probing in that state risks live cache poisoning. The gate in §5.5.1 prevents this. Trade-off: we miss reflection findings on a narrow class of non-Akamai CDNs that hide cache-status headers on first request. The emitted `WCP_CACHE_KEYING_UNDETERMINED` INFO finding communicates the gap and recommends manual testing.

### 7.6 Rollback
All changes are in-place. A single revert commit restores v0.4.0 cleanly. Per-file diffs are focused and review-friendly.

---

## 8. Testing Strategy

### 8.1 Unit tests (TDD per fix)

**`tests/test_cache_reflect.py`**
- `test_alt_svc_reflection_detected` — canary in `Alt-Svc: h3="attacker:443"` → context `alt_svc_header`
- `test_set_cookie_reflection_detected` — canary in `Set-Cookie: session=...` → context `set_cookie_header`
- `test_alt_svc_wins_over_lower_contexts` — canary in both `Alt-Svc` and body text → returns `alt_svc_header`
- `test_alt_svc_and_script_src_priority` — canary in both → `script_src` wins (CRITICAL > HIGH)
- `test_set_cookie_and_link_header_priority` — canary in both → `set_cookie_header` wins

**`tests/test_cache_oracle.py`**
- `test_is_cached_via_age_increment_when_status_unknown`
- `test_is_cached_false_when_age_static_and_status_unknown`
- `test_query_string_keyed_none_when_s1_unknown_non_akamai`
- `test_query_string_keyed_true_when_s1_miss_s2_hit`
- `test_query_string_keyed_false_when_s1_hit`
- `test_akamai_x_cache_key_with_query_string_confirms_keyed`
- `test_akamai_x_cache_key_without_query_string_confirms_unkeyed`
- `test_akamai_pragma_probe_failure_falls_through_to_undetermined`
- `test_akamai_qs_in_key_parser_unit` — direct test of `_akamai_qs_in_key`

**`tests/test_cache_probe.py`**
- `test_alt_svc_context_maps_to_alt_svc_poisoning_finding`
- `test_set_cookie_context_maps_to_set_cookie_poisoning_finding`

**`tests/test_cache_auditor_unit.py`**
- `test_abort_event_cancels_pending_probes` — inject a slow probe, set abort_event mid-run, assert the slow probe is cancelled not awaited to completion
- `test_emits_undetermined_finding_when_keying_unknown`
- `test_emits_no_cache_key_qs_only_when_definitively_false`
- `test_no_finding_when_query_string_keyed_is_true`
- `test_active_probes_skipped_when_query_string_keyed_is_none` — safety-gate regression test: oracle with `is_cached=True`, `query_string_keyed=None`, assert zero probe requests issued
- `test_akamai_confirms_false_uses_vary_fallback_buster` — Akamai target with `X-Cache-Key` lacking `?` and `Vary: Accept-Language` → `buster_strategy == "accept_language"`
- `test_akamai_confirms_false_no_vary_sets_buster_none` — Akamai target with `X-Cache-Key` lacking `?` and no useful Vary → `buster_strategy == "none"`, active probing skipped

### 8.2 Integration tests

Existing `tests/test_cache_auditor_live.py` (3 slow tests against cdnjs/httpbin) stays unchanged. No new live tests required for v0.4.1.

### 8.3 Regression bar

- All 135 existing tests must pass
- New tests: ~14 unit tests added
- `black` + `ruff` clean
- `pytest -m slow` still green

### 8.4 Coverage

No numeric coverage target. Each of the 5 priority items gets at least one failing-then-passing test per the project's TDD convention.

---

## 9. Release Checklist

- [ ] Branch `feature/cache-v041-hardening` created via superpowers:using-git-worktrees
- [ ] All 5 priorities implemented per §5
- [ ] All new unit tests pass (§8.1)
- [ ] All 135 existing tests pass
- [ ] `pyproject.toml` version → `0.4.1`
- [ ] README changelog entry
- [ ] `black` + `ruff` clean
- [ ] Live integration tests green against cdnjs/httpbin
- [ ] Commit history: one commit per priority for clean bisect
- [ ] PR or merge to main per superpowers:finishing-a-development-branch

---

## 10. Rollout Plan

Single-target release. No feature flag, no staged rollout — it's a bug-fix patch. If a regression appears after merge:
1. Revert the offending commit
2. Tag v0.4.2 with the revert
3. Add a regression test
4. Re-land the fix properly

---

## 11. Out of Scope for v0.4.1

Tracked for v0.5.0:

- **Scanner safety**: rate limiting, User-Agent identification, narrowed exception handling
- **Module structure**: oracle split, `cache_key.py` extraction (motivated by CORS DAST reuse)
- **CORS DAST**: separate brainstorm/spec/plan cycle; will reuse cache module primitives
- **HTTP/3 cross-protocol probing**: send actual H3 upgrade probes (currently detect Alt-Svc reflection only)

Tracked for v0.6.0+ per v0.4.0 parent spec:

- Path normalization (`//` vs `/`, URL encoding variants)
- Fat GET body poisoning
- HTTP/2 `:method`/`:path` pseudo-header poisoning
- Request smuggling (HTTP/1.1 / HTTP/2 desync)
