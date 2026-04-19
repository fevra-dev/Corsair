# Cache Module v0.4.1 Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close five detection/correctness/spec-compliance gaps in Corsair's v0.4.0 Web Cache Poisoning module, releasing as v0.4.1.

**Architecture:** In-place edits to `corsair/cache/{reflect,probe,findings,oracle,auditor}.py`. No new modules, no CLI surface changes, no new dependencies. Python 3.9+ compatibility preserved.

**Tech Stack:** Python 3.9+, httpx (async), pytest, asyncio manual task cancellation (no TaskGroup — that's 3.11+).

**Spec:** `docs/superpowers/specs/2026-04-18-cache-module-v041-hardening-design.md`

---

## File Structure

**Files modified:**
- `corsair/cache/reflect.py` — two new header contexts (`alt_svc_header`, `set_cookie_header`)
- `corsair/cache/probe.py` — route new contexts in `CONTEXT_TO_SEVERITY`
- `corsair/cache/findings.py` — three new findings (Alt-Svc HIGH, Set-Cookie HIGH, Keying-Undetermined INFO)
- `corsair/cache/oracle.py` — age-fallback `is_cached`, Optional[bool] `query_string_keyed`, Akamai `X-Cache-Key` parser, `_resolve_buster_from_vary` helper
- `corsair/cache/auditor.py` — preemptive probe cancellation, undetermined-keying passive emission, safety gate on active probing
- `pyproject.toml` — version bump 0.2.0 → 0.4.1
- `README.md` — changelog entry

**Tests modified:**
- `tests/test_cache_reflect.py` — Alt-Svc + Set-Cookie detection, severity priority
- `tests/test_cache_findings.py` — finding count bump 16 → 19, new-finding assertions
- `tests/test_cache_probe.py` — context → finding-id mapping
- `tests/test_cache_oracle.py` — age fallback, Optional keyed, Akamai parser, Vary helper
- `tests/test_cache_auditor_unit.py` — safety gate, preemptive abort, undetermined emission

**Boundary rationale:** Each unit has one clear responsibility. `reflect.py` classifies response contexts. `findings.py` declares findings. `oracle.py` establishes cache state. `auditor.py` orchestrates. Task boundaries preserve these responsibilities — no task touches more than one concern at a time, except Task 8 which must bundle three coupled pieces to avoid leaving the code in a broken intermediate state.

---

### Task 1: Set up isolated worktree

**Files:**
- Worktree: `.worktrees/cache-v041-hardening`
- Branch: `feature/cache-v041-hardening`

- [ ] **Step 1: Verify `.worktrees/` is gitignored**

Run: `git check-ignore -q .worktrees && echo OK || echo NOT_IGNORED`
Expected: `OK`

If `NOT_IGNORED`: add `.worktrees/` to `.gitignore`, commit, then proceed. (Already confirmed in repo — commit `0b7063f` added it.)

- [ ] **Step 2: Create worktree on a new branch off main**

Run: `git worktree add .worktrees/cache-v041-hardening -b feature/cache-v041-hardening main`
Expected: `Preparing worktree (new branch 'feature/cache-v041-hardening')` + `HEAD is now at <sha> ...`

- [ ] **Step 3: Change working directory and install**

Run:
```bash
cd .worktrees/cache-v041-hardening
pip install -e '.[dev]'
```
Expected: `Successfully installed corsair-scan-0.2.0 ...` (version is stale — will be bumped in Task 10)

- [ ] **Step 4: Verify clean test baseline**

Run: `pytest -q`
Expected: `135 passed` (per memory #446) with no failures. If any test fails, stop and investigate — do not proceed.

- [ ] **Step 5: Verify lint baseline**

Run: `black --check . && ruff check .`
Expected: `All done!` from black, no diagnostics from ruff.

---

### Task 2: Add three new finding definitions

Register all three findings up front so later tasks can reference them. They are unreachable until their callers land — this is intentional and safe.

**Files:**
- Modify: `corsair/cache/findings.py` (add three `Finding` instances + registry entries)
- Test: `tests/test_cache_findings.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_cache_findings.py` (inside the existing `TestCacheFindingDefinitions` class):

```python
    def test_alt_svc_poisoning_finding_exists(self):
        f = get_finding("WCP_ALT_SVC_POISONING")
        assert f is not None
        assert f.severity == Severity.HIGH
        assert f.header == "Alt-Svc"
        assert "HTTP/3" in f.description or "QUIC" in f.description

    def test_set_cookie_poisoning_finding_exists(self):
        f = get_finding("WCP_SET_COOKIE_POISONING")
        assert f is not None
        assert f.severity == Severity.HIGH
        assert f.header == "Set-Cookie"
        assert "session" in f.description.lower() or "fixation" in f.description.lower()

    def test_cache_keying_undetermined_finding_exists(self):
        f = get_finding("WCP_CACHE_KEYING_UNDETERMINED")
        assert f is not None
        assert f.severity == Severity.INFO
        assert "manual" in f.recommendation.lower()
```

Update the existing count test:
```python
    def test_finding_count(self):
        assert len(ALL_CACHE_FINDINGS) == 19
```
(Was `16`.)

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_cache_findings.py -q`
Expected: 4 failures (3 missing findings + count mismatch).

- [ ] **Step 3: Add finding definitions**

Open `corsair/cache/findings.py`. After the `_WCP_LIVE_CACHE_POISONED` block (around line 196), insert:

```python
_WCP_ALT_SVC_POISONING = Finding(
    header="Alt-Svc",
    category=HeaderCategory.CACHING,
    severity=Severity.HIGH,
    title="Alt-Svc cache poisoning via unkeyed header",
    description=(
        "An unkeyed request header is reflected into the cached Alt-Svc response "
        "header. This allows an attacker to poison the cache with an attacker-"
        "controlled HTTP/3 endpoint, pinning every subsequent victim browser to "
        "the attacker's QUIC server for the Alt-Svc TTL. The attack exploits the "
        "HTTP/2-to-HTTP/3 protocol upgrade to redirect clients transparently."
    ),
    current_value=None,
    recommendation=(
        "Add the reflected header to the cache key, or strip it at the CDN/proxy "
        "layer. Consider shortening Alt-Svc max-age for defense-in-depth."
    ),
    example_value="Vary: X-Forwarded-Host",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_444],
)

_WCP_SET_COOKIE_POISONING = Finding(
    header="Set-Cookie",
    category=HeaderCategory.CACHING,
    severity=Severity.HIGH,
    title="Set-Cookie cache poisoning via unkeyed header",
    description=(
        "An unkeyed request header is reflected into the cached Set-Cookie "
        "response header. A cached Set-Cookie from a poisoned response is "
        "delivered to every subsequent user, enabling session fixation or "
        "cookie injection attacks."
    ),
    current_value=None,
    recommendation=(
        "Responses that set cookies must be keyed by whatever influences the "
        "cookie value, or cached as private. Strip reflected headers at the "
        "CDN/proxy layer."
    ),
    example_value="Cache-Control: private, no-store",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_444],
)

_WCP_CACHE_KEYING_UNDETERMINED = Finding(
    header="Cache-Control",
    category=HeaderCategory.CACHING,
    severity=Severity.INFO,
    title="Cache keying could not be determined",
    description=(
        "The scanner could not conclusively determine whether the query string "
        "is part of the cache key. This occurs when the CDN does not expose "
        "cache status headers on the first request and does not provide a "
        "cache-key inspection mechanism. Active probing was skipped to avoid "
        "inadvertently poisoning the live cache."
    ),
    current_value=None,
    recommendation="Manually verify whether the query string is part of the cache key.",
    example_value="N/A",
    reference_url=_REF_URL,
)
```

- [ ] **Step 4: Wire into the registry**

In the `ALL_CACHE_FINDINGS` dict (around line 269-289), add three entries. The active-reflection section becomes:

```python
    # Active - reflection
    "WCP_UNKEYED_HEADER_CRITICAL": _WCP_UNKEYED_HEADER_CRITICAL,
    "WCP_UNKEYED_HEADER_HIGH": _WCP_UNKEYED_HEADER_HIGH,
    "WCP_UNKEYED_HEADER_MEDIUM": _WCP_UNKEYED_HEADER_MEDIUM,
    "WCP_UNKEYED_HEADER_LOW": _WCP_UNKEYED_HEADER_LOW,
    "WCP_LIVE_CACHE_POISONED": _WCP_LIVE_CACHE_POISONED,
    "WCP_UNKEYED_HEADER_NO_REFLECT": _WCP_UNKEYED_HEADER_NO_REFLECT,
    "WCP_PROBE_SKIPPED": _WCP_PROBE_SKIPPED,
    "WCP_ALT_SVC_POISONING": _WCP_ALT_SVC_POISONING,          # NEW
    "WCP_SET_COOKIE_POISONING": _WCP_SET_COOKIE_POISONING,    # NEW
```

And append to the passive section:
```python
    "WCP_CACHE_KEYING_UNDETERMINED": _WCP_CACHE_KEYING_UNDETERMINED,  # NEW
```

- [ ] **Step 5: Run tests to verify pass**

Run: `pytest tests/test_cache_findings.py -q`
Expected: all finding-registry tests pass.

- [ ] **Step 6: Commit**

```bash
git add corsair/cache/findings.py tests/test_cache_findings.py
git commit -m "feat(cache): register Alt-Svc, Set-Cookie, Keying-Undetermined findings

Add finding templates for v0.4.1 detections. Registered but not yet
emitted — follow-up commits wire them into reflect/probe/auditor.
"
```

---

### Task 3: Alt-Svc reflection detection

Wire `Alt-Svc` response header into the reflection detector and map the new context to `WCP_ALT_SVC_POISONING`.

**Files:**
- Modify: `corsair/cache/reflect.py` (HEADER_CONTEXTS, CONTEXT_SEVERITY_ORDER)
- Modify: `corsair/cache/probe.py` (CONTEXT_TO_SEVERITY)
- Test: `tests/test_cache_reflect.py`
- Test: `tests/test_cache_probe.py`

- [ ] **Step 1: Write failing reflect tests**

Append to `tests/test_cache_reflect.py` inside `class TestHeaderReflection`:

```python
    def test_alt_svc_header(self):
        resp = _mock_response(
            headers={"Alt-Svc": 'h3="abc123.corsair-canary.invalid:443"; ma=86400'}
        )
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "alt_svc_header"

    def test_alt_svc_wins_over_cors(self):
        resp = _mock_response(
            headers={
                "Alt-Svc": 'h3="abc123.corsair-canary.invalid:443"',
                "Access-Control-Allow-Origin": "https://abc123.corsair-canary.invalid",
            }
        )
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "alt_svc_header"

    def test_script_src_wins_over_alt_svc(self):
        resp = _mock_response(
            body='<script src="https://abc123.corsair-canary.invalid/x.js"></script>',
            headers={"Alt-Svc": 'h3="abc123.corsair-canary.invalid:443"'},
        )
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "script_src"
```

- [ ] **Step 2: Write failing probe tests**

Append to `tests/test_cache_probe.py`:

```python
class TestContextToFinding:
    def test_alt_svc_maps_to_alt_svc_poisoning(self):
        from corsair.cache.probe import CONTEXT_TO_SEVERITY
        severity, finding_id = CONTEXT_TO_SEVERITY["alt_svc_header"]
        assert severity == "HIGH"
        assert finding_id == "WCP_ALT_SVC_POISONING"
```

- [ ] **Step 3: Run tests to verify failure**

Run: `pytest tests/test_cache_reflect.py tests/test_cache_probe.py -q`
Expected: 4 failures (3 reflect tests + 1 probe test). Tests fail because `Alt-Svc` isn't in `HEADER_CONTEXTS` and `alt_svc_header` isn't in `CONTEXT_TO_SEVERITY`.

- [ ] **Step 4: Add `alt-svc` to `HEADER_CONTEXTS`**

Open `corsair/cache/reflect.py`. Change lines 22-28 (the `HEADER_CONTEXTS` list):

```python
HEADER_CONTEXTS: list[tuple[str, str]] = [
    ("content-security-policy", "csp_header"),
    ("location", "location_header"),
    ("access-control-allow-origin", "cors_header"),
    ("link", "link_header"),
    ("alt-svc", "alt_svc_header"),       # NEW
    ("set-cookie", "other_header"),
]
```

- [ ] **Step 5: Insert `alt_svc_header` into `CONTEXT_SEVERITY_ORDER`**

In `corsair/cache/reflect.py`, change `CONTEXT_SEVERITY_ORDER` (lines 39-52) to:

```python
CONTEXT_SEVERITY_ORDER: list[str] = [
    "script_src",
    "csp_header",
    "alt_svc_header",   # NEW: HIGH-severity H3 vector, above generic HIGH contexts
    "location_header",
    "link_href",
    "link_header",
    "meta_refresh",
    "cors_header",
    "js_variable",
    "canonical_href",
    "img_src",
    "body_text",
    "other_header",
]
```

- [ ] **Step 6: Map the new context in `probe.py`**

Open `corsair/cache/probe.py`. Change `CONTEXT_TO_SEVERITY` (lines 72-85) by inserting the new entry after `csp_header`:

```python
CONTEXT_TO_SEVERITY: dict[str, tuple[str, str]] = {
    "script_src": ("CRITICAL", "WCP_UNKEYED_HEADER_CRITICAL"),
    "csp_header": ("CRITICAL", "WCP_UNKEYED_HEADER_CRITICAL"),
    "alt_svc_header": ("HIGH", "WCP_ALT_SVC_POISONING"),   # NEW
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
```

- [ ] **Step 7: Run tests to verify pass**

Run: `pytest tests/test_cache_reflect.py tests/test_cache_probe.py -q`
Expected: all pass.

- [ ] **Step 8: Run full suite to verify no regression**

Run: `pytest -q`
Expected: 138 or more passing (was 135; +3 reflect tests, +1 probe test; findings tests already landed in Task 2). No failures.

- [ ] **Step 9: Commit**

```bash
git add corsair/cache/reflect.py corsair/cache/probe.py tests/test_cache_reflect.py tests/test_cache_probe.py
git commit -m "feat(cache): detect Alt-Svc reflection as HIGH severity

Closes HTTP/3 cross-protocol cache poisoning blind spot. Canary
reflected into Alt-Svc now routes to WCP_ALT_SVC_POISONING. Context
ranks above cors_header/link_header — Alt-Svc pinning is a more
powerful primitive than generic HIGH reflections.
"
```

---

### Task 4: Set-Cookie reflection detection

Upgrade `set-cookie` from `other_header` (LOW) to its own `set_cookie_header` context (HIGH), routed to `WCP_SET_COOKIE_POISONING`.

**Files:**
- Modify: `corsair/cache/reflect.py` (HEADER_CONTEXTS, CONTEXT_SEVERITY_ORDER)
- Modify: `corsair/cache/probe.py` (CONTEXT_TO_SEVERITY)
- Test: `tests/test_cache_reflect.py`
- Test: `tests/test_cache_probe.py`

- [ ] **Step 1: Write failing reflect tests**

Append to `tests/test_cache_reflect.py` inside `class TestHeaderReflection`:

```python
    def test_set_cookie_header(self):
        resp = _mock_response(
            headers={"Set-Cookie": "session=abc123; Path=/"}
        )
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "set_cookie_header"

    def test_set_cookie_wins_over_cors(self):
        resp = _mock_response(
            headers={
                "Set-Cookie": "session=abc123; Path=/",
                "Access-Control-Allow-Origin": "https://abc123.corsair-canary.invalid",
            }
        )
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "set_cookie_header"

    def test_set_cookie_and_body_text(self):
        # Set-Cookie should win over body_text (LOW)
        resp = _mock_response(
            body="<p>hello abc123</p>",
            headers={"Set-Cookie": "tracker=abc123"},
        )
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "set_cookie_header"
```

- [ ] **Step 2: Write failing probe test**

Append to the existing `TestContextToFinding` class in `tests/test_cache_probe.py`:

```python
    def test_set_cookie_maps_to_set_cookie_poisoning(self):
        from corsair.cache.probe import CONTEXT_TO_SEVERITY
        severity, finding_id = CONTEXT_TO_SEVERITY["set_cookie_header"]
        assert severity == "HIGH"
        assert finding_id == "WCP_SET_COOKIE_POISONING"
```

- [ ] **Step 3: Run tests to verify failure**

Run: `pytest tests/test_cache_reflect.py tests/test_cache_probe.py -q`
Expected: 4 failures — `set-cookie` is currently bucketed as `other_header`, and `set_cookie_header` is not in `CONTEXT_TO_SEVERITY`.

- [ ] **Step 4: Upgrade `set-cookie` in `HEADER_CONTEXTS`**

In `corsair/cache/reflect.py`, change the last line of `HEADER_CONTEXTS`:

```python
HEADER_CONTEXTS: list[tuple[str, str]] = [
    ("content-security-policy", "csp_header"),
    ("location", "location_header"),
    ("access-control-allow-origin", "cors_header"),
    ("link", "link_header"),
    ("alt-svc", "alt_svc_header"),
    ("set-cookie", "set_cookie_header"),   # was: "other_header"
]
```

- [ ] **Step 5: Insert `set_cookie_header` into `CONTEXT_SEVERITY_ORDER`**

In `corsair/cache/reflect.py`, insert `set_cookie_header` after `alt_svc_header` and before `location_header`:

```python
CONTEXT_SEVERITY_ORDER: list[str] = [
    "script_src",
    "csp_header",
    "alt_svc_header",
    "set_cookie_header",   # NEW: session-fixation primitive, above generic HIGH
    "location_header",
    "link_href",
    "link_header",
    "meta_refresh",
    "cors_header",
    "js_variable",
    "canonical_href",
    "img_src",
    "body_text",
    "other_header",
]
```

- [ ] **Step 6: Handle fallback in `detect_reflection`**

Review `corsair/cache/reflect.py:80` — the existing guard:

```python
if not body_matches and all(c == "other_header" for c in found_contexts):
    found_contexts.append("body_text")
```

This line promotes `other_header` contexts to `body_text` when body has the canary and no body pattern matched. Set-Cookie is no longer `other_header`, so this guard is unaffected — no change needed.

- [ ] **Step 7: Map the new context in `probe.py`**

In `corsair/cache/probe.py`, insert `set_cookie_header` into `CONTEXT_TO_SEVERITY` after `alt_svc_header`:

```python
CONTEXT_TO_SEVERITY: dict[str, tuple[str, str]] = {
    "script_src": ("CRITICAL", "WCP_UNKEYED_HEADER_CRITICAL"),
    "csp_header": ("CRITICAL", "WCP_UNKEYED_HEADER_CRITICAL"),
    "alt_svc_header": ("HIGH", "WCP_ALT_SVC_POISONING"),
    "set_cookie_header": ("HIGH", "WCP_SET_COOKIE_POISONING"),   # NEW
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
```

- [ ] **Step 8: Run tests to verify pass**

Run: `pytest tests/test_cache_reflect.py tests/test_cache_probe.py -q`
Expected: all pass.

- [ ] **Step 9: Run full suite**

Run: `pytest -q`
Expected: no regressions.

- [ ] **Step 10: Commit**

```bash
git add corsair/cache/reflect.py corsair/cache/probe.py tests/test_cache_reflect.py tests/test_cache_probe.py
git commit -m "feat(cache): detect Set-Cookie reflection as HIGH severity

Upgrades Set-Cookie reflection from LOW (other_header bucket) to
dedicated HIGH finding WCP_SET_COOKIE_POISONING. Cached Set-Cookie
from a poisoned response is delivered to every subsequent user —
session fixation grade per Gemini WCP research.
"
```

---

### Task 5: `is_cached` honors age-increment evidence

Widen `oracle.is_cached` so UNKNOWN cache-status with increasing `Age` still marks the target as cached. Fixes silent skip of active probing on CDNs that omit X-Cache headers.

**Files:**
- Modify: `corsair/cache/oracle.py:176`
- Test: `tests/test_cache_oracle.py`

- [ ] **Step 1: Write failing test**

Append to `tests/test_cache_oracle.py`:

```python
import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from corsair.cache.oracle import CacheOracle, establish_oracle


def _mock_client_pair(r1_headers, r2_headers, r1_body="", r2_body=""):
    """Return an AsyncMock client whose GET calls yield r1 then r2 responses."""
    r1 = MagicMock()
    r1.headers = r1_headers
    r1.text = r1_body
    r2 = MagicMock()
    r2.headers = r2_headers
    r2.text = r2_body
    client = MagicMock()
    client.get = AsyncMock(side_effect=[r1, r2])
    return client


class TestIsCachedAgeFallback:
    def test_is_cached_via_age_increment_when_status_unknown(self):
        # No cache-status headers but Age increments 0 → 5
        r1_headers = {"content-type": "text/html", "age": "0"}
        r2_headers = {"content-type": "text/html", "age": "5"}
        client = _mock_client_pair(r1_headers, r2_headers)

        oracle = asyncio.run(establish_oracle(client, "https://example.com", timeout=5))
        assert oracle.is_cached is True
        assert oracle.age_increments is True

    def test_is_cached_false_when_age_static_and_status_unknown(self):
        r1_headers = {"content-type": "text/html", "age": "10"}
        r2_headers = {"content-type": "text/html", "age": "10"}
        client = _mock_client_pair(r1_headers, r2_headers)

        oracle = asyncio.run(establish_oracle(client, "https://example.com", timeout=5))
        assert oracle.is_cached is False
        assert oracle.age_increments is False
```

- [ ] **Step 2: Run test to verify failure**

Run: `pytest tests/test_cache_oracle.py::TestIsCachedAgeFallback -q`
Expected: `test_is_cached_via_age_increment_when_status_unknown` fails — `is_cached` is False because `s2 != HIT`. Second test passes.

- [ ] **Step 3: Widen `is_cached`**

In `corsair/cache/oracle.py`, change line 176:

```python
# Before:
oracle.is_cached = s2 == CacheStatus.HIT

# After:
oracle.is_cached = (s2 == CacheStatus.HIT) or oracle.age_increments
```

Note: `oracle.age_increments` is currently computed on lines 190-192, *after* `is_cached` is set. Move the age-increment computation to *before* the `is_cached` assignment so the boolean references the already-computed field:

```python
    r2_headers = {k.lower(): v for k, v in r2.headers.items()}
    s2 = read_cache_status(r2_headers, oracle.cdn_fingerprint)

    age1 = int(r1_headers.get("age", "0") or 0)
    age2 = int(r2_headers.get("age", "0") or 0)
    oracle.age_increments = age2 > age1

    oracle.is_cached = (s2 == CacheStatus.HIT) or oracle.age_increments

    if s1 == CacheStatus.HIT:
        oracle.query_string_keyed = False
        # ... existing Vary fallback ...
```

The existing s1=HIT branch stays below. Result: `is_cached` is computed after `age_increments`, so the OR works correctly.

- [ ] **Step 4: Run test to verify pass**

Run: `pytest tests/test_cache_oracle.py::TestIsCachedAgeFallback -q`
Expected: both tests pass.

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: no regressions.

- [ ] **Step 6: Commit**

```bash
git add corsair/cache/oracle.py tests/test_cache_oracle.py
git commit -m "fix(cache): is_cached falls back to Age increment when status unknown

CDNs that omit X-Cache headers (bespoke edge, some Varnish configs)
previously silently marked targets not-cached, skipping all active
probing. Monotonically increasing Age across two requests is
independent evidence of cache persistence — use it as a fallback.
"
```

---

### Task 6: Akamai `X-Cache-Key` parser

Add a pure-function helper that classifies whether the query string is part of the Akamai cache key. Unit-tested in isolation; wired into the decision table in Task 8.

**Files:**
- Modify: `corsair/cache/oracle.py` (add `_akamai_qs_in_key`)
- Test: `tests/test_cache_oracle.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_cache_oracle.py`:

```python
from corsair.cache.oracle import _akamai_qs_in_key


class TestAkamaiCacheKeyParser:
    def test_empty_returns_none(self):
        assert _akamai_qs_in_key("") is None

    def test_none_returns_none(self):
        assert _akamai_qs_in_key(None) is None

    def test_with_query_string_returns_true(self):
        # Typical Akamai format: /L/TTL/RULE/host/path?qs/_metadata
        key = "/L/3600/1234/example.com/page?id=1/_metadata"
        assert _akamai_qs_in_key(key) is True

    def test_without_query_string_returns_false(self):
        key = "/L/3600/1234/example.com/page/_metadata"
        assert _akamai_qs_in_key(key) is False

    def test_question_mark_only_after_underscore_metadata_is_false(self):
        # Metadata trailer after /_ should be ignored
        key = "/L/3600/1234/example.com/page/_bucket?reserved=1"
        assert _akamai_qs_in_key(key) is False

    def test_question_mark_in_url_and_metadata_is_true(self):
        key = "/L/3600/1234/example.com/page?id=1/_bucket?reserved=1"
        assert _akamai_qs_in_key(key) is True
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_cache_oracle.py::TestAkamaiCacheKeyParser -q`
Expected: ImportError — `_akamai_qs_in_key` doesn't exist yet.

- [ ] **Step 3: Implement the parser**

In `corsair/cache/oracle.py`, add after the `make_buster` function (around line 118):

```python
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
```

- [ ] **Step 4: Run tests to verify pass**

Run: `pytest tests/test_cache_oracle.py::TestAkamaiCacheKeyParser -q`
Expected: all 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add corsair/cache/oracle.py tests/test_cache_oracle.py
git commit -m "feat(cache): add Akamai X-Cache-Key query-string parser

Pure helper — wiring into the oracle decision table follows. Lets
Akamai targets give us an authoritative signal for cache keying
instead of falling into the undetermined bucket.
"
```

---

### Task 7: Extract `_resolve_buster_from_vary` helper

Pure refactor: extract the Vary-header buster-strategy fallback from the existing s1=HIT branch into a module-level helper. No behavior change. Prepares the ground for Task 8, which calls the helper from a second branch (Akamai-confirms-False).

**Files:**
- Modify: `corsair/cache/oracle.py`
- Test: `tests/test_cache_oracle.py`

- [ ] **Step 1: Write failing tests against the new helper**

Append to `tests/test_cache_oracle.py`:

```python
from corsair.cache.oracle import _resolve_buster_from_vary


class TestResolveBusterFromVary:
    def test_accept_language_in_vary(self):
        oracle = CacheOracle(url="https://example.com", vary_header="Accept-Language, User-Agent")
        _resolve_buster_from_vary(oracle)
        assert oracle.buster_strategy == "accept_language"
        assert oracle.buster_param == "Accept-Language"

    def test_user_agent_in_vary(self):
        oracle = CacheOracle(url="https://example.com", vary_header="User-Agent")
        _resolve_buster_from_vary(oracle)
        assert oracle.buster_strategy == "user_agent"
        assert oracle.buster_param == "User-Agent"

    def test_vary_missing_sets_none(self):
        oracle = CacheOracle(url="https://example.com", vary_header=None)
        _resolve_buster_from_vary(oracle)
        assert oracle.buster_strategy == "none"

    def test_vary_unhelpful_sets_none(self):
        oracle = CacheOracle(url="https://example.com", vary_header="Accept-Encoding")
        _resolve_buster_from_vary(oracle)
        assert oracle.buster_strategy == "none"

    def test_accept_language_precedes_user_agent(self):
        oracle = CacheOracle(url="https://example.com", vary_header="User-Agent, Accept-Language")
        _resolve_buster_from_vary(oracle)
        assert oracle.buster_strategy == "accept_language"
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_cache_oracle.py::TestResolveBusterFromVary -q`
Expected: ImportError.

- [ ] **Step 3: Add the helper and replace the inline block**

In `corsair/cache/oracle.py`, add after `_akamai_qs_in_key`:

```python
def _resolve_buster_from_vary(oracle: CacheOracle) -> None:
    """Pick a buster strategy from Vary when QS is NOT part of the cache key.

    Mutates `oracle.buster_strategy` and `oracle.buster_param`. Sets
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
```

In `establish_oracle`, replace the existing inline block at lines 178-188. Before:

```python
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
```

After:

```python
    if s1 == CacheStatus.HIT:
        oracle.query_string_keyed = False
        _resolve_buster_from_vary(oracle)
```

- [ ] **Step 4: Run tests to verify pass**

Run: `pytest tests/test_cache_oracle.py::TestResolveBusterFromVary -q`
Expected: all pass.

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: no regressions. This is a pure refactor — all existing oracle tests still pass.

- [ ] **Step 6: Commit**

```bash
git add corsair/cache/oracle.py tests/test_cache_oracle.py
git commit -m "refactor(cache): extract _resolve_buster_from_vary helper

Pure refactor of the Vary-based fallback logic out of the s1=HIT
branch. No behavior change. Next commit reuses it from the
Akamai-confirms-False branch.
"
```

---

### Task 8: `query_string_keyed` Optional[bool] with Akamai decision table and safety gate

Atomic change that couples four pieces. These must land together — any split leaves the code in a broken intermediate state where the dataclass type, the oracle setter, the passive-check reader, and the active-probe gate disagree.

1. Dataclass field becomes `Optional[bool] = None`
2. `establish_oracle` resolves the field per the decision table (§5.5 of the spec)
3. `_passive_checks` emits `WCP_NO_CACHE_KEY_QS` only on `is False`; emits `WCP_CACHE_KEYING_UNDETERMINED` on `is None`
4. `_audit_async` gates active probing on `query_string_keyed is not None` (safety, §5.5.1 of the spec)

**Files:**
- Modify: `corsair/cache/oracle.py` (dataclass + decision table)
- Modify: `corsair/cache/auditor.py` (passive emission + safety gate)
- Test: `tests/test_cache_oracle.py`
- Test: `tests/test_cache_auditor_unit.py`

- [ ] **Step 1: Write failing oracle tests**

Append to `tests/test_cache_oracle.py`:

```python
class TestQueryStringKeyedResolution:
    def test_default_is_none(self):
        oracle = CacheOracle(url="https://example.com")
        assert oracle.query_string_keyed is None

    def test_s1_miss_s2_hit_sets_true(self):
        # s1 MISS (Cloudflare MISS), s2 HIT → buster isolates → QS in key
        r1_headers = {"cf-cache-status": "MISS", "age": "0"}
        r2_headers = {"cf-cache-status": "HIT", "age": "1"}
        client = _mock_client_pair(r1_headers, r2_headers)

        oracle = asyncio.run(establish_oracle(client, "https://example.com", timeout=5))
        assert oracle.query_string_keyed is True
        assert oracle.buster_strategy == "query_param"

    def test_s1_hit_sets_false_and_vary_fallback(self):
        # s1 HIT means buster was ignored; Vary: Accept-Language allows a fallback
        r1_headers = {"cf-cache-status": "HIT", "vary": "Accept-Language", "age": "10"}
        r2_headers = {"cf-cache-status": "HIT", "vary": "Accept-Language", "age": "20"}
        client = _mock_client_pair(r1_headers, r2_headers)

        oracle = asyncio.run(establish_oracle(client, "https://example.com", timeout=5))
        assert oracle.query_string_keyed is False
        assert oracle.buster_strategy == "accept_language"

    def test_s1_unknown_s2_hit_non_akamai_stays_none(self):
        # No CDN status headers on s1, HIT on s2, no Akamai key → undetermined
        r1_headers = {"content-type": "text/html", "age": "0"}
        r2_headers = {"cf-cache-status": "HIT", "age": "1"}
        client = _mock_client_pair(r1_headers, r2_headers)

        oracle = asyncio.run(establish_oracle(client, "https://example.com", timeout=5))
        assert oracle.query_string_keyed is None

    def test_s2_miss_leaves_keyed_none(self):
        # Target never confirmed cached via status → undetermined
        r1_headers = {"cf-cache-status": "MISS"}
        r2_headers = {"cf-cache-status": "MISS"}
        client = _mock_client_pair(r1_headers, r2_headers)

        oracle = asyncio.run(establish_oracle(client, "https://example.com", timeout=5))
        assert oracle.query_string_keyed is None
```

- [ ] **Step 2: Write failing Akamai-integration tests**

In `tests/test_cache_oracle.py`, add a helper that returns *three* responses (GET, Akamai Pragma probe, GET) since Akamai-fingerprint targets make an extra request:

```python
def _mock_client_triple(r1_headers, pragma_headers, r2_headers):
    """Client for Akamai: GET → Pragma probe → GET."""
    r1 = MagicMock(); r1.headers = r1_headers; r1.text = ""
    rp = MagicMock(); rp.headers = pragma_headers; rp.text = ""
    r2 = MagicMock(); r2.headers = r2_headers; r2.text = ""
    client = MagicMock()
    client.get = AsyncMock(side_effect=[r1, rp, r2])
    return client


class TestAkamaiIntegratedDecisionTable:
    def test_akamai_key_with_qs_confirms_true(self):
        # Akamai fingerprint via x-check-cacheable; s1 UNKNOWN, s2 HIT
        r1_headers = {"x-check-cacheable": "YES", "server": "AkamaiGHost"}
        pragma_headers = {
            "x-check-cacheable": "YES",
            "x-cache-key": "/L/3600/1234/example.com/page?id=1/_metadata",
        }
        r2_headers = {"x-check-cacheable": "YES", "x-cache": "TCP_HIT"}
        client = _mock_client_triple(r1_headers, pragma_headers, r2_headers)

        oracle = asyncio.run(establish_oracle(client, "https://example.com", timeout=5))
        assert oracle.cdn_fingerprint == "akamai"
        assert oracle.query_string_keyed is True
        assert oracle.buster_strategy == "query_param"

    def test_akamai_key_without_qs_confirms_false_with_vary_fallback(self):
        r1_headers = {
            "x-check-cacheable": "YES",
            "server": "AkamaiGHost",
            "vary": "Accept-Language",
        }
        pragma_headers = {
            "x-check-cacheable": "YES",
            "x-cache-key": "/L/3600/1234/example.com/page/_metadata",
        }
        r2_headers = {
            "x-check-cacheable": "YES",
            "x-cache": "TCP_HIT",
            "vary": "Accept-Language",
        }
        client = _mock_client_triple(r1_headers, pragma_headers, r2_headers)

        oracle = asyncio.run(establish_oracle(client, "https://example.com", timeout=5))
        assert oracle.query_string_keyed is False
        assert oracle.buster_strategy == "accept_language"

    def test_akamai_key_without_qs_no_vary_sets_buster_none(self):
        r1_headers = {"x-check-cacheable": "YES", "server": "AkamaiGHost"}
        pragma_headers = {
            "x-check-cacheable": "YES",
            "x-cache-key": "/L/3600/1234/example.com/page/_metadata",
        }
        r2_headers = {"x-check-cacheable": "YES", "x-cache": "TCP_HIT"}
        client = _mock_client_triple(r1_headers, pragma_headers, r2_headers)

        oracle = asyncio.run(establish_oracle(client, "https://example.com", timeout=5))
        assert oracle.query_string_keyed is False
        assert oracle.buster_strategy == "none"

    def test_akamai_pragma_probe_missing_key_leaves_none(self):
        r1_headers = {"x-check-cacheable": "YES", "server": "AkamaiGHost"}
        pragma_headers = {"x-check-cacheable": "YES"}  # no x-cache-key
        r2_headers = {"x-check-cacheable": "YES", "x-cache": "TCP_HIT"}
        client = _mock_client_triple(r1_headers, pragma_headers, r2_headers)

        oracle = asyncio.run(establish_oracle(client, "https://example.com", timeout=5))
        assert oracle.akamai_cache_key is None
        assert oracle.query_string_keyed is None
```

- [ ] **Step 3: Write failing auditor tests**

In `tests/test_cache_auditor_unit.py`, update the `_mock_oracle` helper so callers can opt in to each `query_string_keyed` state. Change:

```python
def _mock_oracle(is_cached=True, cdn="cloudflare", buster_strategy="query_param"):
    return CacheOracle(
        url="https://example.com",
        is_cached=is_cached,
        cdn_fingerprint=cdn,
        buster_strategy=buster_strategy,
        cache_control="public, max-age=3600",
        vary_header="Accept-Encoding",
    )
```

to:

```python
def _mock_oracle(
    is_cached=True,
    cdn="cloudflare",
    buster_strategy="query_param",
    query_string_keyed=True,
):
    return CacheOracle(
        url="https://example.com",
        is_cached=is_cached,
        cdn_fingerprint=cdn,
        buster_strategy=buster_strategy,
        query_string_keyed=query_string_keyed,
        cache_control="public, max-age=3600",
        vary_header="Accept-Encoding",
    )
```

Rationale: existing tests default to `True` (the only sensible value for "happy path" passive/active tests). New tests pass `None` or `False` explicitly.

Append to `tests/test_cache_auditor_unit.py`:

```python
class TestQueryStringKeyedEmission:
    def test_emits_no_cache_key_qs_when_false(self):
        auditor = CacheAuditor(active=False)
        oracle = _mock_oracle(is_cached=True, query_string_keyed=False)
        with patch(
            "corsair.cache.auditor.establish_oracle",
            new=AsyncMock(return_value=oracle),
        ):
            findings = auditor.audit("https://example.com", {})
        assert any(
            f.title == "Query string excluded from cache key" for f in findings
        )
        assert not any(
            f.title == "Cache keying could not be determined" for f in findings
        )

    def test_emits_undetermined_when_none(self):
        auditor = CacheAuditor(active=False)
        oracle = _mock_oracle(is_cached=True, query_string_keyed=None)
        with patch(
            "corsair.cache.auditor.establish_oracle",
            new=AsyncMock(return_value=oracle),
        ):
            findings = auditor.audit("https://example.com", {})
        assert any(
            f.title == "Cache keying could not be determined" for f in findings
        )
        assert not any(
            f.title == "Query string excluded from cache key" for f in findings
        )

    def test_no_keying_finding_when_true(self):
        auditor = CacheAuditor(active=False)
        oracle = _mock_oracle(is_cached=True, query_string_keyed=True)
        with patch(
            "corsair.cache.auditor.establish_oracle",
            new=AsyncMock(return_value=oracle),
        ):
            findings = auditor.audit("https://example.com", {})
        assert not any(
            f.title in (
                "Query string excluded from cache key",
                "Cache keying could not be determined",
            )
            for f in findings
        )


class TestActiveProbingSafetyGate:
    def test_skipped_when_query_string_keyed_is_none(self):
        auditor = CacheAuditor(active=True)
        oracle = _mock_oracle(
            is_cached=True,
            buster_strategy="query_param",
            query_string_keyed=None,
        )
        with patch(
            "corsair.cache.auditor.establish_oracle",
            new=AsyncMock(return_value=oracle),
        ):
            with patch("corsair.cache.auditor.probe_single_header") as mock_probe:
                auditor.audit("https://example.com", {})
                mock_probe.assert_not_called()

    def test_runs_when_query_string_keyed_is_true(self):
        auditor = CacheAuditor(active=True)
        oracle = _mock_oracle(
            is_cached=True,
            buster_strategy="query_param",
            query_string_keyed=True,
        )
        with patch(
            "corsair.cache.auditor.establish_oracle",
            new=AsyncMock(return_value=oracle),
        ):
            # Return a no-op CanaryResult so probing finishes cleanly
            from corsair.cache.probe import CanaryResult
            with patch(
                "corsair.cache.auditor.probe_single_header",
                new=AsyncMock(return_value=CanaryResult(header_name="X", canary="")),
            ) as mock_probe, patch(
                "corsair.cache.auditor.probe_cpdos_oversize",
                new=AsyncMock(return_value=CanaryResult(header_name="X", canary="")),
            ), patch(
                "corsair.cache.auditor.probe_cpdos_malformed",
                new=AsyncMock(return_value=CanaryResult(header_name="X", canary="")),
            ), patch(
                "corsair.cache.auditor.probe_cpdos_method_override",
                new=AsyncMock(return_value=CanaryResult(header_name="X", canary="")),
            ):
                auditor.audit("https://example.com", {})
                assert mock_probe.call_count >= 1

    def test_runs_when_query_string_keyed_is_false_with_vary_buster(self):
        auditor = CacheAuditor(active=True)
        oracle = _mock_oracle(
            is_cached=True,
            buster_strategy="accept_language",
            query_string_keyed=False,
        )
        with patch(
            "corsair.cache.auditor.establish_oracle",
            new=AsyncMock(return_value=oracle),
        ):
            from corsair.cache.probe import CanaryResult
            with patch(
                "corsair.cache.auditor.probe_single_header",
                new=AsyncMock(return_value=CanaryResult(header_name="X", canary="")),
            ) as mock_probe, patch(
                "corsair.cache.auditor.probe_cpdos_oversize",
                new=AsyncMock(return_value=CanaryResult(header_name="X", canary="")),
            ), patch(
                "corsair.cache.auditor.probe_cpdos_malformed",
                new=AsyncMock(return_value=CanaryResult(header_name="X", canary="")),
            ), patch(
                "corsair.cache.auditor.probe_cpdos_method_override",
                new=AsyncMock(return_value=CanaryResult(header_name="X", canary="")),
            ):
                auditor.audit("https://example.com", {})
                assert mock_probe.call_count >= 1
```

- [ ] **Step 4: Run failing tests**

Run: `pytest tests/test_cache_oracle.py tests/test_cache_auditor_unit.py -q`
Expected: many failures (dataclass default is still True; Akamai branches don't exist; auditor passive emission uses `not oracle.query_string_keyed`; safety gate missing).

- [ ] **Step 5: Change the dataclass field**

In `corsair/cache/oracle.py`, change line 32:

```python
# Before:
    query_string_keyed: bool = True

# After:
    query_string_keyed: Optional[bool] = None
```

- [ ] **Step 6: Rewrite the decision table in `establish_oracle`**

In `corsair/cache/oracle.py`, replace the current s1=HIT block plus the implicit "default" behavior with the explicit decision table. After the `is_cached` assignment (now after `age_increments` per Task 5), replace lines 178-188 with:

```python
    if s1 == CacheStatus.HIT:
        oracle.query_string_keyed = False
        _resolve_buster_from_vary(oracle)
    elif s1 == CacheStatus.MISS and s2 == CacheStatus.HIT:
        oracle.query_string_keyed = True
        # buster_strategy stays "query_param" (dataclass default)
    elif s2 == CacheStatus.HIT and oracle.akamai_cache_key:
        akamai_keyed = _akamai_qs_in_key(oracle.akamai_cache_key)
        if akamai_keyed is True:
            oracle.query_string_keyed = True
            # buster_strategy stays "query_param"
        elif akamai_keyed is False:
            oracle.query_string_keyed = False
            _resolve_buster_from_vary(oracle)
        # akamai_keyed is None: stays undetermined (query_string_keyed stays None)
    # else: s1 UNKNOWN without Akamai key, or s2 not HIT → stays None (undetermined)
```

Note ordering: the `elif s1 == MISS and s2 == HIT` branch must come before the Akamai branch because a Cloudflare→Akamai edge ordering could otherwise match the Akamai branch first when the MISS→HIT evidence is already conclusive. The current ordering is correct.

- [ ] **Step 7: Update `_passive_checks` emission**

In `corsair/cache/auditor.py`, replace lines 97-100:

```python
# Before:
        if not oracle.query_string_keyed:
            finding = get_finding("WCP_NO_CACHE_KEY_QS")
            if finding:
                findings.append(finding)

# After:
        if oracle.query_string_keyed is False:
            finding = get_finding("WCP_NO_CACHE_KEY_QS")
            if finding:
                findings.append(finding)
        elif oracle.query_string_keyed is None:
            finding = get_finding("WCP_CACHE_KEYING_UNDETERMINED")
            if finding:
                findings.append(finding)
        # True → no finding
```

- [ ] **Step 8: Add the active-probing safety gate**

In `corsair/cache/auditor.py`, inside `_audit_async`, add a new guard between the `not oracle.is_cached` early-return and the `buster_strategy == "none"` guard. Current code (lines 67-74):

```python
            if not oracle.is_cached:
                return findings

            if oracle.buster_strategy == "none":
                skipped = get_finding("WCP_PROBE_SKIPPED")
                if skipped:
                    findings.append(skipped)
                return findings
```

After:

```python
            if not oracle.is_cached:
                return findings

            if oracle.query_string_keyed is None:
                # Safety gate: if we can't prove our buster isolates, probing
                # could inadvertently poison the live cache. The undetermined
                # finding was already emitted in _passive_checks.
                return findings

            if oracle.buster_strategy == "none":
                skipped = get_finding("WCP_PROBE_SKIPPED")
                if skipped:
                    findings.append(skipped)
                return findings
```

- [ ] **Step 9: Run all tests to verify pass**

Run: `pytest tests/test_cache_oracle.py tests/test_cache_auditor_unit.py -q`
Expected: all pass.

- [ ] **Step 10: Run full suite**

Run: `pytest -q`
Expected: no regressions. The scanner-integration tests (`tests/test_scanner_cache_integration.py`) use `CacheOracle` indirectly through `CacheAuditor.audit`; the passing-value default (`query_string_keyed=True`) preserves existing mock behavior if any test constructs a `CacheOracle` directly without setting the field. Verify nothing broke.

- [ ] **Step 11: Commit**

```bash
git add corsair/cache/oracle.py corsair/cache/auditor.py tests/test_cache_oracle.py tests/test_cache_auditor_unit.py
git commit -m "fix(cache): conservative query_string_keyed with Akamai+safety gate

Changes:
- query_string_keyed is Optional[bool], default None (undetermined)
- Decision table in establish_oracle: s1=HIT → False (Vary fallback),
  s1=MISS+s2=HIT → True, Akamai X-Cache-Key → authoritative signal,
  else → None
- _passive_checks emits WCP_NO_CACHE_KEY_QS only on False; emits
  WCP_CACHE_KEYING_UNDETERMINED on None
- Active probing skipped when query_string_keyed is None (safety:
  buster isolation unproven → risk of live cache poisoning)

Resolves audit items #4 (false-negative), #5 (Akamai dead code).
"
```

---

### Task 9: Preemptive probe cancellation

Replace `asyncio.gather(*tasks)` with a pattern that cancels pending tasks when `abort_event` is set. Python 3.9-compatible (no TaskGroup).

**Files:**
- Modify: `corsair/cache/auditor.py:128-180` (`_active_probes`)
- Test: `tests/test_cache_auditor_unit.py`

- [ ] **Step 1: Write failing test**

Append to `tests/test_cache_auditor_unit.py`:

```python
import asyncio

from corsair.cache.oracle import CacheOracle
from corsair.cache.probe import CanaryResult


class TestPreemptiveAbort:
    def test_abort_event_cancels_pending_probes(self):
        auditor = CacheAuditor(active=True, max_concurrency=2, timeout=5)
        oracle = _mock_oracle(
            is_cached=True,
            buster_strategy="query_param",
            query_string_keyed=True,
        )

        probe_start_count = {"n": 0}
        probe_finish_count = {"n": 0}

        async def fast_poisoning_probe(*args, **kwargs):
            # Completes immediately with live-poisoning; sets abort_event
            abort_event = kwargs.get("abort_event")
            probe_start_count["n"] += 1
            if abort_event is not None:
                abort_event.set()
            probe_finish_count["n"] += 1
            return CanaryResult(
                header_name=args[2] if len(args) > 2 else "X-Forwarded-Host",
                canary="",
                confirmed_unkeyed=True,
                severity="CRITICAL",
                finding_id="WCP_LIVE_CACHE_POISONED",
                detail="Simulated live poisoning",
            )

        async def slow_probe(*args, **kwargs):
            probe_start_count["n"] += 1
            try:
                await asyncio.sleep(3.0)
            except asyncio.CancelledError:
                raise
            probe_finish_count["n"] += 1
            return CanaryResult(header_name="X", canary="")

        # First probe triggers poisoning; rest are slow and should be cancelled
        call_order = {"n": 0}
        async def dispatch(*args, **kwargs):
            call_order["n"] += 1
            if call_order["n"] == 1:
                return await fast_poisoning_probe(*args, **kwargs)
            return await slow_probe(*args, **kwargs)

        with patch(
            "corsair.cache.auditor.establish_oracle",
            new=AsyncMock(return_value=oracle),
        ):
            with patch(
                "corsair.cache.auditor.probe_single_header",
                new=AsyncMock(side_effect=dispatch),
            ), patch(
                "corsair.cache.auditor.probe_cpdos_oversize",
                new=AsyncMock(side_effect=slow_probe),
            ), patch(
                "corsair.cache.auditor.probe_cpdos_malformed",
                new=AsyncMock(side_effect=slow_probe),
            ), patch(
                "corsair.cache.auditor.probe_cpdos_method_override",
                new=AsyncMock(side_effect=slow_probe),
            ):
                import time
                start = time.time()
                findings = auditor.audit("https://example.com", {})
                elapsed = time.time() - start

        # If cancellation works, we finish well under the 3-second slow-probe sleep
        assert elapsed < 2.0, f"Probing ran for {elapsed:.2f}s — abort did not cancel pending tasks"
        # The live-poisoning finding is present
        assert any(f.title == "Live cache poisoned during scan" for f in findings)
        # More probes started than finished — some were cancelled
        assert probe_start_count["n"] > probe_finish_count["n"]
```

- [ ] **Step 2: Run test to verify failure**

Run: `pytest tests/test_cache_auditor_unit.py::TestPreemptiveAbort -q`
Expected: failure — current `asyncio.gather` awaits all slow probes; elapsed ≥ 3.0s.

- [ ] **Step 3: Rewrite `_active_probes` to use preemptive cancellation**

In `corsair/cache/auditor.py`, replace the full body of `_active_probes` (lines 128-180) with:

```python
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
                    client,
                    oracle,
                    header_name,
                    value_template,
                    timeout=self.timeout,
                    abort_event=abort_event,
                )

        async def limited_cpdos(probe_func):
            async with semaphore:
                if abort_event.is_set():
                    return CanaryResult(header_name="CPDoS", canary="", detail="Aborted")
                return await probe_func(
                    client,
                    oracle,
                    timeout=self.timeout,
                    abort_event=abort_event,
                )

        tasks: list[asyncio.Task] = []
        for header_name, value_template in PROBE_HEADERS:
            tasks.append(asyncio.create_task(limited_probe(header_name, value_template)))
        tasks.append(asyncio.create_task(limited_cpdos(probe_cpdos_oversize)))
        tasks.append(asyncio.create_task(limited_cpdos(probe_cpdos_malformed)))
        tasks.append(asyncio.create_task(limited_cpdos(probe_cpdos_method_override)))

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
            # Drain the watcher so it doesn't leave an unawaited task warning
            try:
                await watcher
            except (asyncio.CancelledError, Exception):
                pass

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

Key points:
- `asyncio.create_task(...)` wraps each coroutine so individual handles are cancellable.
- `abort_watcher` awaits the abort event once; when fired, it iterates pending tasks and calls `.cancel()` on each.
- `gather(..., return_exceptions=True)` surfaces `CancelledError` as a return value; we skip those when collecting findings.
- `finally` block ensures the watcher is cleaned up whether probing succeeded or raised.

- [ ] **Step 4: Run the failing test**

Run: `pytest tests/test_cache_auditor_unit.py::TestPreemptiveAbort -q`
Expected: pass. Elapsed time is well under 3 seconds.

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: no regressions. Existing `TestCacheAuditorActiveSkip` tests continue to pass.

- [ ] **Step 6: Commit**

```bash
git add corsair/cache/auditor.py tests/test_cache_auditor_unit.py
git commit -m "fix(cache): preemptive probe cancellation on live poisoning

asyncio.gather waited for in-flight probes to finish after
abort_event fired. Now we track task handles and cancel pending
ones inside an abort_watcher coroutine. Python 3.9 compatible —
no TaskGroup.

Closes the gap between v0.4.0 spec language ('abort immediately')
and observed behavior (up to 4 more Phase-3 requests).
"
```

---

### Task 10: Version bump, changelog, release

Bump `pyproject.toml` from `0.2.0` → `0.4.1`, add a README changelog entry, run full suite and lint pass, push PR branch.

**Files:**
- Modify: `pyproject.toml`
- Modify: `README.md`

- [ ] **Step 1: Bump version**

In `pyproject.toml`, change line 7:

```toml
# Before:
version = "0.2.0"

# After:
version = "0.4.1"
```

Note: version is stale — this was supposed to bump with v0.4.0 but didn't. The bump to `0.4.1` leapfrogs `0.4.0` in the manifest; that's acceptable because the module was feature-complete at v0.4.0 and this release is strictly additive.

- [ ] **Step 2: Read the current README changelog section**

Run: `grep -n -E '^## (Changelog|Release|Version|v[0-9])' README.md | head -20`

If the README has a changelog section, append under it. If not, locate the top of the README and add a changelog section near the existing v0.4.0 notes.

- [ ] **Step 3: Add a v0.4.1 changelog entry**

Add this block to the README changelog section (exact location depends on existing structure):

```markdown
### v0.4.1 — Cache Module Hardening (2026-04-18)

**Detection gaps closed:**
- `WCP_ALT_SVC_POISONING` (HIGH): Alt-Svc cache poisoning via unkeyed header — HTTP/3 cross-protocol vector where attacker pins victim browsers to a malicious QUIC endpoint.
- `WCP_SET_COOKIE_POISONING` (HIGH): Set-Cookie cache poisoning via unkeyed header — session fixation and cookie injection via cached response headers.

**Correctness:**
- `is_cached` now falls back to Age-increment evidence when cache-status headers are absent.
- `query_string_keyed` is now conservative (`Optional[bool]`). Akamai `X-Cache-Key` is parsed as an authoritative signal for cache-key composition.
- `WCP_CACHE_KEYING_UNDETERMINED` (INFO) fires when keying cannot be confirmed; active probing is skipped in that state to avoid inadvertent live-cache poisoning.

**Spec compliance:**
- Active probing is preemptively cancelled when live poisoning is confirmed (was: cooperative, allowed 4 in-flight probes to complete).
```

- [ ] **Step 4: Run the full suite**

Run: `pytest -q`
Expected: all passing (should be ~155+ tests now). Zero failures.

- [ ] **Step 5: Run slow tests (live integration)**

Run: `pytest -q -m slow`
Expected: 3 live cache-auditor tests pass against cdnjs/httpbin. If network is unavailable, this step is optional — note skip reason in final report.

- [ ] **Step 6: Lint and format**

Run: `black . && ruff check --fix . && black --check . && ruff check .`
Expected: `All done!` (black) and no ruff diagnostics.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml README.md
git commit -m "chore(cache): bump version to 0.4.1 and document changelog

v0.4.1 ships five detection/correctness/spec-compliance fixes to
the cache module. All in-place; no API breakage; Python 3.9+.
"
```

- [ ] **Step 8: Final verification**

Run:
```bash
git log main..HEAD --oneline
```
Expected output: 9 focused commits (Tasks 2-10), one per priority. Clean history for bisect.

Run: `pytest -q`
Expected: green.

Run: `git status`
Expected: `nothing to commit, working tree clean`.

---

## Spec Coverage Checklist

| Spec section | Covered by |
|---|---|
| §2.1 Alt-Svc blind spot | Task 3 |
| §2.1 Set-Cookie under-classification | Task 4 |
| §2.2 is_cached age fallback | Task 5 |
| §2.2 query_string_keyed conservative | Task 8 |
| §2.3 Preemptive abort | Task 9 |
| §2.4 Akamai X-Cache-Key wiring | Tasks 6, 7, 8 |
| §5.1 HEADER_CONTEXTS additions | Tasks 3, 4 |
| §5.2 CONTEXT_TO_SEVERITY routing | Tasks 3, 4 |
| §5.3 New finding definitions | Task 2 |
| §5.4 is_cached widening | Task 5 |
| §5.5 Decision table | Task 8 |
| §5.5 _akamai_qs_in_key parser | Task 6 |
| §5.5 _resolve_buster_from_vary helper | Task 7 |
| §5.5.1 Active-probing safety gate | Task 8 |
| §5.6 Preemptive probe cancellation | Task 9 |
| §5.7 Undetermined finding emission | Task 8 |
| §8.1 Unit tests | Tasks 2-9 |
| §9 Release checklist | Task 10 |

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-18-cache-module-v041-hardening-plan.md`.
