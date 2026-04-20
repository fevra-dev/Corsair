# CORS DAST Module Design

**Status:** Approved
**Date:** 2026-04-19
**Target version:** v0.5.0 (Wave 1); v0.5.x (subsequent waves)
**Supersedes:** `corsair/analyzers/cors.py` (static analyzer is absorbed into `corsair/cors/passive.py`)

---

## 1. Executive Summary

Corsair today ships a 107-line **static** CORS analyzer (`corsair/analyzers/cors.py`) that inspects response headers on the scan target and flags wildcard ACAO, wildcard + credentials, and null origin. This misses the whole class of CORS misconfigurations that are only detectable by actively probing the target with varied `Origin` headers — arbitrary-origin reflection, subdomain/regex bypasses, protocol downgrade, internal-network origin trust, preflight divergence, and CORS cache poisoning.

This spec defines **CORS DAST (Dynamic Application Security Testing)** — a new `corsair/cors/` module that sends a prioritized sequence of Origin-varied requests, analyzes ACAO/ACAC/Vary reflection, and emits 16 finding classes covering the full taxonomy documented in `RESEARCH/Designing Dynamic CORS DAST for Corsair.md`.

The module mirrors the architecture of the existing `corsair/cache/` auditor (passive phase + concurrent active probes + preemptive abort on critical), reuses its concurrency infrastructure, and integrates into `HeadScanner.scan_target()` as a post-cache audit phase.

**Implementation ships in four waves** so the most-valuable findings (Core 5: reflection, null, wildcard+creds) can ship in v0.5.0 before the bypass matrix, preflight, and cache-key probing land in v0.5.1+.

---

## 2. Goals & Non-Goals

**Goals:**
- Detect the 16 dynamically-observable CORS misconfiguration classes in the research taxonomy.
- Distinguish *exploitable* misconfigurations (arbitrary origin + credentials on authenticated endpoint) from *suspicious* ones (wildcard on a public API) via a signal-driven severity model.
- Integrate cleanly into the existing `HeadScanner.scan_target()` pipeline with a single `--no-cors-probe` opt-out.
- Safe by default — no state-changing probes, no credentialed probes, no traffic to internal networks.

**Non-goals:**
- Crawling or subpath discovery. Each invocation audits a single URL (matches cache/TLS module convention).
- Browser-level enforcement testing. This is a server-side policy scanner — we don't spin up a headless browser.
- Exploit automation. We flag misconfigs; we do not demonstrate exfiltration.
- Mutation testing or fuzzing of Origin values beyond the fixed taxonomy-driven payload set.

---

## 3. Architecture

### 3.1 Package layout

```
corsair/cors/
├── __init__.py       # exports CORSAuditor
├── passive.py        # response-header checks (migrated from analyzers/cors.py)
├── probe.py          # Origin payload generation + httpx probe execution
├── analyzers.py      # response classification → finding ID + sensitivity heuristic
├── auditor.py        # CORSAuditor orchestrator, 3-phase pipeline
└── findings.py       # 16 Finding definitions + get_finding() registry
```

### 3.2 Integration point

`HeadScanner.scan_target()` calls `CORSAuditor().audit(url, headers, cache_context)` **after** the cache module runs. The cache module has already established CDN fingerprint + cache-status; CORS DAST reads those values from `cache_context` instead of re-fingerprinting, saving 1–2 requests per scan.

### 3.3 Deletion and migration

- `corsair/analyzers/cors.py` — **deleted**.
- `corsair/analyzers/__init__.py` — `CORSAnalyzer` entry now thin-wraps `corsair.cors.passive.analyze(headers)`. All existing analyzer-pipeline consumers continue working unchanged.
- Existing tests in `tests/test_analyzers.py` for `CORSAnalyzer` — migrated to `tests/test_cors_passive.py` (not duplicated).

### 3.4 CLI surface (additions to `corsair/cli.py`)

| Flag | Default | Effect |
|---|---|---|
| `--no-cors-probe` | off (probing enabled) | Skip Phase 2 and Phase 3; Phase 1 (passive) still runs. |
| `--cors-evil-origin URL` | `https://evil.example` | Seed origin used for arbitrary-origin reflection probes. |
| `--cors-state-changing` | off | Enable POST/PUT probes for `CORS_POST_LEAK` (Wave 4). Prints ROE warning on first invocation with 5s abort window. Can be skipped with `--yes`. |

### 3.5 Dependencies

`httpx` (already used), `asyncio` (stdlib). **No new runtime dependencies.**

---

## 4. Three-phase pipeline

### 4.1 Phase 1 — Passive (always runs)

Inspects response headers already collected by the main scanner — no additional requests. Final-state emissions:
- `CORS_WILDCARD_CRED` (MEDIUM) when `ACAO: *` and `ACAC: true`. **Ships in Wave 1.**
- `CORS_FRAMEWORK_DEFAULT` (LOW/MEDIUM) when header patterns match Flask-CORS or Express permissive defaults. **Ships in Wave 4** (see §8).
- Baseline `PASS` finding when CORS headers are absent (same-origin policy active). **Ships in Wave 1.**

In Wave 1, Phase 1 emits only `CORS_WILDCARD_CRED` and the baseline `PASS`. The framework-default heuristic is added by Wave 4 without changing the phase-1 contract.

Shares code with `passive.py`. Runs even when `--no-cors-probe` is set.

### 4.2 Phase 2 — Active reflection (opt-out via `--no-cors-probe`)

Sends a fixed matrix of Origin-varied GETs to the target URL. For each response, captures ACAO, ACAC, Vary, Set-Cookie.

**Payload set (~12 GETs):**
- Arbitrary origin: the `--cors-evil-origin` value (default `https://evil.example`)
- Null: `Origin: null`
- Subdomain/regex bypass matrix (derived from target host):
  - `https://evil.{host}` (pre-domain wildcard)
  - `https://{host}.evil.com` (post-domain)
  - `https://{host-tld-stripped}.evil.com` (unescaped dot / TLD confusion)
  - `https://{host}.evil` (suffix-match)
  - `https://anysub.{host}` (wildcard subdomain)
  - `https://{host-prefix}-evil.com` (contains-match)
- Protocol downgrade: `http://{host}` (only when target is HTTPS)
- Internal origins: `http://127.0.0.1`, `http://localhost`, `http://10.0.0.1`, `http://192.168.0.1`

Each probe uses a unique cache-busting query param (`_cb={uuid}`) to avoid polluting live caches.

Results flow through `analyzers.classify_reflection()` which returns a finding ID based on ACAO match + ACAC value + sensitivity heuristic.

### 4.3 Phase 3 — Active preflight + cache-key (opt-out via `--no-cors-probe`)

**Preflight matrix (~4 OPTIONS):**
- `OPTIONS` with `Access-Control-Request-Method: PUT`
- `OPTIONS` with `Access-Control-Request-Method: DELETE`
- `OPTIONS` with `Access-Control-Request-Method: PATCH`
- `OPTIONS` with `Access-Control-Request-Headers: X-Custom`

Compares preflight allow-list against Phase 2 simple-request behavior. Fires `CORS_PREFLIGHT_DIVERGENCE` on mismatch, `CORS_METHODS_HEADERS_BROAD` on overly permissive preflight responses.

**Cache-key divergence probing (~4 GETs):**
Repeats the arbitrary-origin probe with four distinct origins:
1. `--cors-evil-origin` (default `https://evil.example`)
2. `https://evil-b.example`
3. `https://evil-c.example`
4. Request with no `Origin` header at all (baseline for `CORS_VARY_ORIGIN_CONDITIONAL`)

If ACAO differs across origins 1–3 but `Vary: Origin` is absent, fires `CORS_VARY_ORIGIN_MISSING`. If the CDN returns the same cached response body across origins 1–3 with mismatched ACAO, fires `CORS_CDN_CACHE_KEY_MISS`. If `Vary: Origin` is present in responses 1–3 but absent in response 4, fires `CORS_VARY_ORIGIN_CONDITIONAL`.

### 4.4 State-changing probes (Wave 4, opt-in via `--cors-state-changing`)

Off by default. Adds ~4 POST probes for `CORS_POST_LEAK`. Prints ROE warning on first invocation:

```
WARNING: --cors-state-changing enables POST/PUT probes that may
modify server state. Use only on targets you're authorized to test.
Press Ctrl-C within 5 seconds to abort, or wait to continue.
```

### 4.5 Concurrency

Identical pattern to `CacheAuditor._active_probes()` after v0.4.1:
- `asyncio.Semaphore(max_concurrency=5)` bounds in-flight requests.
- `asyncio.Event()` (`abort_event`) set when any CRITICAL finding fires.
- `asyncio.create_task()` for each probe so handles are cancellable.
- `abort_watcher` coroutine cancels pending tasks when `abort_event` fires.
- `asyncio.gather(..., return_exceptions=True)` surfaces `CancelledError` as a skippable result.

### 4.6 Probe budget summary

| Phase | Probes | Opt-out |
|---|---|---|
| 1 (passive) | 0 | never |
| 2 (reflection) | ~12 | `--no-cors-probe` |
| 3 (preflight + cache-key) | ~8 | `--no-cors-probe` |
| 4 (state-changing) | ~4 | off by default; `--cors-state-changing` |
| **Total (default)** | **~20** | |
| **Total (with state-changing)** | **~24** | |

Expected scan overhead on a responsive target: 10–15 seconds.

---

## 5. Finding taxonomy

All 16 findings ship in `corsair/cors/findings.py`. Column **Severity** shows the default with signal-driven adjustment in parens (↓ = downgrade when sensitivity signals absent).

| ID | Title | Severity | Phase | Fires when |
|---|---|---|---|---|
| `CORS_ARBITRARY_ORIGIN_CRED` | Arbitrary origin reflection with credentials | CRITICAL (↓ HIGH) | 2 | ACAO == `--cors-evil-origin` AND ACAC: true |
| `CORS_ARBITRARY_ORIGIN` | Arbitrary origin reflection | HIGH (↓ MEDIUM) | 2 | ACAO == `--cors-evil-origin` AND no ACAC |
| `CORS_NULL_ORIGIN_CRED` | Null origin trusted with credentials | HIGH | 2 | ACAO: null AND ACAC: true |
| `CORS_NULL_ORIGIN` | Null origin trusted | MEDIUM | 2 | ACAO: null AND no ACAC |
| `CORS_WILDCARD_CRED` | Wildcard with credentials | MEDIUM | 1 | ACAO: `*` AND ACAC: true |
| `CORS_SUBDOMAIN_BYPASS` | Subdomain/regex bypass | HIGH (↓ MEDIUM) | 2 | ACAO reflects a bypass-matrix payload |
| `CORS_PROTOCOL_DOWNGRADE` | HTTP origin trusted on HTTPS target | HIGH | 2 | Target is HTTPS AND ACAO matches `http://{host}` |
| `CORS_INTERNAL_ORIGIN` | Internal/private origin trusted | HIGH | 2 | ACAO matches 127.0.0.1, localhost, or RFC1918 |
| `CORS_THIRD_PARTY_XSS_RISK` | Third-party origin with XSS risk | HIGH | 2 (heuristic) | ACAO reflects known-third-party domain + ACAC: true |
| `CORS_PREFLIGHT_DIVERGENCE` | Preflight vs simple divergence | MEDIUM | 3 | GET allowed but OPTIONS denies, or vice versa |
| `CORS_POST_LEAK` | Credentialed POST from untrusted origin | MEDIUM | 3 (gated) | POST allowed with untrusted Origin + ACAC: true |
| `CORS_VARY_ORIGIN_MISSING` | Missing Vary: Origin on dynamic CORS | HIGH | 3 | Active: ACAO differs per Origin, cacheable, no Vary: Origin |
| `CORS_VARY_ORIGIN_CONDITIONAL` | Vary: Origin only when Origin present | MEDIUM | 3 | Vary: Origin present with Origin, absent without |
| `CORS_CDN_CACHE_KEY_MISS` | CDN cache-key omits Origin | MEDIUM | 3 | Repeated Origin-varied probes return identical cached response with mismatched ACAO |
| `CORS_FRAMEWORK_DEFAULT` | Misconfigured framework default | LOW–MEDIUM | 1 | Passive: headers match Flask-CORS / Express permissive defaults |
| `CORS_METHODS_HEADERS_BROAD` | Overly broad methods/headers | LOW | 3 | OPTIONS response lists `*` or all verbs + `Access-Control-Allow-Headers: *` |

**Meta findings:**
- `CORS_PROBE_INCONCLUSIVE` (INFO) — target returned 401/403/5xx on every probe; analysis skipped.
- `CORS_PHASE_TIMEOUT` (INFO) — a phase hit the 60s global timeout.

Total Finding registry entries: **16 + 2 meta = 18**.

### 5.1 Sensitivity heuristic

Implemented in `analyzers.classify_sensitivity(response, request_headers) -> Literal["sensitive", "unknown"]`.

Returns `"sensitive"` if ANY of these signals is present:
1. `Set-Cookie` header on the response.
2. `Authorization` header in the scan's original request (set by user).
3. Response `Content-Type` matches `application/json` or `application/*+json`.
4. Anonymous probe (no cookies) returns 302/303 to a path containing `login`, `signin`, `auth`, or `sso`.

Otherwise `"unknown"` — findings with the (↓) marker emit at the lower severity, and the Finding `description` field is extended with:

> "Severity downgraded from {default} to {current} because no sensitivity signal (authenticated session, JSON API, or login redirect) was observed. If this endpoint returns sensitive data under authentication, manually confirm and escalate."

### 5.2 Finding ID naming convention

Matches existing cache module `WCP_*` style: `CORS_` prefix, uppercase, underscore-separated. All IDs are stable contract — once shipped, renames require a deprecation cycle.

---

## 6. Safety & error handling

### 6.1 Probe isolation

- All probes use unique cache-busting query params (`_cb={uuid}`) to avoid poisoning live caches.
- Probes only modify the `Origin` request header (plus preflight-specific `Access-Control-Request-*`). They do NOT send real cookies or Authorization headers — only what Corsair was configured to send. Per Q2 decision, credentialed probing is out of scope.
- Internal-origin probes (CORS-008) send `Origin: http://127.0.0.1` as a request header; we do NOT actually connect to internal networks. Safe by construction.

### 6.2 Preemptive abort on confirmed CRITICAL

When `CORS_ARBITRARY_ORIGIN_CRED` (or any CRITICAL) fires, `abort_event.set()` is called inside the probe's classifier. The `abort_watcher` cancels all pending probe tasks, same pattern as cache v0.4.1. Under 2 seconds wall-clock from confirmation to full stop.

### 6.3 Error handling per edge case

| Condition | Behavior |
|---|---|
| No CORS headers on any probe | Phase 1 emits PASS finding; Phase 2/3 skipped |
| Same-origin echo (server echoes Origin matching own host) | Not a finding; classifier treats as correct |
| Target behind auth gate (401/403 on all probes) | Emit `CORS_PROBE_INCONCLUSIVE` INFO; continue |
| 5xx on probe | Retry once with 1s backoff; if still failing, skip without finding |
| HTTP-only target | Skip `CORS_PROTOCOL_DOWNGRADE` probe (not meaningful) |
| httpx connect error | Log at DEBUG; if >50% of probes in a phase fail, emit phase-level warning |

### 6.4 Timeouts

- Per-probe timeout: **10s** (matches cache module default).
- Per-phase timeout: **60s**. Exceeded → emit `CORS_PHASE_TIMEOUT` INFO and move to next phase.

### 6.5 State-changing probes

Off by default. Opt-in via `--cors-state-changing`. First invocation prints ROE warning with 5-second abort window unless `--yes` is also passed (for CI automation). Only adds POST probes; no PUT/DELETE/PATCH in Wave 4.

---

## 7. Testing strategy

### 7.1 Test files

| File | Purpose |
|---|---|
| `tests/test_cors_passive.py` | Response-header classification; migrated from `tests/test_analyzers.py`'s CORS tests |
| `tests/test_cors_probe.py` | Payload generation + probe execution (`respx`-mocked httpx) |
| `tests/test_cors_analyzers.py` | `classify_reflection`, `classify_sensitivity` (4×2 signal truth table) |
| `tests/test_cors_findings.py` | Finding registry integrity — 18 entries, severities match §5, descriptions present |
| `tests/test_cors_auditor_unit.py` | 3-phase pipeline, opt-out flags, preemptive abort, POST gate |
| `tests/test_cors_integration.py` | `@pytest.mark.slow` — live smoke tests against `httpbin.org` and a permissive CORS fixture |

### 7.2 Fixtures & regression locks

- Shared `_mock_response(headers, status=200, body="")` helper.
- **Golden-file test** for `build_bypass_matrix("example.com")` — produces an exact 6-item list. Any change to payload generation breaks the test; intentional changes require updating the golden file.
- Finding registry integrity test: `len(FINDINGS) == 18` + per-ID severity check.

### 7.3 Coverage targets

- Unit: every finding ID has at least one firing test and one negative test.
- Unit: sensitivity heuristic has a full 4×2 truth table (all four signals × present/absent).
- Orchestration: abort path, POST gate, timeout path, opt-out flags each have dedicated tests.
- Integration: smoke only — confirms end-to-end pipeline executes, not comprehensive.

### 7.4 Explicitly NOT testing

- Real CDN cache behavior (stubbed via fixtures).
- Browser CORS enforcement (out of scope).
- Mutation testing.

---

## 8. Implementation priority order (10 tasks, 4 waves)

### Wave 1 — Scaffolding & Core 5 (ships v0.5.0)

1. **Worktree + package skeleton.** `corsair/cors/__init__.py`, empty module files, test files with `pytest.importorskip` stubs.
2. **Finding definitions for Core 5.** `CORS_ARBITRARY_ORIGIN_CRED`, `CORS_ARBITRARY_ORIGIN`, `CORS_NULL_ORIGIN_CRED`, `CORS_NULL_ORIGIN`, `CORS_WILDCARD_CRED` + `get_finding()` registry + `test_cors_findings.py`.
3. **Migrate `analyzers/cors.py` → `corsair/cors/passive.py`.** Update registry wrapper; move tests. **Zero behavior change** (regression gate).
4. **Active probe infrastructure.** `probe.py` with `build_origin_probe(url, origin)`, `run_probes(client, probes)`, semaphore + `abort_event` concurrency.
5. **Reflection classifier.** `analyzers.py` with `classify_reflection()` and `classify_sensitivity()`. 4×2 sensitivity truth-table tests.
6. **`CORSAuditor` wiring.** 3-phase pipeline (passive + active reflection only in Wave 1). `HeadScanner.scan_target()` integration. `--no-cors-probe` and `--cors-evil-origin` flags.

### Wave 2 — Bypass matrix & protocol/internal (ships v0.5.1)

7. **Bypass-matrix payloads + 3 findings.** `build_bypass_matrix(host)` with golden-file lock + `CORS_SUBDOMAIN_BYPASS`, `CORS_PROTOCOL_DOWNGRADE`, `CORS_INTERNAL_ORIGIN` findings + classifier extensions.

### Wave 3 — Preflight & cache-key (ships v0.5.2)

8. **Preflight probe.** OPTIONS with request-method/headers matrix + `CORS_PREFLIGHT_DIVERGENCE`, `CORS_METHODS_HEADERS_BROAD`.
9. **Cache-key divergence probing.** `CORS_VARY_ORIGIN_MISSING`, `CORS_VARY_ORIGIN_CONDITIONAL`, `CORS_CDN_CACHE_KEY_MISS`. Cross-reference `WCP_NO_VARY_ORIGIN` in descriptions.

### Wave 4 — State-changing, framework, third-party, polish (ships v0.5.3)

10. **Final findings + release.** `CORS_POST_LEAK` (behind `--cors-state-changing` with ROE warning) + `CORS_THIRD_PARTY_XSS_RISK` + `CORS_FRAMEWORK_DEFAULT` (Flask-CORS / Express heuristics) + live-integration smoke tests + version bump to v0.5.3 + changelog.

Each wave is independently shippable. Wave 1 alone covers ~80% of real-world CORS bugs.

---

## 9. Open questions / future work

Items explicitly deferred out of v0.5.0 scope:

- **Credentialed probing** — sending real cookies / auth from the scan session with varied Origins. Valuable for endpoints that only emit CORS headers when authenticated, but risks rate-limiting and exercising sensitive paths. Revisit in v0.6 if demand arises; would need new CLI flag `--cors-credentialed` with its own ROE warning.
- **Subpath discovery** — scanning `/api/*` endpoints alongside the primary URL. Better suited to a separate "crawler" module than the CORS auditor itself.
- **Browser-based confirmation** — launching headless Chrome to verify findings are browser-exploitable. Out of scope; would require adding a browser dependency.
- **Known-XSS third-party catalog for `CORS_THIRD_PARTY_XSS_RISK`** — Wave 4 ships with a small hardcoded list; a dynamic catalog (e.g., fetched from a curated threat feed) is a v0.6 concern.
- **Custom payload injection** — letting users add their own Origin values to the probe matrix. `--cors-evil-origin` already covers the most common case (a user's own attacker domain).

---

## 10. References

- `RESEARCH/Designing Dynamic CORS DAST for Corsair.md` — 16-class taxonomy source.
- `RESEARCH/corsair_cors_dast_research.md` — probe-set derivations, prior-art comparison.
- `RESEARCH/CORS-DAST-Research-Prompt.md` — original research prompt.
- PortSwigger, "Exploiting CORS misconfigurations" — https://portswigger.net/web-security/cors
- MDN CORS reference — https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- `docs/superpowers/specs/2026-04-15-web-cache-poisoning-design.md` — architecture pattern this module mirrors.
- `docs/superpowers/specs/2026-04-18-cache-module-v041-hardening-design.md` — preemptive-abort pattern this module reuses.
