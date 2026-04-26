# Fetch Metadata Enforcement Probing — Design Specification

**Target version:** Corsair v0.5.3
**Author:** Fevra (with Claude)
**Date:** 2026-04-26
**Research source:** `RESEARCH/Fetch_Metadata_Enforcement_Probing_Implementation_Reference.md`
**Status:** Approved for implementation

---

## 1. Goal & Threat Model

### 1.1 What this module detects

A new DAST module that probes whether an HTTP server enforces a **Fetch Metadata
resource isolation policy** — server-side rejection of requests where
`Sec-Fetch-Site: cross-site` is paired with non-`navigate` modes. Browsers send
`Sec-Fetch-*` headers automatically (Chrome 80+, Firefox 87+, Safari 16.4+,
~97% browser coverage); JavaScript cannot override them. Servers that reject
cross-site requests at this layer block browser-initiated CSRF, cross-origin
data leaks via `no-cors` fetches, and cross-origin script inclusion.

### 1.2 Threat model — what FM enforcement defends against

| Attack | FM enforcement defends? | Notes |
|---|---|---|
| CSRF via `<form>` POST | Yes | `Sec-Fetch-Site: cross-site` + `Sec-Fetch-Mode: navigate` + non-GET → blocked |
| CSRF via `fetch()` from attacker page | Yes | `cors` mode + `cross-site` → blocked |
| Cross-origin XSSI / `no-cors` data read | Yes | `no-cors` + `cross-site` → blocked |
| Drive-by clickjacking | Partial | `Sec-Fetch-Dest: iframe` + `cross-site` → blocked |
| CSRF via scripted non-browser client | **No** | Attacker omits Sec-Fetch headers; canonical policy fails open |
| SSRF (server-outbound) | No | FM is inbound only |
| API abuse with stolen Bearer token from non-browser | No | Same as above |

The defining caveat: **Fetch Metadata enforcement is a browser-specific control**.
Non-browser clients (curl, scripted attackers, server-to-server) can omit the
headers entirely; the canonical web.dev reference policy allows absent-header
requests for backward compatibility. Every NOT_ENFORCED finding must carry this
caveat in its description to avoid over-claiming.

### 1.3 Spec status — best-practice, not compliance

The W3C Fetch Metadata Request Headers specification is a Working Draft. It
defines what browsers send; it imposes no normative requirement on servers.
Absence of FM enforcement is a missing defense-in-depth control, not a spec
violation. All findings must be framed accordingly. HIGH severity is reserved
for the case where FM enforcement is the **last** line of defense — no CSRF
token detected, no SameSite=Strict session cookie.

---

## 2. Architecture

### 2.1 Module layout

```
corsair/fetch_metadata/
├── __init__.py          # exports FetchMetadataAuditor
├── auditor.py           # orchestrator
├── probe.py             # probe header sets + EnforcementResult + classify_enforcement()
└── findings.py          # 3 finding factories
```

Flat layout mirrors `corsair/cors/` and `corsair/cache/`. No `corsair/checks/`
prefix (the research doc's assumed structure does not match Corsair's actual
layout).

### 2.2 Class & API surface

```python
class FetchMetadataAuditor:
    def __init__(self, timeout: float = 10.0, active: bool = True): ...
    def audit(self, url: str, baseline_headers: Mapping[str, str]) -> list[Finding]:
        """Synchronous entry; runs asyncio internally."""
```

Sync `audit()` over async internals — matches the established pattern in
`corsair/cors/auditor.py:CORSAuditor.audit()` and
`corsair/cache/auditor.py:CacheAuditor.audit()`.

### 2.3 Reuse from existing modules

- `corsair.cache.oracle.fingerprint_cdn(headers) -> Optional[str]` — pure
  function returning `cloudflare`, `akamai`, `fastly`, `varnish`, `nginx`,
  `cloudfront`, `generic`, or `None`.
- `corsair.models.Finding`, `Severity`, `HeaderCategory` — existing dataclasses.
- `httpx` — already in `dependencies` (no new deps).

### 2.4 No new dependencies

Reuses the existing `httpx` async client. Cookie parsing uses the stdlib pattern
already employed in `corsair/analyzers/cookies.py`.

---

## 3. Probe Sequence

### 3.1 Four probes — effective cost: 3 extra HTTP requests

| Probe | Purpose | Additional headers |
|---|---|---|
| **B** Baseline | Reuse from `scanner.scan_target()` | (none — no Sec-Fetch-* headers) |
| **S** Safe | Confirm server doesn't blanket-reject Sec-Fetch | `Sec-Fetch-Site: same-origin`, `Sec-Fetch-Mode: cors`, `Sec-Fetch-Dest: empty` |
| **A** Adversarial | Primary enforcement signal | `Sec-Fetch-Site: cross-site`, `Sec-Fetch-Mode: cors`, `Sec-Fetch-Dest: empty` |
| **C** Canary | Distinguish stripping from non-enforcement | `Sec-Fetch-Site: corsair-canary-invalid`, `Sec-Fetch-Mode: cors`, `Sec-Fetch-Dest: empty` |

**Probes S, A, C run concurrently** via `asyncio.gather` over a single
`httpx.AsyncClient`. Probe B is the existing scanner baseline — passed in via
`baseline_headers`. The auditor itself does not currently receive the baseline
body, so the auditor performs **its own GET as Probe B** (4 HTTP requests in
total when the auditor runs). This avoids a cross-cutting refactor of
`scanner.scan_target()` to plumb response bodies to all auditors. A future
release may share the baseline.

### 3.2 What is deliberately not in any probe

- **No `Origin` header.** Including a cross-origin Origin would merge the FM
  signal with a CORS rejection signal. Keep them isolated.
- **No `Referer` header.** Avoids triggering Referer-based CSRF heuristics that
  would conflate signals.
- **No POST.** GET produces the same enforcement signal without side-effect
  risk. POST probes are deferred to a future release.
- **No path probing.** Only the provided URL is probed. Path-scoped enforcement
  (`/api/*` etc.) is a future-wave research item.

### 3.3 Header values — exact tokens

```python
SAFE_PROBE_HEADERS = {
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
}

ADVERSARIAL_PROBE_HEADERS = {
    "Sec-Fetch-Site": "cross-site",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
}

CANARY_PROBE_HEADERS = {
    "Sec-Fetch-Site": "corsair-canary-invalid",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
}
```

### 3.4 Body hashing

```python
def _body_hash(body: bytes) -> str:
    return hashlib.sha256(body[:4096]).hexdigest()
```

First 4 KB only — sufficient to discriminate distinct response bodies and
avoids paying for very large pages.

---

## 4. Classification Function

### 4.1 Result enum

```python
class EnforcementResult(Enum):
    ENFORCED = "enforced"
    SOFT_ENFORCED = "soft_enforced"
    NOT_ENFORCED = "not_enforced"
    INCONCLUSIVE = "inconclusive"
```

### 4.2 Status code sets

```python
ENFORCEMENT_STATUS_CODES = {400, 403, 405, 451}
REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
AUTH_STATUS_CODES = {401}
```

`{400, 403, 405, 451}` covers Go `net/http` (403), `django-modern-csrf` (403),
Rails (403), `tower-sec-fetch` (403), and stricter implementations that return
400 on invalid Sec-Fetch values. Body content varies too widely across
frameworks to use as a discriminator — status code is the only reliable signal.

### 4.3 Decision rules — applied in order

```python
def classify_enforcement(
    baseline_status: int,
    safe_status: int,
    adversarial_status: int,
    canary_status: int,
    baseline_body_hash: str,
    adversarial_body_hash: str,
) -> EnforcementResult:
```

1. `safe_status in ENFORCEMENT_STATUS_CODES` → **INCONCLUSIVE** (server
   blanket-rejects Sec-Fetch; signal poisoned).
2. `baseline_status >= 500` or `baseline_status in AUTH_STATUS_CODES` →
   **INCONCLUSIVE** (target unhealthy or behind auth).
3. `adversarial_status in ENFORCEMENT_STATUS_CODES`
   **AND** `canary_status in ENFORCEMENT_STATUS_CODES` → **ENFORCED**
   (server is enforcing; canary value also rejected — strongest signal).
4. `adversarial_status in ENFORCEMENT_STATUS_CODES`
   **AND** `canary_status == baseline_status`
   **AND** `canary` body hash matches baseline → **ENFORCED**
   (server allowlist enforcement; canary value not in the spec enum is
   silently allowed by the server — meaning the server's allowlist contains
   only `same-origin`/`same-site`/`none` and treats the canary the same as
   `cross-site`. This is consistent with the canonical web.dev policy.)

   *Edge case to note in implementation:* rule 4's body-hash equality should
   also be considered satisfied when the canary returns 2xx and matches the
   baseline body — this is the typical case. Rule 3 covers the spec-strict
   case where the canary itself draws a 4xx for an invalid token.

5. `adversarial_status in REDIRECT_STATUS_CODES`
   **AND** `baseline_status not in REDIRECT_STATUS_CODES` →
   **INCONCLUSIVE** (likely auth redirect, not FM rejection).
6. `adversarial_status < 300`
   **AND** `adversarial_body_hash != baseline_body_hash` →
   **SOFT_ENFORCED** (server returned 2xx but modified the body for cross-site
   requests — a softer enforcement pattern; for example, returning a sanitized
   page).
7. `adversarial_status == baseline_status`
   **AND** `canary_status == baseline_status` → **NOT_ENFORCED**
   (clean signal; canary confirms no proxy stripping is masking enforcement).
8. Otherwise → **INCONCLUSIVE**.

### 4.4 The canary's discriminating role

The canary distinguishes three states that look identical on the
adversarial-only signal:

| State | Probe A | Probe C | Result |
|---|---|---|---|
| Server enforces (spec-strict) | 4xx | 4xx | ENFORCED (rule 3) |
| Server enforces (allowlist) | 4xx | 2xx | ENFORCED (rule 4, body-match) |
| Server doesn't enforce, headers reach origin | 2xx | 2xx (=baseline) | NOT_ENFORCED (rule 7) |
| Proxy strips all Sec-Fetch-* before origin | 2xx (=baseline) | 2xx (=baseline) | NOT_ENFORCED (rule 7) — ambiguous, see §6.1 |

States 3 and 4 are not distinguishable from response bodies alone. We narrow
the false-positive surface via CDN-fingerprint-based severity downgrade
(§5.3).

---

## 5. Findings

Three finding IDs registered in a new module-level findings file. Naming
convention follows existing `WCP_*` and `CORS_*` registries — `FM_*` prefix.

### 5.1 `FM_NO_FETCH_METADATA_POLICY` — NOT_ENFORCED finding

**Severity matrix (CDN-aware):**

| Cookie signals | CDN detected? | Severity | Score deduction |
|---|---|---|---|
| No SameSite, no CSRF token | No | HIGH | -10 |
| No SameSite, no CSRF token | Yes | MEDIUM | -6 |
| Partial: SameSite=Lax XOR CSRF token | No | MEDIUM | -6 |
| Partial: SameSite=Lax XOR CSRF token | Yes | LOW | -3 |
| SameSite=Strict + CSRF token | No | LOW | -3 |
| SameSite=Strict + CSRF token | Yes | LOW | -3 |

**`SOFT_ENFORCED` result:** emits this finding ID as well, but at INFO severity
(deduction 0) with description noting "soft enforcement detected — server
returned modified content rather than 4xx; verify the policy actively blocks
unauthorized cross-site access."

**Title:** `No Fetch Metadata Resource Isolation Policy`

**Description (template):**
```
The server returned the same response to a Sec-Fetch-Site: cross-site probe
as to a Sec-Fetch-Site: same-origin probe, indicating no Fetch Metadata
resource isolation policy is enforced. Browser-initiated cross-site requests
(CSRF via fetch, cross-origin data leaks via no-cors) are not blocked at the
server layer.

{mitigation_note}

Caveat: non-browser scripted clients can bypass this control regardless of
enforcement status. Fetch Metadata defends against browser-based CSRF and
cross-origin data leaks, not API abuse or server-to-server attacks.
```

`{mitigation_note}` is one of:
- HIGH (no mitigations): "No CSRF token cookie or SameSite=Strict cookie was detected on this endpoint."
- MEDIUM/LOW (partial): "Partial CSRF mitigations detected: <SameSite=Lax | CSRF token>. Adding Fetch Metadata enforcement would strengthen defense-in-depth."
- LOW (full mitigations): "SameSite=Strict cookies and a CSRF token were detected. Fetch Metadata enforcement would add a third independent layer."
- CDN downgrade suffix: " A CDN was fingerprinted on the response; in rare cases the CDN may strip Sec-Fetch-* headers before reaching origin. Verify on a direct-origin scan."

**`recommendation`:**
```
Implement a server-side resource isolation policy that rejects requests where
Sec-Fetch-Site is cross-site and Sec-Fetch-Mode is not navigate. Start in
logging mode to identify endpoints that need cross-site exemptions, then
switch to blocking. Reference: https://web.dev/articles/fetch-metadata
```

**`example_value`:** the web.dev Python pseudo-code (from research §6).

**`reference_url`:** `https://web.dev/articles/fetch-metadata`

**`compliance_mappings`:**
- All severities: `OWASP:2021:A01`, `CWE-352`, `CWE-693`
- HIGH only (no other CSRF mitigations detected): also include `PCI-DSS:4.0:6.2.4`
- HIGH and MEDIUM: also include `NIST:SP800-53:SC-23`

### 5.2 `FM_FETCH_METADATA_ENFORCED` — ENFORCED finding (positive)

**Severity:** PASS, score deduction 0.

**Title:** `Fetch Metadata Resource Isolation Policy Enforced`

**Description:**
```
The server returned a rejection response (4xx) to a cross-site Fetch Metadata
probe while allowing the same-origin probe. A resource isolation policy is
active and blocking browser-initiated cross-site requests.
```

**`recommendation`:**
```
No action required. Consider logging enforcement rejections for threat
intelligence and reviewing whether sensitive endpoints would benefit from
stricter Sec-Fetch-Mode constraints.
```

**`compliance_mappings`:** `CWE-352` (positive coverage marker).

### 5.3 `FM_FETCH_METADATA_INCONCLUSIVE` — INCONCLUSIVE finding

**Severity:** INFO, score deduction 0.

**Title:** `Fetch Metadata Probe Inconclusive`

**Description:**
```
The Fetch Metadata enforcement probe produced an ambiguous result: {reason}.
This may indicate CDN or reverse proxy header stripping, an authentication
wall preventing probe differentiation, or a non-standard enforcement response.
Manual verification is required.
```

`{reason}` is one of:
- "Safe-probe rejected — server appears to blanket-reject Sec-Fetch headers"
- "Baseline target returned {status} — cannot probe meaningfully"
- "Adversarial probe redirected ({status}); likely auth, not enforcement"
- "Network error during probe sequence"

**`recommendation`:**
```
Scan the origin directly (bypassing CDN) to confirm or rule out enforcement.
Check application middleware for Fetch Metadata policy implementation.
```

### 5.4 Context inference (auditor-internal)

```python
@dataclass
class FMContext:
    has_samesite_strict: bool
    has_samesite_lax: bool
    has_csrf_token: bool
    cdn_detected: bool
```

Derived from baseline `Set-Cookie` headers:

- **Session cookie names** (case-insensitive substring match):
  `{session, sessionid, sid, auth, token, jwt}` — same set as
  `corsair/analyzers/cookies.py:95`.
- **`has_samesite_strict`**: `True` if any session-named cookie has
  `SameSite=Strict`.
- **`has_samesite_lax`**: `True` if any session-named cookie has
  `SameSite=Lax`.
- **`has_csrf_token`**: `True` if any cookie name (case-insensitive) is in
  `{csrftoken, xsrf-token, _csrf, __requestverificationtoken, csrf}`.
- **`cdn_detected`**: `fingerprint_cdn(baseline_headers) is not None`.

HTML body parsing (CSRF meta-tag) is **not** in scope for v0.5.3 — it adds
substantial complexity for marginal precision improvement. May ship in v0.5.4.

---

## 6. Suppression & False-Positive Defenses

### 6.1 The unresolved residual

Two scenarios produce identical observations:

1. **Server doesn't enforce; headers reach origin.** A=B, C=B.
2. **Proxy strips all `Sec-Fetch-*` before origin.** A=B, C=B.

The classification function returns `NOT_ENFORCED` in both cases (rule 7). This
is the residual false-positive surface. The CDN-fingerprint severity downgrade
(§5.1) is the conservative response: when a CDN is fingerprinted, severity is
reduced one step and the description warns operators to verify on a
direct-origin scan.

### 6.2 What gets the downgrade

CDN list reused from `corsair/cache/oracle.py:fingerprint_cdn`:
`cloudflare`, `akamai`, `fastly`, `varnish`, `nginx`, `cloudfront`, `generic`.
All of these trigger the downgrade. Cloudflare is documented as not stripping
Sec-Fetch-* (research §3); the others are inferred-but-unconfirmed
pass-through, so the conservative downgrade is appropriate.

### 6.3 Out of scope for v0.5.3

| Item | Why deferred |
|---|---|
| `Vary: Sec-Fetch-*` static pre-screen | Research §10 OQ3 — useful positive signal but adds spec complexity. Defer to v0.5.4. |
| Stricter canary (e.g., `<script>` value) | Research §3 advanced — modest additional discrimination. Defer to a future research wave. |
| Path probing (`/api`, `/graphql`) | Research §10 OQ4 — explicit future-wave item. |
| POST probes | Research §2 — risk of side effects, GET is sufficient signal. |
| HTML body CSRF-token meta-tag detection | Adds HTML parsing dependency; cookie-name detection is sufficient for v0.5.3. |
| Direct-origin DNS bypass | Out of single-URL DAST scope. |

---

## 7. Integration

### 7.1 CLI flag

Added to `corsair/cli.py`:

```
--fm-probe / --no-fm-probe   Fetch Metadata enforcement probing (default: on)
```

Pattern matches the existing `--cors-probe / --no-cors-probe` and
`--cache-probe / --no-cache-probe` flags. Plumbed through to
`HeadScanner.__init__` as `self.fm_probe: bool`.

### 7.2 `scanner.py` wiring

Inserted after the CORS auditor block (currently at `corsair/scanner.py:188-196`),
before score calculation:

```python
# Fetch Metadata enforcement probe (wave 1)
if self.fm_probe:
    try:
        fm_auditor = FetchMetadataAuditor(timeout=self.timeout, active=True)
        fm_findings = fm_auditor.audit(final_url, headers)
        findings.extend(fm_findings)
    except Exception as e:
        logger.error(f"Fetch Metadata audit failed: {e}")
```

`HeadScanner.__init__` accepts `fm_probe: bool = True`. CLI passes the flag
through.

### 7.3 What the auditor receives

- `final_url`: the post-redirect URL (consistent with cache_auditor and
  cors_auditor inputs).
- `baseline_headers`: parsed response headers from the existing scanner
  baseline. The auditor uses these for **CDN fingerprinting** and **cookie
  context inference** only. The auditor performs its own GET as Probe B (no
  shared body — see §3.1 rationale).

### 7.4 Auditor implementation sketch

```python
class FetchMetadataAuditor:
    def __init__(self, timeout: float = 10.0, active: bool = True):
        self.timeout = timeout
        self.active = active

    def audit(self, url: str, baseline_headers: Mapping[str, str]) -> list[Finding]:
        if not self.active:
            return []
        return asyncio.run(self._audit_async(url, baseline_headers))

    async def _audit_async(
        self, url: str, baseline_headers: Mapping[str, str]
    ) -> list[Finding]:
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
            # Probe B (own baseline), S, A, C concurrently
            # gather, hash bodies, classify, emit findings via factories
```

`follow_redirects=False` is critical — redirect chasing could mask the
adversarial 302 signal that distinguishes auth-redirects from FM-rejections.

### 7.5 Failure handling

Network errors during any probe → return a single
`FM_FETCH_METADATA_INCONCLUSIVE` finding with the network-error reason and
move on. Module-level exceptions are caught and logged at the scanner level
(see §7.2) — same pattern as cache/CORS auditors.

---

## 8. Testing Strategy

### 8.1 Test files

| File | Tests | Scope |
|---|---|---|
| `tests/test_fetch_metadata_probe.py` | ~25 | `classify_enforcement`, probe header sets, body hash, status sets |
| `tests/test_fetch_metadata_findings.py` | ~10 | Severity matrix, compliance mappings, description fields |
| `tests/test_fetch_metadata_auditor.py` | ~6 | End-to-end with mocked `httpx.AsyncClient` |

### 8.2 `test_fetch_metadata_probe.py` — unit tests

**`TestClassifyEnforcement`** — every decision rule:
- Rule 1: `safe_status=403` → INCONCLUSIVE (regardless of A, C).
- Rule 2: `baseline_status=500` → INCONCLUSIVE; `baseline_status=401` → INCONCLUSIVE.
- Rule 3: A=403, C=400 → ENFORCED.
- Rule 4: A=403, C=200, baseline=200, canary body matches baseline body → ENFORCED.
- Rule 5: A=302, baseline=200 → INCONCLUSIVE.
- Rule 6: A=200, body differs → SOFT_ENFORCED.
- Rule 7: A=200, C=200, all hashes match baseline → NOT_ENFORCED.
- Rule 8: A=418 (unclassified) → INCONCLUSIVE.

**`TestProbeHeaderSets`**:
- `SAFE_PROBE_HEADERS` keys exact-match `{Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest}`.
- No `Origin` key in any probe set.
- No `Referer` key in any probe set.
- Canary value is `corsair-canary-invalid` (literal).

**`TestBodyHash`**:
- Identical first 4 KB → identical hash even when later bytes differ.
- One-byte difference in first 4 KB → different hash.

**`TestEnforcementStatusSet`**:
- 400, 403, 405, 451 ∈ ENFORCEMENT_STATUS_CODES.
- 429, 418, 200, 503 ∉ ENFORCEMENT_STATUS_CODES.

### 8.3 `test_fetch_metadata_findings.py` — finding factory tests

**`TestSeverityMatrix`** — six rows from §5.1 each verified:
- `(no_ss, no_csrf, no_cdn) → HIGH, score=-10`
- `(no_ss, no_csrf, cdn) → MEDIUM, score=-6`
- `(lax, no_csrf, no_cdn) → MEDIUM, score=-6`
- `(lax, no_csrf, cdn) → LOW, score=-3`
- `(strict, csrf, no_cdn) → LOW, score=-3`
- `(strict, csrf, cdn) → LOW, score=-3`

**`TestComplianceMappings`**:
- All NOT_ENFORCED severities: `OWASP:2021:A01`, `CWE-352`, `CWE-693` present.
- HIGH only: `PCI-DSS:4.0:6.2.4` present.
- HIGH and MEDIUM: `NIST:SP800-53:SC-23` present.
- LOW: PCI-DSS not present.

**`TestNonBrowserCaveat`**: NOT_ENFORCED description contains the literal
substring `non-browser scripted clients`.

**`TestPositiveFinding`**: `FM_FETCH_METADATA_ENFORCED` has `Severity.PASS`
and score deduction 0.

**`TestInconclusiveFinding`**: `FM_FETCH_METADATA_INCONCLUSIVE` has
`Severity.INFO`, includes the supplied reason in description.

### 8.4 `test_fetch_metadata_auditor.py` — integration with mocked httpx

Pattern: `unittest.mock.patch("httpx.AsyncClient")` + `AsyncMock`. Same shape
as `tests/test_cors_wave2_auditor.py`. Each test stubs the four probe responses
(B, S, A, C) with chosen status codes, headers, and bodies.

| Test | Setup | Assertion |
|---|---|---|
| `test_enforced_emits_pass_finding` | A=403, C=403, S=200, B=200 | One PASS finding, ID `FM_FETCH_METADATA_ENFORCED` |
| `test_not_enforced_no_cdn_high` | All probes 200, no Set-Cookie, no CDN headers | One HIGH finding, score=-10 |
| `test_not_enforced_with_cdn_downgrades` | All 200, baseline headers contain `cf-ray`, no cookies | One MEDIUM finding, score=-6 |
| `test_inconclusive_when_safe_rejects` | S=403 | One INFO finding, ID `FM_FETCH_METADATA_INCONCLUSIVE` |
| `test_full_severity_matrix_via_cookies` | All 200, vary baseline `Set-Cookie` to test Strict+csrftoken vs Lax-only vs none | Severity matches §5.1 |
| `test_disabled_when_active_false` | `FetchMetadataAuditor(active=False).audit(url, {})` | Returns `[]` |

### 8.5 Regression baseline

- Full suite: `python3 -m pytest tests/ --ignore=tests/test_tls_auditor.py -q` must remain at 320 passing **before** the implementation, and ≥360 passing **after**.
- Existing scanner-integration tests (`tests/test_scanner_*`) must continue to pass with `--fm-probe` defaulting on. If mock targets without Set-Cookie produce unexpected NOT_ENFORCED findings that break existing assertions, the implementation will toggle `fm_probe=False` in fixtures rather than weakening the assertions — the existing tests assert specific finding lists.

---

## 9. Release Plan

### 9.1 Implementation tasks (preview — full breakdown in plan)

1. Probe primitives + `classify_enforcement` + unit tests (TDD).
2. Finding templates + severity calibration + factory tests.
3. `FetchMetadataAuditor` integration with mocked httpx + integration tests.
4. CLI flag + `scanner.py` wiring + scanner-integration test verification.
5. v0.5.3 release commit (version bump + README changelog).

### 9.2 Version & changelog

- `corsair/__init__.py`: `__version__ = "0.5.3"`.
- `pyproject.toml`: `version = "0.5.3"`.
- `README.md`: new `### v0.5.3 — Fetch Metadata Probing (2026-04-26)` section
  inserted above the v0.5.2 section. Body must mention:
  - New DAST module: `corsair/fetch_metadata/`.
  - Three new findings: `FM_NO_FETCH_METADATA_POLICY` (HIGH/MEDIUM/LOW),
    `FM_FETCH_METADATA_ENFORCED` (PASS), `FM_FETCH_METADATA_INCONCLUSIVE`
    (INFO).
  - Four-probe canary-extended classification.
  - CDN-fingerprint severity downgrade.
  - CLI flag: `--fm-probe / --no-fm-probe`.
  - No new dependencies.

### 9.3 Out-of-scope future work (documented in roadmap, not v0.5.3)

- `Vary: Sec-Fetch-*` static pre-screen.
- HTML body CSRF meta-tag detection.
- Path-scoped probing (`/api`, `/graphql`).
- POST adversarial probes (gated on `--fm-post-probe`).
- Direct-origin DNS bypass for CDN-fronted targets.

---

## 10. References

- Research source: `RESEARCH/Fetch_Metadata_Enforcement_Probing_Implementation_Reference.md`
- W3C Fetch Metadata Request Headers (Working Draft): https://www.w3.org/TR/fetch-metadata/
- Google web.dev — Protect your resources with Fetch Metadata: https://web.dev/articles/fetch-metadata
- OWASP CSRF Prevention Cheat Sheet (issue #1803): https://github.com/OWASP/CheatSheetSeries/issues/1803
- Go 1.23 net/http CrossOriginProtection: https://pkg.go.dev/net/http#CrossOriginProtection
- Rails PR #56350 (Fetch Metadata CSRF enforcement): https://github.com/rails/rails/pull/56350
- django-modern-csrf: https://pypi.org/project/django-modern-csrf/
- tower-sec-fetch (Rust/Axum): https://github.com/matteojoliveau/tower-sec-fetch
- Cloudflare HTTP headers reference (Sec-Fetch passthrough confirmation): https://developers.cloudflare.com/fundamentals/reference/http-headers/
- CWE-352 Cross-Site Request Forgery: https://cwe.mitre.org/data/definitions/352.html
- CWE-693 Protection Mechanism Failure: https://cwe.mitre.org/data/definitions/693.html
