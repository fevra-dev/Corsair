# Alt-Svc Cache-Poisoning Detection Hardening — Design Spec

**Target version:** Corsair v0.5.2 (cache module feature bump)
**Status:** Design approved 2026-04-24
**Supersedes research:** `RESEARCH/Alt-Svc Cache Poisoning Research.md`, `RESEARCH/alt_svc_implementation_reference.md` (premise partially stale — v0.4.1 already shipped canary-based Alt-Svc reflection detection)

---

## 1. Scope

### 1.1 Goal

Harden the already-shipped Alt-Svc cache-poisoning detection (v0.4.1 added `WCP_ALT_SVC_POISONING`) with:

1. **Correctness:** upgrade the reflection check from plain substring match to an alt-authority-anchored regex, handling `Alt-Svc: clear`, multi-value headers, and parameter-value false positives.
2. **Efficiency:** CDN-aware pre-check that suppresses the active Alt-Svc reflection probe on providers that always sanitize origin Alt-Svc (Cloudflare, Fastly, Akamai-with-HTTP/3).
3. **Coverage:** three new passive findings on the baseline `Alt-Svc` value, detecting suspicious configurations that don't require canary reflection:
   - Cross-registrable-domain alt-authority (MEDIUM)
   - Private / invalid-TLD alt-authority host (MEDIUM)
   - Excessive persistence: `ma > 30 days AND persist=1` (LOW)

### 1.2 Out of scope

- **HTTP/2 `ALTSVC` frame inspection.** httpx does not expose HTTP/2 frame types 0x0a as response metadata; capturing frame-level `ALTSVC` advertisements would require an alternative HTTP/2 client. Documented as a known limitation.
- **Port-only reflection** (X-Forwarded-Port reflected into the port component of alt-authority). Low-value signal relative to the host-injection vector; deferred.
- **Partial reflection** (first-label-only match). The research itself recommends deferring until live testing demonstrates the need.
- **Passive Alt-Svc analysis behind Cloudflare/Fastly/Akamai+HTTP/3.** The pre-check suppresses the *active probe*, but passive analyzers run on every target regardless of CDN. This is deliberate: passive is cheap, and defense-in-depth catches cases where a CDN changes policy or has a bug.

### 1.3 Deliverables

- One new module: `corsair/cache/altsvc.py`.
- Three new findings registered in `corsair/cache/findings.py`.
- One new runtime dependency: `tldextract>=5.0.0`.
- Edits to `corsair/cache/reflect.py`, `corsair/cache/probe.py`, `corsair/cache/auditor.py` (thin-caller wire-ups, no logic duplication).
- New test file: `tests/test_cache_altsvc.py` (~30 unit tests).
- New integration tests in `tests/test_cache_altsvc_integration.py` (~5 tests).
- Version bumps: `corsair/__init__.py`, `pyproject.toml` → `0.5.2`.
- README changelog entry.

---

## 2. Architecture

### 2.1 New module: `corsair/cache/altsvc.py`

Single source of truth for Alt-Svc grammar knowledge, canary detection, passive analysis, and pre-check logic. Mirrors the isolation pattern already established by `corsair/cache/oracle.py` (CDN fingerprinting).

**Public API:**

```python
@dataclass(frozen=True)
class AltSvcEntry:
    protocol_id: str        # "h3", "h2", "h3-29", ...
    host: Optional[str]     # None when alt-authority was port-only (":443")
    port: int
    ma: Optional[int]       # seconds; None when omitted (RFC default 86400)
    persist: bool           # True when persist=1 is present

def parse_alt_svc(value: str) -> List[AltSvcEntry]: ...
    # Returns [] for "clear", empty, or malformed input. Never raises.

def detect_alt_svc_canary(value: str, canary: str) -> bool: ...
    # Alt-authority-anchored regex. Replaces plain substring check in reflect.py.

def analyze_alt_svc_suspicious(
    value: str,
    target_hostname: str,
) -> List[str]: ...
    # Returns finding IDs: subset of
    #   ["WCP_ALT_SVC_CROSS_DOMAIN",
    #    "WCP_ALT_SVC_PRIVATE_HOST",
    #    "WCP_ALT_SVC_EXCESSIVE_PERSISTENCE"]

def should_probe_alt_svc(
    cdn_fingerprint: Optional[str],
    baseline_headers: Mapping[str, str],
) -> bool: ...
    # False on Cloudflare, Fastly, and Akamai when baseline Alt-Svc contains ma=93600.
    # True otherwise (including unknown CDN / no CDN).
```

### 2.2 Data flow through `CacheAuditor`

```
CacheAuditor.audit()
├── baseline request → response.headers["alt-svc"]
├── Phase: passive analysis
│   └── analyze_alt_svc_suspicious(baseline_alt_svc, target_host)
│       └── emits 0-3 passive findings (A, B, C)
├── Phase: active reflection probe
│   ├── should_probe_alt_svc(cdn_fp, baseline_headers)
│   │   └── False → emit WCP_PROBE_SKIPPED (existing finding, reused)
│   └── run canary probes → detect_alt_svc_canary(...)
│       └── emits WCP_ALT_SVC_POISONING on match
```

### 2.3 Touch points (edits, not rewrites)

- **`reflect.py`** — in the loop over `HEADER_CONTEXTS`, branch on header name. For `alt-svc`, call `altsvc.detect_alt_svc_canary()`. Other headers unchanged.
- **`probe.py`** — insert `altsvc.should_probe_alt_svc()` gate before dispatching the Alt-Svc-targeted canary probe batch. On skip, emit `WCP_PROBE_SKIPPED`.
- **`auditor.py`** — call `altsvc.analyze_alt_svc_suspicious()` in the passive phase. Emit findings via existing `get_finding()` helper.
- **`findings.py`** — register 3 new `Finding` templates.
- **`pyproject.toml`** — add `tldextract>=5.0.0` to core dependencies.

### 2.4 Module-boundary invariants

- `reflect.py` and `probe.py` do not import `re` or `tldextract` for Alt-Svc work — all parsing lives in `altsvc.py`.
- `altsvc.py` does not import `httpx`, `CacheAuditor`, or other cache-module internals — it's pure logic over strings and fingerprint tags.
- Passive analyzers are deterministic and do not issue network requests.

---

## 3. Passive Detection Rules

### 3.1 `WCP_ALT_SVC_CROSS_DOMAIN` — MEDIUM

**Rule:** For each `AltSvcEntry` with `host is not None`, compute `tldextract.extract(host).registered_domain` and `tldextract.extract(target_hostname).registered_domain`. Emit finding if they differ (case-insensitive).

**Why MEDIUM:** A cross-registrable-domain Alt-Svc is almost never a legitimate configuration — CDNs either use port-only alt-authorities (`":443"`) or the origin hostname. A public response advertising `h3="evil.net:443"` from `api.example.com` is a strong signal of either active poisoning or serious misconfiguration.

**Short-circuits:**
- `host is None` → no finding (port-only authority aliases to origin).
- `host == target_hostname` → no finding (explicit origin echo).
- Empty or malformed Alt-Svc → no finding (parser returns empty list).

**PSL awareness:** `tldextract` handles multi-label TLDs (`.co.uk`, `.com.au`, `.github.io`). A heuristic label-strip would misfire on these and is not acceptable at MEDIUM severity.

### 3.2 `WCP_ALT_SVC_PRIVATE_HOST` — MEDIUM

**Rule:** For each `AltSvcEntry` with `host is not None`, emit finding if **any** of:

- `host` parses as an IP (`ipaddress.ip_address(host)`) and `is_private` or `is_loopback` is True — covers `127.0.0.1`, `::1`, `10.*.*.*`, `172.16–31.*.*`, `192.168.*.*`, `fe80::/10`.
- `host` ends with a case-insensitive match to one of: `.local`, `.internal`, `.invalid`, `.localhost`, `.test`, `.example` (non-public pseudo-TLDs per RFC 2606, RFC 6761).
- `tldextract.extract(host).suffix == ""` **and** `host` is not an IP literal — indicates a bare intranet hostname (e.g., `corp-server`, `db1`).

**Why MEDIUM:** A public response advertising private infrastructure is an information-disclosure / configuration-leak signal with direct security impact. Legitimate deployments do not reach this state.

**Emission:** once per response, even if multiple entries qualify.

### 3.3 `WCP_ALT_SVC_EXCESSIVE_PERSISTENCE` — LOW

**Rule:** Emit finding when **any** `AltSvcEntry` has both:
- `ma > 2_592_000` (> 30 days)
- `persist is True` (`persist=1` present)

**Why LOW:** Neither condition alone is actionable (Google/CloudFront use `ma=2592000` routinely; `persist=1` is common for roaming support). The combination amplifies the impact window of any future poisoning event by extending browser-side retention beyond the CDN cache TTL by more than a month. Worth flagging but not severe in isolation.

**Thresholds defensible:**
- `ma=2592000` (exactly 30 days) → no emit (matches Google/CloudFront exactly).
- `ma=2592001+` with `persist=1` → emit.

### 3.4 Composition with existing reflection finding

All four findings (`WCP_ALT_SVC_POISONING` reflection + 3 passive) emit independently on the same response. This mirrors the existing cache module pattern where `WCP_PERMISSIVE_CACHE_CONTROL` and `WCP_CACHE_PUBLIC_SENSITIVE` both fire on overlapping signals. Each finding documents an independent security property:

- Reflection → the injection vector.
- Cross-domain → the destination.
- Private-host → the leaked infrastructure.
- Excessive-persistence → the amplification factor.

Remediation of any single finding does not eliminate the others.

---

## 4. Robustness Upgrades

### 4.1 Alt-authority-anchored canary regex

**Current `reflect.py` behavior:** plain `canary in header_value` for every header. Works for simple cases but matches the canary inside quoted parameter values that are not alt-authorities (low-probability FP) and does not correctly handle `Alt-Svc: clear` (which has no alt-authority and therefore no reflection possible).

**New check in `altsvc.py`:**

```python
def detect_alt_svc_canary(value: str, canary: str) -> bool:
    stripped = value.strip().lower()
    if not stripped or stripped == "clear":
        return False
    pattern = re.compile(
        r'=\s*"[^"]*' + re.escape(canary) + r'[^"]*"',
        re.IGNORECASE,
    )
    return bool(pattern.search(value))
```

**Wire-in (`reflect.py`):**

```python
for header_name, context_id in HEADER_CONTEXTS:
    for key, value in headers.items():
        if key.lower() != header_name:
            continue
        if header_name == "alt-svc":
            matched = altsvc.detect_alt_svc_canary(value, canary)
        else:
            matched = canary in value
        if matched:
            found_contexts.append(context_id)
            break
```

**Correctness properties:**
- `Alt-Svc: clear` → `False` (no alt-authority present).
- Multi-value header (`h2="a:443", h3="b.canary.invalid:443"`) → regex scans full string, matches.
- Canary ONLY in parameter value outside alt-authority: still technically matches the regex because `=` + `"…canary…"` appears. Minor known FP documented in §9; the realistic FP rate is negligible because servers do not emit arbitrary parameter values containing canary hostnames.

### 4.2 CDN pre-check

```python
def should_probe_alt_svc(
    cdn_fingerprint: Optional[str],
    baseline_headers: Mapping[str, str],
) -> bool:
    fp = (cdn_fingerprint or "").lower()
    if fp in {"cloudflare", "fastly"}:
        return False
    if fp == "akamai":
        baseline = baseline_headers.get("alt-svc", "")
        if "93600" in baseline:
            return False
    return True
```

**Call site (`probe.py`):** before dispatching the Alt-Svc-targeted canary batch, call `should_probe_alt_svc(oracle.fingerprint_cdn(baseline), baseline_headers)`. On `False`, emit the existing `WCP_PROBE_SKIPPED` finding with a distinguishing context tag (e.g., `"alt_svc_reflection_precheck"`) for report transparency. Do not emit `WCP_ALT_SVC_POISONING`, even speculatively.

**CDN category rationale:**
- **Cloudflare, Fastly** always override origin Alt-Svc with their own port-only advertisement. Reflection is structurally impossible on these providers.
- **Akamai with HTTP/3 enabled** (detected via `ma=93600` in baseline) also sanitizes. Akamai without HTTP/3 passes Alt-Svc through and remains probeable.
- Any other fingerprint (CloudFront, Varnish, nginx, unknown) → run the probe.

---

## 5. Findings

Three new `Finding` templates registered in `corsair/cache/findings.py` between the existing `_WCP_ALT_SVC_POISONING` and `_WCP_SET_COOKIE_POISONING` entries.

### 5.1 `WCP_ALT_SVC_CROSS_DOMAIN` — MEDIUM

- **Title:** "Alt-Svc alt-authority on different registrable domain"
- **Description:** "The Alt-Svc header advertises an alternative service on a different registrable domain than the request target. A poisoned or malicious Alt-Svc value can pin browsers to an attacker-controlled HTTP/3 endpoint; a cross-domain alt-authority is a strong indicator of either misconfiguration or active exploitation."
- **Recommendation:** "Restrict Alt-Svc alt-authorities to the same registrable domain as the origin, or omit the host portion (port-only alt-authority) so the alternative defaults to the origin hostname."
- **Reference:** RFC 7838 §2.1.
- **Compliance mappings:** `_OWASP_A05`.
- **CWE:** `_CWE_444`.

### 5.2 `WCP_ALT_SVC_PRIVATE_HOST` — MEDIUM

- **Title:** "Alt-Svc advertises private or non-public alt-authority"
- **Description:** "The Alt-Svc alt-authority resolves to a private-network address (RFC1918, loopback) or a non-public TLD (.local, .internal, .invalid). This is almost always an internal-infrastructure leak into a public-facing response and indicates the Alt-Svc value is generated from an untrusted source or a stale internal config."
- **Recommendation:** "Strip Alt-Svc from responses served to the public internet when the alt-authority points to internal infrastructure. Configure the origin or CDN to override Alt-Svc at the edge."
- **Reference:** RFC 7838 §2.1.
- **Compliance mappings:** `_OWASP_A05`, `_OWASP_A01`.
- **CWE:** `_CWE_444`.

### 5.3 `WCP_ALT_SVC_EXCESSIVE_PERSISTENCE` — LOW

- **Title:** "Alt-Svc ma > 30 days combined with persist=1"
- **Description:** "The Alt-Svc header uses both a max-age greater than 30 days and persist=1, causing browsers to retain the alternative service mapping across network-configuration changes for an extended window. This amplifies the impact of any future Alt-Svc cache poisoning event by extending victim lock-in beyond the CDN cache TTL."
- **Recommendation:** "Reduce max-age to 86400 (24h) or less. Omit persist=1 unless the deployment specifically requires alternative services to survive network changes."
- **Reference:** RFC 7838 §3.1.
- **Compliance mappings:** `_OWASP_A05`.
- **CWE:** `_CWE_444`.

**Registry impact:** cache-module `ALL_FINDINGS` size: 20 → 23. Severity score deductions follow existing conventions (MEDIUM = -5, LOW = -2) — no new scoring rules.

---

## 6. Testing

### 6.1 Unit tests: `tests/test_cache_altsvc.py`

**`TestParseAltSvc`** (8 tests) — golden-file parser behavior:
- Single entry, port-only authority.
- Single entry, host + port + ma + persist.
- Multi-value header, order preserved.
- Draft protocol-id (`h3-29`) preserved.
- `clear` directive → empty list.
- Empty / whitespace → empty list.
- Malformed (unclosed quote, missing `=`) → empty list, no exception.
- Unknown parameters ignored gracefully.

**`TestDetectAltSvcCanary`** (5 tests):
- Canary in single-entry host → True.
- Canary in second entry of multi-value header → True.
- `Alt-Svc: clear` → False.
- Canary only inside a quoted parameter value (documented FP boundary) → True (lives with it).
- Empty / malformed input → False.

**`TestCrossDomain`** (5 tests, uses real `tldextract`):
- `api.example.com` vs `evil.net` → emit.
- `api.example.com` vs `h3.example.com` → no emit.
- `api.example.co.uk` vs `cdn.example.co.uk` → no emit (PSL handles `.co.uk`).
- `api.example.com` vs `example.co.uk` → emit.
- Port-only authority → no emit.

**`TestPrivateHost`** (6 tests):
- `127.0.0.1` → emit.
- `10.0.0.1` / `192.168.1.1` / `172.16.0.1` → emit.
- `::1` / `fe80::1` → emit.
- `.local` / `.internal` / `.invalid` / `.localhost` / `.test` / `.example` → emit.
- Bare hostname (no TLD, not IP) → emit.
- Regular public hostname → no emit.

**`TestExcessivePersistence`** (4 tests):
- `ma=2592001; persist=1` → emit.
- `ma=2592000; persist=1` → no emit (boundary).
- `ma=31536000` without persist → no emit.
- `persist=1` with default ma → no emit.

**`TestShouldProbeAltSvc`** (5 tests):
- `cloudflare` → False.
- `fastly` → False.
- `akamai` + baseline `ma=93600` → False.
- `akamai` + baseline `ma=86400` → True.
- `None` / unknown → True.

### 6.2 Integration tests: `tests/test_cache_altsvc_integration.py`

**~5 end-to-end scenarios** through `CacheAuditor` using `respx`-mocked httpx:

- Public cross-domain Alt-Svc with `ma=3600000; persist=1` → 2 findings (cross-domain + excessive-persistence).
- Internal-IP Alt-Svc → 1 finding (private-host).
- Reflection probe fires AND alt-authority is cross-domain → 2 findings (`WCP_ALT_SVC_POISONING` + `WCP_ALT_SVC_CROSS_DOMAIN`) both emit.
- `cdn_fingerprint="cloudflare"` → probe skipped, `WCP_PROBE_SKIPPED` emits; passive runs.
- Missing / empty Alt-Svc → no new findings, no exceptions.

### 6.3 Regression

Must pass unchanged:
- `tests/test_cache_reflect.py` (existing Alt-Svc reflection baseline).
- `tests/test_cache_probe.py`.
- `tests/test_cache_auditor.py`.

**Projected full-suite count:** 283 (post-CORS-Wave 2) → ~320 passed after v0.5.2.

---

## 7. Release

**Version:** Corsair v0.5.1 → v0.5.2.

- `corsair/__init__.py`: `__version__ = "0.5.2"`.
- `pyproject.toml`: `version = "0.5.2"`.
- `README.md`: new changelog section `### v0.5.2 — Alt-Svc Hardening (<release-date>)` inserted above v0.5.1 entry. Release date filled at commit time.

**Dependency change:** `tldextract>=5.0.0` added to core `dependencies` in `pyproject.toml`. No optional-extras changes.

---

## 8. Task Breakdown (Preview)

Implementation plan will be written in a follow-up document (`docs/superpowers/plans/...`). Task order proposed:

1. **Parser & primitives** — `altsvc.py` with `AltSvcEntry` + `parse_alt_svc()`.
2. **Canary detector & reflect.py wire-up.**
3. **Passive analyzers** — all three rules + `tldextract` dependency.
4. **Pre-check** — `should_probe_alt_svc()` + probe.py wire-up.
5. **Finding registry** — 3 Finding templates.
6. **Auditor integration** — passive phase call + end-to-end tests.
7. **Release v0.5.2.**

Each task is independently shippable and leaves the test suite green.

---

## 9. Known Limitations

- **HTTP/2 `ALTSVC` frame** (frame type 0x0a): httpx does not surface these. A server that advertises Alt-Svc only via ALTSVC frames (not response headers) will not trigger any Corsair detection. Mitigation: documented here; Chrome DevTools and Wireshark are the reference tools for frame-level inspection.
- **Parameter-value false positive in canary regex:** a server emitting a canary string inside a quoted non-alt-authority parameter value would match. The probability is negligible because servers do not emit arbitrary hostnames inside parameter values, and Corsair canaries are UUID-derived.
- **Partial reflection** (first-label-only): not detected. The research recommends deferring this until live testing demonstrates the need.
- **Port-only reflection** (X-Forwarded-Port → alt-authority port): not detected. Low-severity variant; deferred.
- **`tldextract` PSL cache staleness:** `tldextract` caches the Public Suffix List on disk and updates periodically. A newly-added eTLD could briefly be misclassified. Impact is bounded — misclassification produces at most one false MEDIUM finding on a cross-domain check, which is a tolerable failure mode.

---

## 10. References

- RFC 7838 — HTTP Alternative Services.
- RFC 9460 — Service Binding and Parameter Specification via the DNS (SVCB/HTTPS records).
- RFC 2606, RFC 6761 — Reserved Top-Level DNS Names (`.local`, `.invalid`, etc.).
- `RESEARCH/Alt-Svc Cache Poisoning Research.md` — threat-model and CDN behavior matrix.
- `RESEARCH/alt_svc_implementation_reference.md` — detection specification (§5.1, §5.4, §8 incorporated here; §7 stale).
- Existing shipped implementation: commits `904e605` (reflect.py Alt-Svc entry), `c5874e4` (`WCP_ALT_SVC_POISONING` finding), `3013621` (v0.4.1 merge).
- `corsair/cache/oracle.py` — CDN fingerprinting source used by the pre-check.
