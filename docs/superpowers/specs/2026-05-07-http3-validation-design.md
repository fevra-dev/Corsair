# HTTP/3 Validation — Design Spec

**Version target:** Corsair / HeadScan **v0.6.0**
**Author:** Brainstorming session, 2026-05-07
**Status:** Approved for implementation planning
**Source research:** `RESEARCH/Corsair HTTP3 Research - Claude.md` (Objectives 1, 2, 3, 6)
**Companion memory:** `~/.claude/projects/-Users-fevra-Apps-HeadScan/memory/project_h3_v060_scope.md` (deferred Tier B/C scope)

---

## 1. Goal

Build the first public security scanner that combines a live HTTP/3 client with security-header analysis in a single binary. v0.6.0 ships **Tier A** of the HTTP/3 research:

- **0-RTT replay vulnerability detection** (CVE-2024-39321 anchor) via combined evidence from QUIC session-ticket inspection (`max_early_data_size`) and RFC 8470 `Early-Data: 1` header response classification.
- **HTTP/1.1 vs HTTP/3 security-header drift analysis** — presence and value-drift across an explicit allowlist.
- **LSQUIC pre-handshake DoS fingerprint** (CVE-2025-54939) — passive `Server` + `Alt-Svc` correlation; no probe required.

No existing public scanner (testssl.sh, sslyze, Mozilla Observatory, SecurityHeaders.com, Snyk) ships an HTTP/3 client paired with security-header analysis at time of release. This is the moat.

**Tier B/C deferred to v0.6.1+:** QPACK `SETTINGS_MAX_FIELD_SECTION_SIZE` advertisement check, Alt-Svc-without-HSTS, Alt-Svc long max-age, Connection-ID rotation privacy. Tracked in the companion memory file.

---

## 2. Architecture

A new optional subsystem at **`corsair/h3/`**, mirroring the layout patterns established by `corsair/integrity_policy/` (v0.5.5) and `corsair/fetch_metadata/`. The entire subsystem is gated behind a new `[h3]` extras group — `import corsair.h3` works without `aioquic`, but actually running a probe requires `pip install corsair-scan[h3]`.

```
corsair/h3/
├── __init__.py    # Public API: H3Auditor; sets h3_available flag
├── client.py      # aioquic-backed scan_h3(); only file that imports aioquic
├── probe.py       # Pure-logic helpers: Alt-Svc → h3 target derivation,
│                  # LSQUIC fingerprint heuristic. No network I/O.
├── diff.py        # Pure-logic H1/H3 header diff (security allowlist,
│                  # presence + value-drift). No network I/O.
├── findings.py    # Finding template registry (H3-001..H3-003) + builders
└── auditor.py     # H3Auditor orchestrator; sync wrapper around async client
```

**Module boundary table:**

| Module | Imports `aioquic`? | Pure logic? | Why |
|---|---|---|---|
| `client.py` | yes | no | Only file allowed to fail on missing extra |
| `probe.py` | no | yes | Trigger derivation + LSQUIC heuristic — testable without network |
| `diff.py` | no | yes | Header comparison — easy unit tests |
| `findings.py` | no | yes | Templates and builders |
| `auditor.py` | only via `client.py` import | partial | The mockable seam for unit tests |

**Public API:**
```python
from corsair.h3 import H3Auditor   # always works
auditor = H3Auditor(timeout=10, active=True, user_agent="...")
findings = auditor.audit(url, h1_headers)  # returns list[Finding]
```

**Availability flag** (mirrors `corsair.tls.tls_available`):
```python
# corsair/h3/__init__.py
try:
    from .client import scan_h3   # noqa: F401
    h3_available = True
except ImportError:
    h3_available = False
```

---

## 3. Components

### 3.1 `client.py` — aioquic-backed H3 client

Single async function:

```python
async def scan_h3(
    url: str,
    timeout: float = 10.0,
    user_agent: str = "Corsair/0.6.0 (HTTP Security Scanner)",
) -> H3ScanResult: ...
```

`H3ScanResult` is a frozen dataclass:

```python
@dataclass(frozen=True)
class H3ScanResult:
    url: str
    status: Optional[int]                # response :status, or None on failure
    headers: dict[str, str]              # response headers (lowercased keys)
    quic_version: Optional[int]          # captured from QUIC config
    early_data_capability: int           # max_early_data_size from session ticket; 0 if absent
    error: Optional[str]                 # error class string; None on success
    duration_ms: float
```

**Connection sequence (single connection):**
1. UDP connect to `(host, port)` derived from Alt-Svc (default 443 if Alt-Svc port elided).
2. QUIC handshake with H3 ALPN (`h3`, fallback to `h3-29` for older drafts).
3. TLS 1.3 NewSessionTicket arrives → `session_ticket_handler` callback captures `max_early_data_size`.
4. Send single H3 HEAD request to `/` with `early-data: 1` user header.
5. Receive `:status` and response headers via `HeadersReceived` event.
6. Close connection; build and return `H3ScanResult`.

Both 0-RTT signals (`max_early_data_size` from the ticket *and* the `Early-Data: 1` response status) are observable in this single connection — no two-connection replay required for v0.6.0.

**Exception → error string mapping (full taxonomy):**

| Exception class | error string |
|---|---|
| `asyncio.TimeoutError` | `"timeout after <N>s"` |
| `ConnectionRefusedError`, `OSError` (ECONNREFUSED, EHOSTUNREACH) | `"connection refused"` or `"udp blocked: <errno>"` |
| `aioquic.quic.connection.QuicConnectionError` | `"quic: <reason_phrase>"` |
| `ssl.SSLError`, `aioquic.tls.AlertReceived` | `"tls: <reason>"` |
| Any other `Exception` | `"unexpected: <type>: <msg>"` |

Every exception in the client is caught; `scan_h3()` always returns an `H3ScanResult`, never raises.

### 3.2 `probe.py` — pure-logic helpers

```python
def derive_h3_target(
    h1_headers: Mapping[str, str],
    fallback_host: str,
) -> Optional[tuple[str, int]]:
    """Parse Alt-Svc, find first h3* entry, return (host, port).
    Returns None when no h3 advertisement present.
    Falls back to fallback_host when Alt-Svc entry omits the host.
    Reuses corsair.cache.altsvc.parse_alt_svc."""

def is_lsquic_fingerprint(
    h1_headers: Mapping[str, str],
    has_h3_advertisement: bool,
) -> bool:
    """Return True iff:
       - has_h3_advertisement is True, AND
       - Server header matches /\b(litespeed|openlitespeed)\b/i.
    Word-boundary regex prevents false positives on 'LiteSpeedAdapter' etc."""
```

No httpx, no aioquic, no network I/O. Trivially unit-testable.

### 3.3 `diff.py` — H1/H3 header diff

```python
SECURITY_HEADER_ALLOWLIST: frozenset[str] = frozenset({
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "cross-origin-opener-policy",
    "cross-origin-opener-policy-report-only",
    "cross-origin-embedder-policy",
    "cross-origin-embedder-policy-report-only",
    "cross-origin-resource-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "integrity-policy",
    "integrity-policy-report-only",
    "reporting-endpoints",
    "document-isolation-policy",
    "document-isolation-policy-report-only",
    "origin-agent-cluster",
})

@dataclass(frozen=True)
class HeaderDiffResult:
    missing_in_h3: list[str]    # present in H1, absent in H3
    missing_in_h1: list[str]    # present in H3, absent in H1
    value_drift: list[tuple[str, str, str]]  # (header, h1_value, h3_value)

def diff_security_headers(
    h1: Mapping[str, str],
    h3: Mapping[str, str],
) -> HeaderDiffResult: ...
```

All comparisons case-insensitive on header names. Values compared case-sensitive (HSTS `max-age=31536000` ≠ `MAX-AGE=31536000` is intentional — it's a real misconfiguration shape). Returned lists are sorted for deterministic finding output.

### 3.4 `findings.py` — template registry

Three core finding IDs, mirroring the registry pattern from `corsair/integrity_policy/findings.py` and `corsair/fetch_metadata/findings.py`:

| ID | Severity tiers | Score impact | Description |
|---|---|---|---|
| **H3-001** | HIGH / LOW / PASS / (no emit) | -15 / -3 / 0 / — | 0-RTT replay vulnerability (severity tier driven by capability × hint-honored matrix) |
| **H3-002** | MEDIUM / LOW / PASS | -10 / -3 / 0 | H1/H3 security header inconsistency (severity = max of active drift modes) |
| **H3-003** | CRITICAL | -20 | LSQUIC pre-handshake DoS fingerprint (CVE-2025-54939) |

Plus two auxiliary INFO emissions (no score impact):
- **H3-INFO-EXTRAS-MISSING** — `[h3]` extra not installed.
- **H3-INFO-INCONCLUSIVE** — probe failed; carries error class in `current_value`.

**Severity matrix for H3-001:**

| `early_data_capability > 0` | Response status == 425 | Tier | Severity |
|---|---|---|---|
| ✓ | ✗ | server vulnerable | HIGH (-15) |
| ✓ | ✓ | well-configured | PASS |
| ✗ | ✗ | header echoed but no vector | LOW (-3) |
| ✗ | ✓ | safe baseline | (no emit) |

**Severity for H3-002:**
- Severity = max of active drift modes (MEDIUM if either missing-in-h3 or value-drift present, else LOW if only missing-in-h1, else PASS).
- Single bundled finding regardless of drift count. Description enumerates each mode it found.
- Description shape:
  ```
  Security headers differ between HTTP/1.1 and HTTP/3:

  Missing on HTTP/3: Strict-Transport-Security, Content-Security-Policy
  Value drift: X-Frame-Options (H1=DENY, H3=SAMEORIGIN)

  All security headers should be applied at the HTTP layer, not tied to
  specific TCP/QUIC listener configuration.
  ```

**Severity for H3-003:**
- CRITICAL. No tiers — the fingerprint either matches or it doesn't.
- Note in description: "Upgrade to LSQUIC 4.3.1+ or disable HTTP/3 advertisement until patched. Active probing not required — fingerprint is passive."
- Fires *before* the QUIC probe (see §4 step 3) so it surfaces even when the probe times out.

**Compliance mappings (every finding):**

| Finding | OWASP | CWE | PCI-DSS 4.0 | NIST |
|---|---|---|---|---|
| H3-001 | A07:2021 | CWE-294 | 6.2.4 | SP 800-52r2 §3.6 |
| H3-002 | A05:2021 | CWE-693 | 6.4.3 | SC-23 |
| H3-003 | A06:2021 | CWE-400, CWE-770 | 6.2.4 | RA-5 |

**`HeaderCategory` enum addition:** `HeaderCategory.H3` (mirrors how `HeaderCategory.INTEGRITY` was added in v0.5.5). Cleaner reporting filter than reusing `NETWORK`.

### 3.5 `auditor.py` — H3Auditor orchestrator

```python
class H3Auditor:
    def __init__(
        self,
        timeout: int = 10,
        active: bool = True,
        user_agent: str = "Corsair/0.6.0 (HTTP Security Scanner)",
    ): ...

    def audit(self, url: str, h1_headers: Mapping[str, str]) -> list[Finding]:
        try:
            return self._audit_inner(url, h1_headers)
        except Exception as e:
            logger.exception("H3 audit unexpectedly failed")
            return [_build_inconclusive_finding(error=f"audit error: {e!r}")]
```

Top-level try/except mirrors `IntegrityPolicyAuditor.audit()` — the truly unexpected becomes a visible INFO finding instead of a silent scan crash.

**Critical implementation note:** `auditor.py` does `from .client import scan_h3`. Tests must patch `corsair.h3.auditor.scan_h3`, **not** `corsair.h3.client.scan_h3` — the former is the binding the auditor uses, the latter is the module-level function the auditor doesn't reference at call time. This footgun was discovered in v0.5.5 (integrity-policy `_fetch_body`) and is documented in the auditor's import block.

---

## 4. Data Flow

`H3Auditor.audit(url, h1_headers)` executes the following sequence:

```
1. Gate check
   - h3_available == False  → emit H3-INFO-EXTRAS-MISSING, return.
   - active == False         → return [] (silent skip).
   - url.scheme != "https"   → return [] (h3 only over QUIC+TLS).

2. Trigger derivation (probe.derive_h3_target)
   - Parse h1_headers["Alt-Svc"] via cache.altsvc.parse_alt_svc.
   - Filter for protocol_id starting with "h3".
   - No h3 entries → return [] (most sites; no signal).
   - Yes h3 entries → (host, port) extracted.

3. LSQUIC passive fingerprint (probe.is_lsquic_fingerprint)
   - h1_headers["Server"] matches /\b(litespeed|openlitespeed)\b/i AND
     has_h3_advertisement == True → emit H3-003 CRITICAL.
   - This finding fires regardless of probe outcome below.

4. H3 probe (client.scan_h3 — async, bridged via asyncio.run)
   - Single connection: handshake → session ticket → HEAD with Early-Data: 1.
   - Returns H3ScanResult with status, headers, early_data_capability, error.
   - Hard timeout from constructor (default 10s).

5. Result classification
   - result.error is not None → emit H3-INFO-INCONCLUSIVE with error class,
     return (LSQUIC finding from step 3 stays in the list if it fired).
   - else: continue to steps 6-7.

6. 0-RTT evaluation
   - capability = result.early_data_capability > 0
   - hint_rejected = (result.status == 425)
   - capability AND NOT hint_rejected → H3-001 HIGH.
   - capability AND     hint_rejected → H3-001 PASS.
   - NOT capability AND NOT hint_rejected → H3-001 LOW.
   - NOT capability AND     hint_rejected → no emit.

7. H1/H3 security-header diff (diff.diff_security_headers)
   - Compute HeaderDiffResult against SECURITY_HEADER_ALLOWLIST.
   - missing_in_h3 OR value_drift non-empty → H3-002 MEDIUM (bundled).
   - Only missing_in_h1 non-empty → H3-002 LOW.
   - All three empty → H3-002 PASS (positive signal).

8. Return list[Finding].
```

---

## 5. Error Handling and Edge Cases

| Condition | Behavior | Why |
|---|---|---|
| `[h3]` extras not installed | Single INFO finding `H3-INFO-EXTRAS-MISSING` | User should know the gap exists |
| `--no-h3-probe` (active=False) | Return `[]`, silent | User explicitly opted out |
| `http://` URL (not https) | Return `[]`, silent | H3 requires QUIC+TLS, not applicable |
| Alt-Svc absent or no h3 entries | Return `[]`, silent | Vast majority of sites; not a misconfig |
| QUIC probe times out | INFO finding `H3-INFO-INCONCLUSIVE` (error="timeout after 10s") | Could be firewall, could be real config gap — user must see it |
| UDP blocked (errno EHOSTUNREACH/ECONNREFUSED) | INFO finding `H3-INFO-INCONCLUSIVE` (error="udp blocked: <errno>") | Same |
| QUIC handshake fails (TLS, ALPN, version mismatch) | INFO finding `H3-INFO-INCONCLUSIVE` (error="tls: <reason>" or "quic: <reason>") | Same |
| Server returns garbage / kills connection mid-stream | INFO finding `H3-INFO-INCONCLUSIVE` | Top-level except in audit() catches |
| LSQUIC fingerprint matches BUT QUIC probe times out | H3-003 CRITICAL still fires (passive) + H3-INFO-INCONCLUSIVE for the failed probe | Fingerprint is passive evidence, doesn't depend on probe success |
| `aioquic` API drift in future minor versions | Top-level except → H3-INFO-INCONCLUSIVE with `"unexpected: <type>: <msg>"` | Visible failure, not silent |

**Probe budget:** one UDP connect + one QUIC handshake + one HEAD. No retries, no second connection. Hard timeout from constructor (default 10s, propagated from CLI `--timeout`).

---

## 6. CLI Surface

New flag in `corsair/cli.py`, added immediately after `--ip-probe`:

```python
@click.option(
    "--h3-probe/--no-h3-probe",
    default=True,
    help="Run HTTP/3 validation (requires `pip install corsair-scan[h3]`)",
)
```

Plumbed identically to v0.5.5's `--ip-probe` work:
- `scan()` function signature gains `h3_probe: bool` after `ip_probe`.
- `HeadScanner.__init__` gains `h3_probe: bool = True`, stored as `self.h3_probe`.
- `HeadScanner` instantiation in `scan()` passes `h3_probe=h3_probe`.

Help text (post-change excerpt):
```
--ip-probe / --no-ip-probe      Run Integrity-Policy validation
--h3-probe / --no-h3-probe      Run HTTP/3 validation (requires `pip install corsair-scan[h3]`)
```

---

## 7. Scanner Integration

New auditor block in `corsair/scanner.py:scan_target()`, added after the existing Integrity-Policy block:

```python
# HTTP/3 validation
try:
    from .h3 import H3Auditor
    h3_auditor = H3Auditor(
        timeout=self.timeout,
        active=self.h3_probe,
        user_agent=self.user_agent,
    )
    h3_findings = h3_auditor.audit(final_url, headers)
    findings.extend(h3_findings)
except Exception as e:
    logger.error(f"H3 audit failed: {e}")
```

Local import keeps `aioquic` loaded only when `scan_target` runs (matching the IP/FM auditor patterns). The outer try/except is the second line of defense behind the auditor's own internal exception handler.

**Pipeline placement rationale:** A new sibling auditor block, not a re-run of the existing pipeline. Re-running every analyzer on H3 headers would double-count findings (e.g., HSTS-missing emitted twice for sites that ship the same headers on both protocols), inflating score penalties without adding signal. The diff finding (H3-002) already captures the H3-specific dimension.

---

## 8. Dependency Packaging

`pyproject.toml` gains:

```toml
[project.optional-dependencies]
h3 = [
    "aioquic>=1.3.0,<2.0",   # H3 client; ARM64 wheels ship from 1.3.0
]
```

- `>=1.3.0` for the native ARM64/aarch64 wheel (research-confirmed).
- `<2.0` to insulate against API breaks in a future major.
- No other transitive deps added — `aioquic`'s `cryptography` and `pylsqpack` requirements overlap with the base `cryptography` already used for TLS auditing.

Install paths:
- Default: `pip install corsair-scan` → no aioquic; `--h3-probe` emits `H3-INFO-EXTRAS-MISSING`.
- H3-enabled: `pip install corsair-scan[h3]` → aioquic present; full probing.

---

## 9. Testing Strategy

### 9.1 Unit tests (~70 tests, ~2s wall time)

| File | Subject | Test count | Strategy |
|---|---|---|---|
| `tests/test_h3_probe.py` | `corsair.h3.probe` | ~18 | Pure-logic over plain dict inputs. Covers Alt-Svc → (host, port) derivation, all `h3-*` protocol-id variants, missing-host fallback, malformed Alt-Svc, LSQUIC fingerprint (case-insensitive, word-boundary, "OpenLiteSpeed" vs "Apache LiteSpeedAdapter"). |
| `tests/test_h3_diff.py` | `corsair.h3.diff` | ~22 | Pure-logic over plain dict inputs. Covers each diff direction (missing-in-h3, missing-in-h1, value-drift), case-insensitive header keys, multi-header drift, all-equal PASS path, severity-max calculation when multiple modes active. |
| `tests/test_h3_auditor.py` | `corsair.h3.auditor.H3Auditor` | ~30 | Mocks `corsair.h3.auditor.scan_h3` (patch at the auditor's bound name — v0.5.5 lesson). Covers gate skips, all four 0-RTT severity tiers, LSQUIC pass-before-probe, INCONCLUSIVE on every error class, finding metadata shape, top-level exception handler. |

### 9.2 Integration tests (~3 tests)

`tests/test_h3_integration.py` — exercises real `aioquic` against a local in-process H3 server. Skipped via `pytest.importorskip("aioquic")` when extras absent.

**Fixture (~120 LOC, in `tests/h3_server.py`):**
- `@pytest.fixture h3_server` — generates a self-signed cert, spins up an `aioquic` H3 server on a random UDP port, yields `(host, port, knob_dict)`. The knob dict controls per-test behavior (response status, max_early_data_size, response headers).

**The three tests:**
1. `test_h3_client_handshake_and_head_request` — sanity. Server returns 200. Asserts status, headers, no error, QUIC version captured.
2. `test_h3_client_captures_session_ticket` — server configured with `max_early_data_size=16384`. Asserts `H3ScanResult.early_data_capability == 16384`.
3. `test_h3_client_handles_425_too_early` — server returns 425 to any request with `Early-Data: 1`. Asserts `H3ScanResult.status == 425`.

**Intentionally NOT integration-tested:**
- Severity-tier matrix (covered exhaustively in unit tests against mocked `scan_h3`).
- Auditor orchestration (same).
- Failure-class taxonomy except happy path (kernel-level setup not desirable in CI).

### 9.3 Scanner-integration smoke (1 test)

`tests/test_h3_auditor.py::TestScannerIntegration::test_h3_finding_emitted_via_full_pipeline` — follows the v0.5.5 pattern. Patches `_fetch_headers`, `corsair.h3.auditor.scan_h3`, and stubs upstream auditors (CacheAuditor.audit, CORSAuditor.audit, FetchMetadataAuditor.audit, IntegrityPolicyAuditor.audit). Asserts a known H3 finding reaches `result.findings`.

### 9.4 Coverage summary

- **Total new tests:** ~73 (70 unit + 3 integration).
- **Target full-suite count:** ~615 passing (544 baseline + 73 H3, with TLS BadSSL exclusions still in place).
- **CI gating:** integration tests skipped automatically when `[h3]` extra absent, so CI without aioquic still passes.

---

## 10. Out of Scope (Explicitly Deferred)

Per the brainstorming Q1 decision (Tier A only for v0.6.0):

- **QPACK `SETTINGS_MAX_FIELD_SECTION_SIZE` advertisement check** (quic-go GHSA-g754-hx8w-x2g6) → v0.6.1.
- **`H3_ALTSVC_WITHOUT_HSTS`** → v0.6.1.
- **`H3_ALTSVC_LONG_MAX_AGE`** → v0.6.1.
- **`H3_NO_CID_ROTATION_SUPPORT`** (Connection-ID rotation privacy) → v0.6.1.
- **Full RFC 8470 two-connection 0-RTT replay** (active replay testing) → considered for `--h3-replay` opt-in flag in a future release, not v0.6.0.
- **H3-specific re-run of existing analyzers** (running CSP/HSTS/IP/CORS analyzers against H3 headers separately) → not planned; the diff finding captures H3-specific drift.
- **Forced H3 probing without Alt-Svc advertisement** (`--h3-force` override) → not in v0.6.0.

---

## 11. Open Questions / Known Limitations

1. **`asyncio.run()` re-entrancy.** If `scan_target` is ever called from inside an existing event loop (e.g., async caller), `asyncio.run()` raises. The `CacheAuditor` has the same constraint; H3 inherits the limitation. Mitigated by the auditor's top-level try/except → INCONCLUSIVE finding rather than scan crash.
2. **`aioquic` fingerprint exposure.** Our QUIC client identifies as aioquic to the target via TLS ClientHello extensions. Targets running QUIC-fingerprinting (rare) could detect Corsair scanning. Acceptable for v0.6.0; revisit if it becomes a CI-bypass concern.
3. **No IPv6-first probe.** v0.6.0 connects via aioquic's default address resolution, which is system-dependent. Targets that serve H3 only on IPv6 may probe-fail on IPv4-only hosts. INCONCLUSIVE finding makes this visible; explicit IPv6 ordering deferred.
4. **`h3-29` ALPN fallback.** A small population of older deployments still negotiates `h3-29` instead of `h3`. v0.6.0 advertises both ALPNs; if real-world data shows older drafts persisting, we'll narrow.

---

## 12. Cutting-edge Positioning Summary

At v0.6.0 release, Corsair becomes the **only public security scanner** with all three of:
1. A live HTTP/3 client (testssl.sh, sslyze, Mozilla Observatory all stop at TCP).
2. End-to-end 0-RTT replay vulnerability detection grounded in QUIC session-ticket evidence (no other public tool combines `max_early_data_size` capability with `Early-Data: 1` hint-honoring classification).
3. HTTP/1.1 vs HTTP/3 security-header drift analysis with value-level comparison (an entire class of misconfigurations no other tool surfaces — the "QUIC vhost was forked from an older config" bug pattern).

LSQUIC fingerprinting (CVE-2025-54939) is a free passive win on ~14% of all websites and ~34% of HTTP/3-enabled sites.

---

## 13. Acceptance Criteria

| # | Criterion | Verified by |
|---|---|---|
| 1 | `from corsair.h3 import H3Auditor` works without `aioquic` installed | Test with extras absent |
| 2 | `H3Auditor.audit(url, headers)` returns `list[Finding]` for every documented scenario | Unit tests `test_h3_auditor.py` |
| 3 | `corsair scan --help` shows `--h3-probe / --no-h3-probe` flag | Manual + smoke test |
| 4 | All ~70 unit tests pass (`pytest tests/test_h3_*.py`) | CI |
| 5 | Integration tests pass when `[h3]` extra installed; skip cleanly when absent | CI |
| 6 | Full suite minus TLS shows zero new failures vs v0.5.5 baseline (~615 total) | CI |
| 7 | `H3Auditor` wired into `HeadScanner.scan_target()` after IP block | Smoke test |
| 8 | v0.6.0 release artifacts updated (`__init__.py`, `pyproject.toml`, README) | Release task in plan |
| 9 | LSQUIC fingerprint fires passively even when QUIC probe times out | Unit test |
| 10 | All four cells of the H3-001 (capability × hint-honored) matrix produce the documented outcome — three emitted tiers (HIGH/LOW/PASS) plus the silent baseline | Parametrized unit tests |

---

## 14. References

- Research doc: `RESEARCH/Corsair HTTP3 Research - Claude.md` (Objectives 1, 2, 3, 6).
- Companion memory: `~/.claude/projects/-Users-fevra-Apps-HeadScan/memory/project_h3_v060_scope.md` (Tier B/C deferred work).
- Spec precedent: `docs/superpowers/specs/2026-05-04-integrity-policy-validation-design.md` (v0.5.5 — pattern this spec follows).
- RFC 9000 — QUIC v1 transport.
- RFC 9114 — HTTP/3.
- RFC 9369 — QUIC v2 (handshake compatibility).
- RFC 8470 — Using Early Data in HTTP (the `Early-Data` header and `425 Too Early`).
- CVE-2024-39321 — Traefik IP-allowlist bypass via 0-RTT.
- CVE-2025-54939 — LSQUIC pre-handshake DoS.
- GHSA-g754-hx8w-x2g6 — quic-go QPACK header expansion DoS (deferred to v0.6.1).
