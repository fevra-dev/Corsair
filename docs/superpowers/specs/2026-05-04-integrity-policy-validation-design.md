# Integrity-Policy Validation — Design Spec

**Version:** Corsair v0.5.5 (proposed)
**Status:** Approved design — pending implementation plan
**Date:** 2026-05-04
**Spec author:** Brainstorming session, this conversation
**Builds on:** v0.5.4 (Reporting-Endpoints Coherence Detection)

---

## 1. Goal

Add Integrity-Policy validation to Corsair: a header-and-body-aware audit of `Integrity-Policy` and `Integrity-Policy-Report-Only` (RFC 9651 Structured Fields, Subresource Integrity §3.8) that detects misconfiguration, omission, and the page-breaking enforcement scenario where cross-origin scripts lack `integrity` attributes.

Five findings ship in this release: **IP-001** (header absent, LOW), **IP-002** (Report-Only present, enforcing absent, INFO), **IP-003** (empty/unrecognized `blocked-destinations`, LOW), **IP-004** (`script` missing from `blocked-destinations`, LOW), and **IP-006** (enforcing IP + cross-origin `<script>` lacking `integrity`, HIGH). The IP-005 case (orphaned `endpoints` reference) is intentionally **not** added here — REPORT-004 (HIGH, Integrity-Policy Monitoring Failure) shipped in v0.5.4 already owns that misconfiguration in the cross-header reporting coherence subsystem.

Cutting-edge positioning: at the time of writing, no public scanner (humble, drHEADer, Mozilla Observatory, Snyk, etc.) implements the IP-006 body-aware check. The closest comparable check is `humble`'s recently-added IP presence detection (commit `8918c52`) — strictly weaker than IP-001 because it does not parse the header value or detect the page-breaking enforcement misconfiguration.

---

## 2. Architecture

### 2.1 Subsystem layout

A new top-level module `corsair/integrity_policy/` contains all IP-specific code, parallel to the existing `corsair/cache/`, `corsair/cors/`, and `corsair/fetch_metadata/` subsystems. The auditor pattern (rather than a `BaseAnalyzer` subclass) is required because IP-006 needs HTTP work and URL context that the static-analyzer contract does not provide.

```
corsair/
  integrity_policy/
    __init__.py            # exports IntegrityPolicyAuditor
    auditor.py             # orchestrator: dispatches static + body checks
    parser.py              # _parse_integrity_policy, _is_html_response
    body.py                # _fetch_body, _extract_cross_origin_scripts
    findings.py            # IP-001/002/003/004/006 templates + builders
tests/
  test_integrity_policy_parser.py   # ~25 tests
  test_integrity_policy_body.py     # ~20 tests
  test_integrity_policy_auditor.py  # ~25 tests + 1 regression
```

Five files keep each module under approximately 200 LOC and testable in isolation. Mirrors `corsair/fetch_metadata/`.

### 2.2 Pipeline integration

`corsair/scanner.py:HeadScanner.__init__` gains an `ip_probe: bool = True` parameter. `HeadScanner.scan_target()` instantiates `IntegrityPolicyAuditor(timeout, active=ip_probe, user_agent=user_agent)` after the existing `FetchMetadataAuditor` block:

```python
# Integrity-Policy validation
try:
    ip_auditor = IntegrityPolicyAuditor(
        timeout=self.timeout,
        active=self.ip_probe,
        user_agent=self.user_agent,
    )
    ip_findings = ip_auditor.audit(final_url, headers)
    findings.extend(ip_findings)
except Exception as e:
    logger.error(f"Integrity-Policy audit failed: {e}")
```

CLI: `corsair/cli.py` gains `--ip-probe / --no-ip-probe` (default ON) plumbed through `cli_main` to `HeadScanner.__init__`. Matches the existing `--cache-probe / --no-cache-probe`, `--cors-probe / --no-cors-probe`, `--fm-probe / --no-fm-probe` pattern.

### 2.3 Two-stage auditor flow

Inside `IntegrityPolicyAuditor.audit(url, headers)`:

**Stage 1 — Static path (always runs).** Parse `Integrity-Policy` and `Integrity-Policy-Report-Only`. Emit one of: IP-001 (both absent), IP-002 (RO only), IP-003 (parse error or no recognized destinations), IP-004 (`script` missing), or static PASS.

**Stage 2 — Active path (runs when `active=True` AND enforcing IP detected AND response is HTML-class).** GET the document body, extract cross-origin scripts lacking `integrity`. Emit IP-006 (HIGH), IP-006 PASS, or IP-006 INCONCLUSIVE (INFO) on body fetch failure.

The static path runs unconditionally so users always get the cheap header-shape findings, even with `--no-ip-probe`. Active path is opt-out.

---

## 3. Components

### 3.1 `parser.py`

```python
def _parse_integrity_policy(value: str) -> dict:
    """Parse an Integrity-Policy or IP-Report-Only header value.

    Returns: {
      'blocked_destinations': list[str],  # lowercased recognized + unknown tokens
      'sources': list[str],               # ['inline'] if absent (per spec default)
      'endpoints': list[str],             # lowercased tokens
      'parse_error': bool,                # True if no SF dict members found
    }
    """

def _is_html_response(headers: dict) -> bool:
    """Return True iff Content-Type is text/html, application/xhtml+xml,
    application/xml, or text/xml (charset/params stripped).

    Empty/missing Content-Type returns False (stricter than reporting.py
    because body fetching costs a round-trip; we only do it when the server
    explicitly advertises HTML)."""
```

**Regex for SF dictionary members:** `r'(?:^|,)\s*([\w][\w\-]*)\s*=\s*\(([^)]*)\)'` with `re.IGNORECASE`. Tokens within the inner list are split on whitespace. Unknown SF dict keys (anything other than `blocked-destinations`, `sources`, `endpoints`) are silently dropped per RFC 9651 forward-compatibility rules.

**Sources default:** Per the SRI §3.8 spec, omitting `sources` is equivalent to `sources=(inline)`. The parser populates this default explicitly so downstream code does not branch on key presence.

**Case normalization:** SF tokens are technically case-sensitive, but in practice all defined IP tokens are lowercase. Parser lowercases tokens to make comparison logic case-insensitive.

### 3.2 `body.py`

```python
def _fetch_body(url: str, timeout: int, user_agent: str) -> tuple[str, str | None]:
    """GET url with the supplied User-Agent. Return (body_text, error_or_None).

    Honors timeout. Caps body at 1 MB (truncates the rest). Treats non-2xx
    as a soft failure: returns ("", "HTTP <status>"). Network exceptions
    return ("", "<exception class>: <message>")."""

def _extract_cross_origin_scripts(body: str, document_url: str) -> list[str]:
    """Return list of cross-origin script src URLs that lack an integrity
    attribute in the same opening tag.

    Cross-origin = different scheme, host, or port from document_url
    (exact tuple match — not eTLD+1, not registrable domain). Protocol-relative
    `//host/x.js` is resolved against the document scheme. Pure relative URLs
    (`/x.js`, `x.js`) are same-origin and skipped.

    Match order in regex: `<script\b([^>]*?)>`, then within attrs scan for
    src and integrity using independent attribute regexes."""
```

**Body cap rationale:** 1 MB covers > 99% of HTML documents. Truncation happens before parsing; if truncation occurred, the IP-006 builder appends a one-line note ("Note: response body was truncated at 1 MB; some scripts may not have been examined.") to the finding's description.

**Cross-origin classification:** Use `urllib.parse.urlsplit` for both URLs. Compare `(scheme, hostname, port)` triples with explicit-default-port handling: `https://x.example/` and `https://x.example:443/` compare equal; `https://x.example:8443/` does not.

**False positives accepted:** HTML-comment-wrapped scripts and `<noscript>` subtree scripts will be matched by the regex. This is documented in the finding description with a "verify in browser" note. Adding a real HTML parser (e.g., `selectolax`, `lxml`) doubles the dependency footprint for a low-frequency edge case.

### 3.3 `findings.py`

Five Finding templates (`_IP_001_TEMPLATE` ... `_IP_006_TEMPLATE`) plus three PASS variants and one INCONCLUSIVE variant. Module structure mirrors `corsair/fetch_metadata/findings.py`:

- DRY constructors `_compliance(framework, req_id, req_name, status='FAIL') -> ComplianceMapping` and `_cwe(cwe_id, desc) -> CVECorrelation`.
- Module-level constants for each compliance/CWE entry: `_OWASP_A08`, `_CWE_353`, `_CWE_494`, `_CWE_829`, `_NIST_SI_7`, `_PCI_6_4_3`.
- Public API: `get_finding(finding_id) -> Finding | None` returns a `copy.deepcopy` of the template; builders (`build_ip_003_finding(parsed_value)`, `build_ip_006_finding(scripts, truncated, body_fetch_error=None)`) substitute runtime context.

**Severity assignments and score deductions** (per the research file's Severity Justification Addendum, locked in this spec):

| ID | Severity | Score deduction | Category |
|---|---|---|---|
| IP-001 | LOW | 3 | INTEGRITY |
| IP-002 | INFO | 0 | INTEGRITY |
| IP-003 | LOW | 2 | INTEGRITY |
| IP-004 | LOW | 3 | INTEGRITY |
| IP-006 | HIGH | 10 | INTEGRITY |
| IP-006 PASS | PASS | 0 | INTEGRITY |
| IP-006 INCONCLUSIVE | INFO | 0 | INTEGRITY |

`HeaderCategory.INTEGRITY` — already defined in `corsair/models.py` as confirmed in v0.5.4 development; no model change needed.

### 3.4 `auditor.py`

```python
class IntegrityPolicyAuditor:
    def __init__(
        self,
        timeout: int = 10,
        active: bool = True,
        user_agent: str = "HeadScan/1.0 (Security Header Analyzer)",
    ): ...

    def audit(self, url: str, headers: dict) -> list[Finding]:
        findings: list[Finding] = []

        # Stage 1: static path
        ip_value = self._get_header(headers, "integrity-policy")
        ip_ro_value = self._get_header(headers, "integrity-policy-report-only")
        static_findings, parsed = self._static_audit(ip_value, ip_ro_value)
        findings.extend(static_findings)

        # Stage 2: active path gate
        if not self.active:
            return findings
        if not parsed or parsed.get("parse_error"):
            return findings
        if "script" not in parsed["blocked_destinations"]:
            return findings  # IP-004 already emitted; body check would be noise
        if not _is_html_response(headers):
            return findings

        # Stage 3: body fetch + IP-006
        body, error = _fetch_body(url, self.timeout, self.user_agent)
        if error is not None:
            findings.append(build_ip_006_inconclusive_finding(error))
            return findings
        truncated = len(body) >= ONE_MEGABYTE
        scripts = _extract_cross_origin_scripts(body, url)
        if scripts:
            findings.append(build_ip_006_finding(scripts, truncated))
        else:
            findings.append(build_ip_006_pass_finding(truncated))

        return findings
```

`_static_audit(ip_value, ip_ro_value) -> tuple[list[Finding], dict | None]` returns `(findings, parsed_dict_or_None)`. The parsed dict is needed by Stage 2; returning it from Stage 1 avoids re-parsing.

### 3.5 `__init__.py`

```python
"""Integrity-Policy validation subsystem (v0.5.5)."""

from .auditor import IntegrityPolicyAuditor

__all__ = ["IntegrityPolicyAuditor"]
```

---

## 4. Data flow walkthroughs

Three concrete scenarios end-to-end.

### 4.1 Healthy site (full coverage, all scripts have integrity)

Request: `GET https://example.com/`. Response headers:
```
HTTP/1.1 200 OK
Content-Type: text/html
Reporting-Endpoints: sri="https://example.com/sri-reports"
Integrity-Policy: blocked-destinations=(script), endpoints=(sri)
```
Body contains: `<script src="https://cdn.example.net/lib.js" integrity="sha384-..." crossorigin="anonymous"></script>`.

1. `scanner._fetch_headers()` returns `(200, headers, "https://example.com/", None)`.
2. `IntegrityPolicyAuditor.audit("https://example.com/", headers)`:
   - Stage 1: `_parse_integrity_policy("blocked-destinations=(script), endpoints=(sri)")` → `{'blocked_destinations': ['script'], 'sources': ['inline'], 'endpoints': ['sri'], 'parse_error': False}`. No IP-001/002/003/004; emit static PASS.
   - Stage 2 gate: `active=True`; parsed.parse_error False; `'script'` in blocked_destinations; `_is_html_response(headers)` True. Proceed.
   - `_fetch_body("https://example.com/", 10, "...")` returns `(body_text, None)`.
   - `_extract_cross_origin_scripts(body_text, "https://example.com/")` returns `[]`.
   - Emit IP-006 PASS.
3. Findings appended: 2 PASS. Static PASS describes the healthy enforcement; IP-006 PASS describes verified script coverage.

In parallel, the existing `ReportingCoherenceAnalyzer` (v0.5.4) runs and observes `endpoints=(sri)` with `sri` defined in `Reporting-Endpoints`. No REPORT-004 emitted. Coherent.

### 4.2 Cross-origin script lacking integrity (IP-006 fires)

Response headers:
```
Content-Type: text/html
Integrity-Policy: blocked-destinations=(script)
```
Body contains: `<script src="https://cdn.analytics.example/tag.js"></script>` (no integrity attribute).

1. Stage 1: parse OK; `'script'` present; emit static PASS.
2. Stage 2 gate: passes (active, script present, HTML).
3. `_fetch_body` returns `(body_text, None)`.
4. `_extract_cross_origin_scripts` returns `["https://cdn.analytics.example/tag.js"]`.
5. Emit IP-006 with `current_value = "1 cross-origin script(s) lacking integrity:\n- https://cdn.analytics.example/tag.js"`. Description references the page-breaking risk and notes which browser versions enforce. Recommendation includes the `sha384-` hash command and a fallback "demote to Integrity-Policy-Report-Only".

### 4.3 Body fetch failure (INCONCLUSIVE)

Response: same as 4.2. The document GET times out (server slow, transient 5xx, etc.).

1. Stage 1: emit static PASS.
2. Stage 2 gate: passes.
3. `_fetch_body` returns `("", "Request timeout")`.
4. Emit IP-006 INCONCLUSIVE (INFO) with description: "Body fetch failed: Request timeout. The Integrity-Policy header is enforcing `script` blocking, but the document body could not be retrieved to verify whether scripts carry integrity attributes. Manual verification recommended."

The user knows the check was attempted and why it could not complete, distinguishing this from the silent-PASS case.

### 4.4 Static-path decision tree (always runs)

```
parse(IP value)
├── IP and IP-RO both absent ─────────────── IP-001 (LOW)
├── IP absent, IP-RO present ─────────────── IP-002 (INFO)
├── IP present, parse_error or no destinations ── IP-003 (LOW)
├── IP present, destinations recognized but 'script' missing ── IP-004 (LOW)
└── IP present, 'script' in destinations ─── static PASS
                                              (Stage 2 may run)
```

`Integrity-Policy-Report-Only`'s value content is parsed only for IP-002 detection (presence). Its destinations and endpoints are not separately validated; checking IP-RO endpoints for orphans would duplicate REPORT-004 (which already covers both enforcing and Report-Only IP variants in v0.5.4).

---

## 5. Error handling and edge cases

### 5.1 Header parsing edge cases

| Input | Static path |
|---|---|
| Both headers absent | IP-001 |
| `Integrity-Policy` absent, `Integrity-Policy-Report-Only` present | IP-002 |
| Empty value `""` or whitespace `"   "` | Treated as absent → IP-001 |
| `parse_error: True` (regex matched no SF dict members) | IP-003; description includes raw value verbatim |
| Empty inner list `blocked-destinations=()` | IP-003 |
| Missing `blocked-destinations` key, other keys present | IP-003 (treated equivalently to empty) |
| Unknown destinations only (`blocked-destinations=(scripts foo)`) | IP-003 (no recognized tokens) |
| `script` recognized + unknown tokens (`blocked-destinations=(script futureKind)`) | Static PASS; unknown tokens silently ignored |
| `blocked-destinations=(style)` only | IP-004 |
| `blocked-destinations=(script style)` | Static PASS |
| Both `Integrity-Policy` and `Integrity-Policy-Report-Only` present | Static path uses `Integrity-Policy` only; IP-RO presence yields no separate finding |

The auditor never raises. Any unexpected exception in the static path is caught at the `audit()` boundary, logged via `corsair.utils.get_logger`, and a single INFO finding "Integrity-Policy analysis failed: <exception>" is emitted so the gap is visible.

### 5.2 Body fetch edge cases

| Condition | Stage 2 behavior |
|---|---|
| `active=False` (CLI `--no-ip-probe`) | Skip Stage 2 entirely. No INCONCLUSIVE. |
| Static path emitted IP-001/002/003/004 (parse_error or 'script' missing) | Skip Stage 2. Body check would be noise. |
| `_is_html_response(headers)` False | Skip Stage 2. Body check semantically n/a. No INCONCLUSIVE. |
| Connection error / DNS failure | IP-006 INCONCLUSIVE with the underlying error string |
| Request timeout | IP-006 INCONCLUSIVE with "Request timeout" |
| HTTP 4xx | IP-006 INCONCLUSIVE with "HTTP {status}" |
| HTTP 5xx | IP-006 INCONCLUSIVE with "HTTP {status}" |
| HTTP 2xx, body > 1 MB | Truncate to 1 MB; parse prefix; emit finding with truncation note |
| HTTP 2xx, empty body | `_extract_cross_origin_scripts` returns `[]` → IP-006 PASS |
| Final URL (after redirects) differs from initial URL | Use final URL as `document_url` for cross-origin classification |
| TLS handshake failure | IP-006 INCONCLUSIVE with the SSL exception class name |

### 5.3 Cross-origin classification (worked examples)

Document URL: `https://www.example.com/`.

| Script `src` | Classification | Flagged? |
|---|---|---|
| `https://www.example.com/x.js` | exact origin match | no (same-origin) |
| `https://cdn.example.com/x.js` | different host | yes |
| `https://www.example.com:8080/x.js` | different port | yes |
| `http://www.example.com/x.js` | different scheme | yes |
| `//cdn.example.com/x.js` | resolved to `https://cdn.example.com/x.js` | yes |
| `/js/app.js` | relative → same-origin | no |
| `js/app.js` | relative → same-origin | no |
| `data:text/javascript,...` | data URL | no (no fetch happens) |
| `javascript:void(0)` | not a fetch | no |
| `blob:https://www.example.com/abc` | blob URL | no (browser-internal, no integrity applies) |

### 5.4 Script tag parsing edge cases

| Body fragment | Behavior |
|---|---|
| `<script src="..." async></script>` | matched (regex order-agnostic) |
| `<SCRIPT SRC="..."></SCRIPT>` | matched (case-insensitive) |
| Multi-line opening tag (`<script\n  src="..."\n  integrity="..."\n>`) | matched (`re.DOTALL`) |
| `<script src="...">` followed later by `integrity="..."` text outside the tag | flagged as missing integrity (correct — the attribute must be in the same opening tag) |
| HTML comment `<!-- <script src="x"></script> -->` | matched as a positive (documented false positive) |
| Inline `<script>code</script>` with no `src` | not matched (no src) |
| `<noscript><script src="..."></script></noscript>` | matched as positive (documented edge case) |
| Self-closing `<script src="..."/>` (XHTML) | matched |
| Empty `<script src="">` | not matched (URL parsing fails) |

False positives in HTML comments / `<noscript>` are accepted as a known limitation; the IP-006 finding's description includes a "verify in browser console" note to give users a path to confirm.

---

## 6. Testing strategy

Three test files under `tests/` mirror the source files. Targeted total: ~70 tests for the new subsystem, plus 1 regression test.

### 6.1 `tests/test_integrity_policy_parser.py` (~25 tests)

Pure-function tests. No HTTP. One input string per test, one expected dict comparison.

- **Valid grammars (8 tests):** `(script)`, `(script style)`, `(script), endpoints=(sri)`, `sources=(inline)`, all three keys present, multiple endpoints `(ep1 ep2 ep3)`, comma-separated dict members, trailing comma
- **Whitespace variations (3 tests):** `( script )`, `blocked-destinations =(script)`, leading/trailing whitespace on the whole value
- **Empty / missing (4 tests):** empty inner list `()`, missing key entirely (only `sources=(inline)`), empty value `""`, whitespace-only `"   "`
- **Unknown tokens (2 tests):** all-unknown `(scripts foo)` (parse OK but no recognized destinations), mixed `(script futureKind)` (parse OK, `script` retained)
- **Malformed (2 tests):** `not_valid_sf!!!` (parse_error True), unmatched paren `(script` (parse_error True)
- **Case normalization (2 tests):** `BLOCKED-DESTINATIONS=(SCRIPT)` → tokens lowercased, mixed-case keys
- **Sources default (2 tests):** absence of `sources` key returns `['inline']`, explicit `sources=(inline)` returns same
- **`_is_html_response` (4 tests):** each navigation type, with charset param `text/html; charset=utf-8`, missing CT, non-HTML CT (`application/json`), empty CT

### 6.2 `tests/test_integrity_policy_body.py` (~20 tests)

`_extract_cross_origin_scripts` is pure — tests pass HTML strings directly. `_fetch_body` tests use `pytest-httpx` (already a test dependency in v0.5.4).

- **Cross-origin extraction (5 tests):** different host, different port, different scheme, mixed-case host, IPv4-vs-hostname
- **Same-origin skip (4 tests):** exact-match URL, root-relative `/x.js`, pure-relative `x.js`, fragment-only `#anchor`
- **Protocol-relative (2 tests):** `//cdn.com/x.js` resolves to https → flagged; on http document resolves to http → flagged
- **Integrity present (3 tests):** integrity in any attribute position, integrity with whitespace `integrity = "..."`, integrity inside multi-line tag
- **Multiple scripts (2 tests):** mixed cover/uncovered scripts in same body, all-covered yields empty list
- **Edge cases (2 tests):** data URL skipped, `javascript:` URL skipped
- **Empty / no-script (1 test):** body with no `<script>` tags → empty list
- **Comment / noscript false positives (1 test):** asserts the regex DOES match these cases, so the documented behavior is locked into the test suite
- **`_fetch_body` (mocked HTTP, ~5 tests):** 200 OK with body, 404 → soft fail, 500 → soft fail, timeout via `pytest-httpx`, 1.5 MB body truncated to 1 MB

### 6.3 `tests/test_integrity_policy_auditor.py` (~25 tests + 1 regression)

End-to-end auditor tests covering all decision branches.

- **One per finding type (7 tests):** IP-001, IP-002, IP-003 (3 sub-cases: empty list, missing key, all-unknown tokens), IP-004, IP-006 cross-origin script
- **Static PASS path (2 tests):** clean enforcing IP without body, clean enforcing IP with `--no-ip-probe`
- **IP-006 PASS path (1 test):** enforcing IP + all scripts have integrity
- **IP-006 INCONCLUSIVE (3 tests):** timeout, 5xx, connection error
- **Stage 2 gate skips (5 tests):** `active=False`, parse_error, `script` missing, non-HTML Content-Type, missing Content-Type
- **Combined cases (3 tests):** IP-Report-Only present and enforcing IP both present (no IP-002), IP-003 + body fetch INCONCLUSIVE (parser error AND body fail), IP-004 + body skipped (no IP-006 since `script` missing)
- **Compliance/CWE assertions (3 tests):** assert each finding template has correct severity, category, compliance_mappings include expected framework IDs, reference_url present and HTTPS
- **Smoke test for scanner integration (1 test):** mock `_fetch_headers` to return enforcing IP + HTML CT, mock the body-fetch httpx call, run `HeadScanner.scan_target()`, assert IP-006 emitted as part of the full pipeline

**Regression test for v0.5.4 coexistence (1 test):** Apply `IntegrityPolicyAuditor` and `ReportingCoherenceAnalyzer` to the same fixture (HTML response with `Integrity-Policy: blocked-destinations=(script), endpoints=(missing-endpoint)` and no `Reporting-Endpoints` defining `missing-endpoint`). Assert REPORT-004 (HIGH) still fires from reporting.py AND IP-006 fires (or doesn't, depending on body) from the new auditor — the two subsystems address different misconfigurations and must not collide.

### 6.4 Discipline

- **No live network tests.** All HTTP via `pytest-httpx` mocks. Deterministic, CI-safe, fast (< 5 sec for the full IP suite).
- **Bias toward many small unit tests over few integration tests.** Localizes regressions.
- **Each finding template tested at least once for severity + category + compliance mapping correctness.** Lock the metadata into the test suite.
- **Pre-existing TLS BadSSL test failures (3 in `tests/test_tls_auditor.py::TestBadSSLIntegration`) remain pre-existing.** Unrelated to this feature.

---

## 7. Out of scope

- **IP-005 (orphaned `endpoints` reference)** — REPORT-004 in `corsair/analyzers/reporting.py` (v0.5.4) already detects this misconfiguration at HIGH severity.
- **HTTP/2 server push** — `Integrity-Policy` on a pushed response applies to that resource's document context. Corsair's single-request architecture does not reach pushed resources. Documented as out-of-scope in the IP-006 description.
- **Importmap integrity satisfaction** — whether an importmap's `integrity` field for a module specifier satisfies `sources=(inline)` is unresolved at the spec level. Not assumed either way.
- **Service Worker context enforcement** — Chromium currently treats IP as a no-op in Service Worker contexts. Out of scope.
- **Trusted Types / DOM XSS hardening** — separate roadmap item, separate brainstorming session.
- **Live-fetched module dependency analysis** — fetching the cross-origin script and checking what it loads next is out of scope. The check stops at the document.
- **eTLD+1 same-origin matching** — exact (scheme, host, port) tuple comparison only. Subdomains are cross-origin, by design (matches the browser's same-origin policy).
- **`http-sf` adoption / parser unification** — flagged for the next subsystem that needs SF parsing. When a third SF-parsing analyzer is added, that's the trigger to migrate `reporting.py` and `integrity_policy/parser.py` together to `http-sf` in one focused refactor.

---

## 8. Open questions / known limitations

1. **Firefox 145 Reporting API gap** — Firefox does not yet support the `endpoints` key in `Integrity-Policy` (target: early 2026). This affects REPORT-004's accuracy on Firefox-only stacks but is unrelated to this design's IP-001 through IP-004/006.
2. **HTML comment / `<noscript>` false positives in IP-006** — accepted limitation. Description includes "verify in browser" guidance.
3. **`<script>` injection via JavaScript** — scripts added to the DOM after page load are invisible to a static body scan. IP-006 only catches scripts present in the initial server response. Documented in the finding description.
4. **Compressed bodies** — `httpx` decodes gzip/deflate/br by default. Brotli/zstd-only servers without `httpx` having the codec installed will fail to decode; treated as soft failure → INCONCLUSIVE.
5. **Login-walled documents** — many real targets serve a login redirect at `/`, where the response body has no script tags. IP-006 PASS will fire vacuously. Documented in the description: "PASS does not guarantee coverage of authenticated routes."

---

## 9. Cutting-edge positioning summary

At publication time:

| Tool | IP-001 (presence) | IP-002 | IP-003 (parse) | IP-004 (`script`) | IP-005 (orphan) | IP-006 (page-breaking) |
|---|---|---|---|---|---|---|
| humble (rfc-st) | ✅ (basic) | ❌ | ❌ | ❌ | ❌ | ❌ |
| drHEADer | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Mozilla Observatory | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Snyk / WhatHeader.app | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Corsair v0.5.5 (this spec)** | ✅ | ✅ | ✅ | ✅ | ✅ (REPORT-004, v0.5.4) | ✅ (HIGH, body-aware) |

IP-006 is the discriminating capability. No other public scanner detects the page-breaking enforcement scenario. This spec ships it as a default-on check with single-request body fetch only when IP enforcement is detected — no extra cost on the > 99% of sites that don't deploy IP yet.

---

## 10. Acceptance criteria

The implementation is complete when:

1. `python3 -c "from corsair.integrity_policy import IntegrityPolicyAuditor; print('OK')"` imports without error.
2. `IntegrityPolicyAuditor(timeout=10, active=True).audit(url, headers)` returns a `list[Finding]` for the eleven test scenarios in §6.3.
3. `corsair --help` shows `--ip-probe / --no-ip-probe` (default ON).
4. `python3 -m pytest tests/test_integrity_policy_*.py -v` passes (target: ~70 tests).
5. `python3 -m pytest --ignore=tests/test_tls_auditor.py` shows zero new failures vs v0.5.4 baseline.
6. The `IntegrityPolicyAuditor` is wired into `HeadScanner.scan_target()` after the `FetchMetadataAuditor` block, with try/except logging matching the established pattern.
7. v0.5.5 release artifacts updated: `corsair/__init__.py`, `pyproject.toml`, README changelog block.
8. REPORT-004 still fires correctly on the regression fixture (§6.3) — the new auditor does not interfere with v0.5.4's reporting coherence subsystem.

---

## 11. References

- W3C Editor's Draft: Subresource Integrity §3.8 — https://w3c.github.io/webappsec-subresource-integrity/#integrity-policy-section
- W3C Working Draft (April 2025) — https://www.w3.org/TR/2025/WD-sri-2-20250422/
- RFC 9651 (Structured Field Values for HTTP) — https://www.rfc-editor.org/rfc/rfc9651
- Chrome 138 release notes — https://developer.chrome.com/release-notes/138
- Firefox 145 release notes — https://developer.mozilla.org/en-US/docs/Mozilla/Firefox/Releases/145
- WebKit features in Safari 26.0 — https://webkit.org/blog/17333/webkit-features-in-safari-26-0/
- MDN Integrity-Policy — https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Integrity-Policy
- MDN Integrity-Policy-Report-Only — https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Integrity-Policy-Report-Only
- OWASP Top 10 2021 A08 — https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
- CWE-353 (Missing Support for Integrity Check) — https://cwe.mitre.org/data/definitions/353.html
- CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) — https://cwe.mitre.org/data/definitions/829.html
- NIST SP 800-53 SI-7 — https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/controls?version=5.1&family=SI
- PCI-DSS 4.0 Req 6.4.3 — https://www.pcisecuritystandards.org/document_library/

**Internal references**
- Research file: `RESEARCH/integrity policy/integrity_policy_reference.md` (Apr 2026)
- Predecessor design: `docs/superpowers/specs/2026-05-03-reporting-endpoints-coherence-design.md` (v0.5.4)
- Predecessor plan: `docs/superpowers/plans/2026-05-03-reporting-endpoints-coherence-plan.md`
