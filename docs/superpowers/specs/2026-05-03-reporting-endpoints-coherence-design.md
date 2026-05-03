# Reporting-Endpoints Coherence Detection — Design Spec

**Status:** Approved (design phase complete)
**Date:** 2026-05-03
**Target version:** Corsair v0.5.4
**Author:** brainstorming session, 2026-05-03

## 1. Goal

Add static-analysis detection of orphaned reporting endpoint references across all
HTTP security headers that reference reporting endpoints by name. An orphan exists
when a policy header references a name (e.g., `Content-Security-Policy: ...; report-to my-endpoint`)
but that name is not defined in either the modern `Reporting-Endpoints` header
(RFC 8941 dictionary) or the legacy `Report-To` header (JSON array). Browsers
silently discard reports for unresolved names — the result is a complete loss of
security violation visibility with no surface signal.

The check is **pure static analysis** over headers Corsair has already fetched.
No new HTTP requests, no async, no new dependencies.

## 2. Scope

### In scope (v1)

- Parse `Reporting-Endpoints` (modern V1 dictionary) and `Report-To` (legacy V0 JSON)
  to build the set of defined endpoint names.
- Extract endpoint-name references from ten policy headers and classify each
  unresolved reference into one of three findings.
- Apply a Content-Type discriminator to suppress false positives on non-navigation
  responses (the SPA sub-resource case).
- Append a CDN caveat to findings when a CDN is fingerprinted on the response.
- Deduplicate findings: one finding per orphan name, listing every affected header.
- Optional severity downgrade for known placeholder names referenced exclusively
  from `*-Report-Only` headers.

### Out of scope (deferred to future versions)

- Active probing of the endpoint URLs (e.g., reachability, TLS validation, response code).
- Sub-finding for non-HTTPS endpoint URLs (`Reporting-Endpoints: x="http://..."`)
  which browsers also silently discard.
- Detection of `ReportingObserver` JavaScript usage (would require DOM analysis).
- CLI opt-out flag — static analyzers do not have per-analyzer kill switches in
  this codebase, and adding one for this analyzer alone would be inconsistent.

## 3. Headers covered

### Definition headers (parsed for endpoint names)

| Header | Format | Notes |
|---|---|---|
| `Reporting-Endpoints` | RFC 8941 Structured Fields Dictionary | Modern V1; keys are lowercase tokens. |
| `Report-To` | JSON array of objects | Legacy V0; group names from `group` field, default `"default"`. |

### Reference headers (parsed for endpoint references)

| Header | Reference syntax | Extraction style |
|---|---|---|
| `Content-Security-Policy` | `report-to <token>` directive | regex |
| `Content-Security-Policy-Report-Only` | same | regex |
| `Cross-Origin-Opener-Policy` | `report-to="<name>"` parameter | semicolon-split |
| `Cross-Origin-Opener-Policy-Report-Only` | same | semicolon-split |
| `Cross-Origin-Embedder-Policy` | same | semicolon-split |
| `Cross-Origin-Embedder-Policy-Report-Only` | same | semicolon-split |
| `Document-Isolation-Policy` | same | semicolon-split |
| `Network-Error-Logging` | `report_to` JSON field | JSON parse |
| `Integrity-Policy` | `endpoints=(name1 name2)` RFC 8941 inner list | regex |
| `Integrity-Policy-Report-Only` | same | regex |

Total: 10 reference headers + 2 definition headers.

## 4. Architecture

### Module placement

Single file: `corsair/analyzers/reporting.py`

Registered in `corsair/analyzers/__init__.py` `ALL_ANALYZERS`. No changes to
`corsair/scanner.py` — the analyzer runs in the existing
`HeadScanner._analyze_headers()` phase via the standard
`analyzer = analyzer_class(headers, url); analyzer.analyze()` invocation.

### Class

```python
class ReportingCoherenceAnalyzer(BaseAnalyzer):
    HEADER_NAME = "Reporting-Endpoints"
    CATEGORY = HeaderCategory.REPORTING

    def analyze(self) -> List[Finding]:
        ...
```

Inputs: `self.headers` (case-normalized lowercase dict) and `self.url`.
Outputs: `List[Finding]` carrying `category=HeaderCategory.REPORTING`.

### File structure (estimated 350-450 lines)

```
corsair/analyzers/reporting.py
├── module docstring
├── imports
├── module constants
│   ├── DEFINITION_HEADERS, REFERENCE_HEADERS_*  (header tuples)
│   ├── NAVIGATION_CONTENT_TYPES
│   └── PLACEHOLDER_NAMES
├── parser helpers (module-level functions)
│   ├── _parse_reporting_endpoints(value) -> set[str]
│   ├── _parse_report_to(value) -> set[str]
│   ├── _extract_csp_report_to(value) -> Optional[str]
│   ├── _extract_param_report_to(value) -> Optional[str]
│   ├── _extract_nel_report_to(value) -> Optional[str]
│   ├── _extract_integrity_endpoints(value) -> set[str]
│   └── _is_navigation_response(headers) -> bool
├── finding templates (module-level Finding constants)
│   ├── _REPORT_001_TEMPLATE
│   ├── _REPORT_002_TEMPLATE
│   └── _REPORT_004_TEMPLATE
├── _build_finding(template, orphan_name, affected_headers, cdn_detected) -> Finding
└── class ReportingCoherenceAnalyzer(BaseAnalyzer)
    ├── analyze() -> List[Finding]    # 5-stage orchestration only
    ├── _collect_orphans(modern_defs, legacy_defs) -> tuple[dict, dict, dict]
    ├── _detect_cdn() -> bool
    └── _build_findings(orphan_map, migration_map, ip_orphan_map, cdn_detected) -> List[Finding]
```

## 5. Severity model

Three findings, severity per the research file's REPORT-00X classification:

### REPORT-001 — LOW: Incomplete Migration to Modern Reporting API

Triggers when a referenced endpoint name **is defined in `Report-To`** but
**absent from `Reporting-Endpoints`**. Chromium browsers will fall back to the
V0 cache for most policies; reporting still functions on legacy browsers but
modern policies (Integrity-Policy) won't work. Recommended action: mirror the
definition in `Reporting-Endpoints`.

### REPORT-002 — MEDIUM: Orphaned Security Reporting Endpoint

Triggers when a referenced endpoint name is undefined in **both** `Reporting-Endpoints`
and `Report-To`. Browser silently discards every report. Affects CSP, CSP-RO,
COOP, COOP-RO, COEP, COEP-RO, DIP, NEL.

### REPORT-004 — HIGH: Integrity-Policy Monitoring Failure

Triggers when an `Integrity-Policy` or `Integrity-Policy-Report-Only` `endpoints`
list contains a name undefined in `Reporting-Endpoints`. Special-cased because
Integrity-Policy does **not** fall back to V0 `Report-To` — the orphan is a
guaranteed total failure of SRI monitoring.

### Classification precedence

1. If a name is referenced from any IP/IP-RO header AND undefined → REPORT-004
   (HIGH). The IP-special-case overrides everything else: even if the same name
   appears in a CSP elsewhere on the same response, the finding is emitted as
   REPORT-004 with **all** affected headers (IP and non-IP) listed.
2. Else if a name is in `legacy_defs` only → REPORT-001 (LOW).
3. Else (not defined anywhere) → REPORT-002 (MEDIUM).

### Placeholder downgrade

If an orphan name is in `PLACEHOLDER_NAMES` (`{none, todo, dummy, test, placeholder}`)
**and** every header referencing it is a `*-Report-Only` variant, severity
downgrades to INFO. Applies only to REPORT-002. REPORT-001 stays LOW (already
the floor). REPORT-004 stays HIGH (IP failure is too consequential to soften).

### CDN caveat

If `corsair.cache.oracle.fingerprint_cdn(headers)` returns truthy, append the
following sentence to every emitted finding's description:

> "If reporting endpoints are injected by a CDN/edge gateway, this finding may
> be a false positive on a direct-origin scan."

The caveat is informational only — severity is not modified.

## 6. Data flow

Five sequential stages inside `analyze()`:

### Stage 1 — Discriminator gate

`_is_navigation_response(self.headers)` strips parameters from `Content-Type`,
lowercases, and checks against `NAVIGATION_CONTENT_TYPES`:

```
text/html, application/xhtml+xml, application/xml, text/xml
```

Missing or empty `Content-Type` → returns `True` (analyze the response). Any
other Content-Type → returns `False` and `analyze()` returns `[]` immediately.

### Stage 2 — Definition pass

```python
modern_defs = _parse_reporting_endpoints(self.headers.get("reporting-endpoints", ""))
legacy_defs = _parse_report_to(self.headers.get("report-to", ""))
```

All extracted names are lowercased on extraction so reference matching is
case-insensitive.

### Stage 3 — Reference pass

Walk each of the 10 reference headers, extract the name(s) it references, and
classify each unresolved reference into one of three buckets:

- `orphan_map: dict[name, list[header]]` — undefined in both → REPORT-002 candidates
- `migration_map: dict[name, list[header]]` — defined in legacy only → REPORT-001 candidates
- `ip_orphan_map: dict[name, list[header]]` — IP/IP-RO orphan → REPORT-004 candidates

Names are tracked per orphan so the same name appearing in multiple headers
collapses to a single finding.

### Stage 4 — CDN detection

One call to `fingerprint_cdn(headers)`. Wrapped in try/except; on failure,
`cdn_detected = False`.

### Stage 5 — Finding emission

For each name in `ip_orphan_map`: emit REPORT-004 with all affected headers
listed (including any non-IP headers that also reference the same orphan).
Remove that name from `orphan_map` and `migration_map` to avoid double-emission.

For each name remaining in `migration_map`: emit REPORT-001.

For each name remaining in `orphan_map`: emit REPORT-002 (apply placeholder
downgrade if applicable).

Each finding is built via `_build_finding(template, orphan_name, affected_headers, cdn_detected)`,
which deepcopies the template, injects the orphan name into the title and
description (e.g., `"Orphaned endpoint name 'ghost-endpoint'..."`), sets
`current_value` to `f"Reference: {orphan_name} (in: {', '.join(affected_headers)})"`,
and appends the CDN caveat if applicable.

The `header` field of the emitted Finding is set to the comma-joined list of
affected reference headers (e.g., `"Content-Security-Policy-Report-Only, Cross-Origin-Embedder-Policy"`).

## 7. Worked example

**Input headers:**

```
Content-Type: text/html; charset=utf-8
Reporting-Endpoints: csp-endpoint="https://reports.example.com/csp"
Report-To: {"group":"legacy-group","max_age":10886400,"endpoints":[{"url":"https://r.example.com"}]}
Content-Security-Policy: default-src 'self'; report-to csp-endpoint
Content-Security-Policy-Report-Only: default-src 'self'; report-to ghost-endpoint
Cross-Origin-Opener-Policy: same-origin; report-to="legacy-group"
Cross-Origin-Embedder-Policy: require-corp; report-to="ghost-endpoint"
Integrity-Policy: blocked-destinations=(script), endpoints=(missing-ip-endpoint)
```

**Output (3 findings):**

| Finding ID | Severity | Affected headers | Orphan name |
|---|---|---|---|
| REPORT-004 | HIGH | `Integrity-Policy` | `missing-ip-endpoint` |
| REPORT-002 | MEDIUM | `Content-Security-Policy-Report-Only, Cross-Origin-Embedder-Policy` | `ghost-endpoint` |
| REPORT-001 | LOW | `Cross-Origin-Opener-Policy` | `legacy-group` |

Score impact (default scoring weights): `15 + 10 + 5 = 30` deductions max.
Deduplication ensures `ghost-endpoint` counts once even though it appears in
two reference headers.

## 8. Error handling

The analyzer's `analyze()` must never raise. The scanner already wraps each
analyzer in try/except, but defense-in-depth is warranted because each parser
helper can encounter malformed input.

| Helper | Bad input | Behavior |
|---|---|---|
| `_parse_reporting_endpoints` | malformed dict, junk string | try/except, return `set()` |
| `_parse_report_to` | malformed JSON, truncated, comma-concatenated | wrap with `[...]` if not bare array, json.loads in try/except, return `set()` |
| `_extract_csp_report_to` | no directive, garbage | regex returns no match → `None` |
| `_extract_param_report_to` | missing `report-to=`, malformed quotes | scan parts, return `None` |
| `_extract_nel_report_to` | malformed JSON | try/except, return `None` |
| `_extract_integrity_endpoints` | missing `endpoints=(...)`, unclosed list | regex returns no match → `set()` |
| `_is_navigation_response` | missing Content-Type | treat as in-scope (return True) |
| `fingerprint_cdn` raises | — | try/except, set `cdn_detected = False`, log debug |

### Case normalization

All extracted names are lowercased at parse time (both definitions and
references). RFC 8941 keys are nominally lowercase; `Report-To` group names
may be any case but are normalized on extraction.

### Multi-value header concatenation

httpx may concatenate repeated `Reporting-Endpoints` headers with `,`. RFC 8941
dictionaries are themselves comma-separated, so the concatenated form parses
correctly. For `Report-To`, the parser detects whether the value starts with
`[` and wraps in `[...]` if it doesn't, handling both `{...},{...}` and
`[{...},{...}]` forms.

### Logging

Use `corsair.utils.logger.get_logger(__name__)` for `debug` traces only. No
`error`-level inside the analyzer; the registry logs analyzer-level failures.

## 9. Compliance mappings

Per the research file's compliance section, all REPORT-00X findings carry:

- **OWASP Top 10 2025 → A05** (Security Misconfiguration) — primary mapping;
  the root cause is a header configuration error.
- **OWASP Top 10 2025 → A09** (Security Logging and Monitoring Failures) —
  secondary; the broken pipeline prevents actionable log generation.
- **CWE-778** (Insufficient Logging) — primary CWE.
- **CWE-693** (Protection Mechanism Failure) — secondary, applies to REPORT-004
  specifically (the protection is the SRI monitoring loop).

REPORT-004 additionally carries:

- **PCI-DSS 4.0 Req 11.6.1** (Detect unauthorized changes to HTTP headers and
  payment-page content) — the Integrity-Policy reporting failure means SRI
  violations would not be reported, potentially failing this requirement on
  payment-handling sites.

## 10. Testing plan

Test file: `tests/test_reporting_coherence.py`. TDD: write tests first.

### Layer 1 — Parser unit tests (~20 tests)

Each helper tested in isolation with no analyzer:

- `_parse_reporting_endpoints`: empty string; single endpoint; multiple
  endpoints; quoted URL containing commas; trailing whitespace; case-mixed
  keys (verify lowercased); malformed dict.
- `_parse_report_to`: empty; bare object (auto-wrap); array of objects; missing
  `group` field (defaults to `"default"`); malformed JSON; mixed-case names.
- `_extract_csp_report_to`: directive present; absent; multiple directives
  (only `report-to` extracted); whitespace variants.
- `_extract_param_report_to`: quoted name; unquoted name; missing parameter;
  multiple parameters with `report-to=` not first.
- `_extract_nel_report_to`: valid JSON; malformed JSON; missing `report_to` field.
- `_extract_integrity_endpoints`: single endpoint; multiple endpoints; missing
  `endpoints=`; malformed inner list.
- `_is_navigation_response`: `text/html`; `text/html; charset=utf-8`;
  `application/xhtml+xml`; `application/json` → False; missing → True; empty → True.

### Layer 2 — Classification tests (~10 tests)

Drive the classification logic directly with crafted definition/reference inputs:

- IP-only orphan → REPORT-004 HIGH
- IP orphan + same name in CSP → REPORT-004 (IP wins, both headers listed)
- Name in `Report-To` only, referenced from CSP → REPORT-001 LOW
- Name in nothing, referenced from CSP → REPORT-002 MEDIUM
- Placeholder (`todo`) referenced only from CSP-RO → REPORT-002 downgraded to INFO
- Placeholder referenced from CSP (enforcing) → REPORT-002 stays MEDIUM
- Placeholder referenced from IP → REPORT-004 stays HIGH (no downgrade)
- Same orphan in three headers → 1 finding, all 3 listed
- Two distinct orphan names → 2 findings, no cross-pollination
- Empty headers → 0 findings

### Layer 3 — Analyzer integration tests (~15 tests)

Full `analyze()` calls with crafted header dicts:

- Healthy site (all references resolve) → 0 findings
- Site with no reporting headers at all → 0 findings
- Site with `Reporting-Endpoints` defined but no references → 0 findings
- Non-HTML response (`Content-Type: application/json`) → 0 findings even with orphans
- HTML response, missing Content-Type → analyzed (default-on path)
- The §7 walkthrough example end-to-end → 3 findings with correct severities
  and affected-header lists
- CDN fingerprint detected → caveat appended to all findings
- CDN fingerprint absent → no caveat
- Severity tier preserved across CDN-detected and CDN-absent runs
- COOP-RO and COEP-RO Report-Only siblings extracted correctly
- Malformed JSON in `Report-To` doesn't crash the analyzer
- Malformed `Reporting-Endpoints` doesn't crash
- `Integrity-Policy` orphan with same name also referenced from CSP →
  single REPORT-004 listing both headers
- Two distinct orphans (one MEDIUM, one HIGH) → both findings emitted
- `fingerprint_cdn` raises → caveat absent, no analyzer crash

### Layer 4 — Scanner-integration smoke (~3 tests)

Verify the analyzer is wired into `ALL_ANALYZERS` and runs as part of
`HeadScanner._analyze_headers()`:

- New analyzer appears in `get_analyzer_names()` output
- Scanner test fixture with deliberately orphaned CSP `report-to` produces a
  REPORT-002 finding in the result
- Scanner against a clean response produces no REPORT-* findings

### Test infrastructure

Standard `pytest`. No fixtures beyond raw header dicts. Mock `fingerprint_cdn`
via `monkeypatch` for CDN-caveat tests. No httpx mocking needed at the
analyzer level — pure static analysis. Scanner-integration smoke tests use the
existing scanner test fixtures (which already mock httpx clients).

**Coverage target:** every parser helper exercised, every classification
branch hit, the discriminator gate exercised both directions, the CDN caveat
path exercised both directions.

## 11. Future enhancements

Out of v1 scope; capture for future versions:

- **Non-HTTPS endpoint URL sub-finding.** Browsers silently discard reports to
  `http://` URLs even when the endpoint name is defined. Worth adding as
  REPORT-005 (LOW) after v1 ships.
- **Active endpoint reachability probe.** With user opt-in, send a synthetic
  POST to defined endpoints and check for a 2xx response. Would graduate the
  module from `analyzers/` to `corsair/reporting/auditor.py`.
- **`ReportingObserver` JS detection.** A JS-side `ReportingObserver` is a
  legitimate alternative to HTTP-header reporting. Currently we cannot detect
  it without DOM analysis; if Corsair gains DOM-fetching capability, suppress
  REPORT-002 findings when an observer is present.
- **Permissions-Policy reporting.** Active W3C proposals add reporting to
  Permissions-Policy. Once stabilized, add as the 11th reference header.
- **Multi-response state aggregation.** If Corsair scans multiple URLs from
  the same origin in one run, share extracted definitions across responses to
  avoid the H-D false-positive entirely.

## 12. Implementation handoff

After this spec is approved by the user, the brainstorming skill transitions
to `superpowers:writing-plans` to produce a task-by-task implementation plan
saved to `docs/superpowers/plans/2026-05-03-reporting-endpoints-coherence-plan.md`.
The plan will be executed via `superpowers:subagent-driven-development` in a
dedicated worktree, mirroring the v0.5.3 Fetch Metadata workflow.
