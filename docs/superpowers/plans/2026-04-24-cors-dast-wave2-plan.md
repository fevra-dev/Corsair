# CORS DAST Wave 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship CORS DAST Wave 2 as v0.5.1 — add the bypass matrix (subdomain/regex, protocol downgrade, internal origin) to the active CORS probe set, with three new findings wired through the existing `CORSAuditor` pipeline.

**Architecture:** Extend `build_probes()` with a `build_bypass_matrix(host)` helper that derives a deterministic probe set from the target host. Extend `classify_reflection()` to recognize bypass-pattern reflections via label-specific matchers. Add three new `Finding` entries (`CORS_SUBDOMAIN_BYPASS`, `CORS_PROTOCOL_DOWNGRADE`, `CORS_INTERNAL_ORIGIN`) to `findings.py`. No changes to `CORSAuditor._active_reflection_phase` orchestration — the existing loop already feeds any classifier verdict to `get_finding()` and builds the finding. Wave 2 is purely additive: zero changes to Wave 1 semantics, all Wave 1 tests stay green.

**Tech Stack:** Python 3.9+, `httpx`, `asyncio`, `pytest` (asyncio_mode=auto), `unittest.mock` (AsyncMock/MagicMock/patch).

**Spec reference:** `docs/superpowers/specs/2026-04-19-cors-dast-design.md` §4.2 (payload matrix, lines 96-104) and §5 (finding taxonomy, lines 174-176).

**Wave 1 reference:** `docs/superpowers/plans/2026-04-20-cors-dast-plan.md` (already shipped as v0.5.0 at commit `8842283`).

---

## File Structure

**Files to modify:**
- `corsair/cors/probe.py` — add `build_bypass_matrix(host)`; extend `build_probes()` to include the matrix; add new probe labels.
- `corsair/cors/analyzers.py` — extend `classify_reflection()` with three new branches (subdomain_bypass / protocol_downgrade / internal_origin); add `_DEFAULTS` entries for the three new finding IDs; extend `_DOWNGRADE` for `CORS_SUBDOMAIN_BYPASS`.
- `corsair/cors/findings.py` — add three new `Finding` templates and register them in `ALL_CORS_FINDINGS`.
- `corsair/__init__.py` — bump `__version__` to `"0.5.1"`.
- `pyproject.toml` — bump `version` to `"0.5.1"`.
- `README.md` — prepend a `### v0.5.1 — CORS DAST Wave 2 (2026-04-24)` changelog section above the v0.5.0 section.

**Files to create:**
- `tests/test_cors_bypass_matrix.py` — golden-file test for `build_bypass_matrix()` and label/origin assertions.
- `tests/test_cors_wave2_classifier.py` — classifier tests for the three new branches (regex match, no-match guards, ACAC handling, sensitivity downgrade for `CORS_SUBDOMAIN_BYPASS`).
- `tests/test_cors_wave2_findings.py` — finding-registry tests (IDs present, severities match spec §5, titles, descriptions non-empty).
- `tests/test_cors_wave2_auditor.py` — end-to-end auditor tests with mocked httpx that verify each new finding fires via the full pipeline.

**Files unchanged:**
- `corsair/cors/auditor.py` — no changes (the existing `_active_reflection_phase` already handles any `ReflectionVerdict`).
- `corsair/scanner.py` — no changes.
- `corsair/cli.py` — no changes. Wave 2 uses the existing `--cors-evil-origin` flag to parameterize the bypass matrix.
- `corsair/cors/passive.py` — no changes.

---

## Task 1: Bypass Matrix Builder (`build_bypass_matrix`)

Ship the deterministic payload set from spec §4.2, locked by a golden-file test so the shipped probe order never silently shifts.

**Files:**
- Modify: `corsair/cors/probe.py`
- Test: `tests/test_cors_bypass_matrix.py`

- [ ] **Step 1: Write the failing golden-file test**

Create `tests/test_cors_bypass_matrix.py`:

```python
"""Golden-file tests for the Wave 2 bypass matrix."""

from corsair.cors.probe import build_bypass_matrix, build_probes


class TestBuildBypassMatrix:
    def test_matrix_for_host_api_example_com(self):
        """Golden: exact payload set for api.example.com."""
        probes = build_bypass_matrix(
            url="https://api.example.com/v1/data",
            host="api.example.com",
        )
        origins_and_labels = [(p.origin, p.label) for p in probes]

        expected = [
            # Subdomain/regex bypass patterns
            ("https://evil.api.example.com", "subdomain_evil_prefix"),
            ("https://api.example.com.evil.com", "subdomain_attacker_suffix"),
            ("https://apiXexampleXcom.evil.com", "subdomain_dot_confusion"),
            ("https://api.example.com.evil", "subdomain_tld_confusion"),
            ("https://anysub.api.example.com", "subdomain_wildcard"),
            ("https://api-evil.example.com", "subdomain_contains_match"),
            # Protocol downgrade (HTTPS target → http:// origin)
            ("http://api.example.com", "protocol_downgrade"),
            # Internal/private origins
            ("http://127.0.0.1", "internal_loopback_ip"),
            ("http://localhost", "internal_loopback_name"),
            ("http://10.0.0.1", "internal_rfc1918_10"),
            ("http://192.168.0.1", "internal_rfc1918_192"),
        ]
        assert origins_and_labels == expected, (
            f"Matrix drift. got={origins_and_labels} expected={expected}"
        )

    def test_each_probe_has_unique_cache_buster(self):
        probes = build_bypass_matrix(
            url="https://api.example.com/",
            host="api.example.com",
        )
        busters = [p.cache_buster for p in probes]
        assert len(set(busters)) == len(busters)
        assert all(len(b) == 16 for b in busters)

    def test_all_probes_target_same_url(self):
        url = "https://api.example.com/v1/data?x=1"
        probes = build_bypass_matrix(url=url, host="api.example.com")
        assert all(p.url == url for p in probes)


class TestBuildProbesIncludesMatrix:
    def test_http_target_omits_protocol_downgrade(self):
        """Protocol-downgrade only makes sense when target is HTTPS."""
        probes = build_probes(
            url="http://plain.example.com/",
            evil_origin="https://evil.example",
        )
        labels = [p.label for p in probes]
        assert "protocol_downgrade" not in labels

    def test_https_target_includes_protocol_downgrade(self):
        probes = build_probes(
            url="https://secure.example.com/",
            evil_origin="https://evil.example",
        )
        labels = [p.label for p in probes]
        assert "protocol_downgrade" in labels

    def test_build_probes_includes_wave1_plus_wave2(self):
        probes = build_probes(
            url="https://api.example.com/",
            evil_origin="https://evil.example",
        )
        labels = set(p.label for p in probes)
        # Wave 1
        assert "arbitrary_origin" in labels
        assert "null_origin" in labels
        # Wave 2 (a representative sample — full list locked in
        # TestBuildBypassMatrix.test_matrix_for_host_api_example_com).
        assert "subdomain_evil_prefix" in labels
        assert "internal_loopback_ip" in labels
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_cors_bypass_matrix.py -v`
Expected: FAIL with `AttributeError: module 'corsair.cors.probe' has no attribute 'build_bypass_matrix'`.

- [ ] **Step 3: Implement `build_bypass_matrix` and extend `build_probes`**

Replace the `build_probes` function in `corsair/cors/probe.py` (lines 50-70) with:

```python
def build_bypass_matrix(url: str, host: str) -> List[OriginProbe]:
    """
    Build the Wave 2 bypass-matrix probe set for a given host.

    Derives payloads from spec §4.2:
    - Subdomain/regex bypass (6 patterns)
    - Protocol downgrade (1 pattern — caller decides whether to include)
    - Internal-network origins (4 patterns)

    Ordering is stable; a golden-file test locks the exact payload set.
    """
    # Pre-split for the dot-confusion and TLD-confusion patterns.
    host_no_tld = ".".join(host.split(".")[:-1]) if "." in host else host
    host_dots_sanitized = host.replace(".", "X")
    host_prefix = host.split(".")[0]

    matrix: List[tuple[str, str]] = [
        # --- Subdomain / regex bypass ---
        (f"https://evil.{host}", "subdomain_evil_prefix"),
        (f"https://{host}.evil.com", "subdomain_attacker_suffix"),
        (f"https://{host_dots_sanitized}.evil.com", "subdomain_dot_confusion"),
        (f"https://{host}.evil", "subdomain_tld_confusion"),
        (f"https://anysub.{host}", "subdomain_wildcard"),
        (f"https://{host_prefix}-evil.{'.'.join(host.split('.')[1:]) or 'com'}",
         "subdomain_contains_match"),
        # --- Protocol downgrade ---
        (f"http://{host}", "protocol_downgrade"),
        # --- Internal / private origins ---
        ("http://127.0.0.1", "internal_loopback_ip"),
        ("http://localhost", "internal_loopback_name"),
        ("http://10.0.0.1", "internal_rfc1918_10"),
        ("http://192.168.0.1", "internal_rfc1918_192"),
    ]

    return [
        OriginProbe(
            url=url,
            origin=origin,
            label=label,
            cache_buster=_make_cache_buster(),
        )
        for origin, label in matrix
    ]


def build_probes(url: str, evil_origin: str) -> List[OriginProbe]:
    """
    Build the full active probe set: Wave 1 (arbitrary + null) + Wave 2
    (bypass matrix). Protocol-downgrade probe is dropped for non-HTTPS
    targets (it only demonstrates downgrade when the target is HTTPS).
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or ""
    is_https = parsed.scheme == "https"

    wave1 = [
        OriginProbe(
            url=url,
            origin=evil_origin,
            label="arbitrary_origin",
            cache_buster=_make_cache_buster(),
        ),
        OriginProbe(
            url=url,
            origin="null",
            label="null_origin",
            cache_buster=_make_cache_buster(),
        ),
    ]
    wave2 = build_bypass_matrix(url=url, host=host)
    if not is_https:
        wave2 = [p for p in wave2 if p.label != "protocol_downgrade"]
    return wave1 + wave2
```

Note: `build_bypass_matrix` expects the caller to have already parsed the host. The `subdomain_contains_match` pattern builds `https://{host_prefix}-evil.{rest_of_host}` (e.g. `api-evil.example.com` for `api.example.com`) — when the host has no dots (single-label hostnames, rare), it falls back to `.com` to keep the probe syntactically valid.

The dot-confusion pattern intentionally replaces dots with `X` (a literal character) rather than removing them — this catches regex allowlists that treat `.` as a metacharacter without escaping. Example: if an allowlist regex is `^api\.example\.com$` (correct) the pattern won't match, but if it's `^api.example.com$` (unescaped), `apiXexampleXcom.evil.com` will match and the server will reflect it.

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_cors_bypass_matrix.py -v`
Expected: PASS — all 5 tests.

Also run the Wave 1 probe tests to confirm zero regression:
Run: `python3 -m pytest tests/test_cors_probe.py -v`
Expected: PASS — all 9 Wave 1 probe tests still pass (the `build_probes` contract is extended, not changed, and Wave 1 labels still appear).

- [ ] **Step 5: Commit**

```bash
git add corsair/cors/probe.py tests/test_cors_bypass_matrix.py
git commit -m "feat(cors): add Wave 2 bypass matrix probe builder

Adds build_bypass_matrix(url, host) producing 11 payloads derived from
spec §4.2: 6 subdomain/regex bypass patterns + 1 protocol-downgrade +
4 internal-network origins. Matrix order is locked by a golden-file
test. build_probes() now returns Wave 1 + Wave 2; protocol_downgrade
is dropped for non-HTTPS targets.

Wave 2 Task 1/5."
```

---

## Task 2: Wave 2 Finding Definitions

Add three `Finding` templates matching spec §5 severities and register them.

**Files:**
- Modify: `corsair/cors/findings.py`
- Test: `tests/test_cors_wave2_findings.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_cors_wave2_findings.py`:

```python
"""Wave 2 finding registry tests."""

from corsair.cors.findings import ALL_CORS_FINDINGS, get_finding
from corsair.models import HeaderCategory, Severity


WAVE2_IDS = (
    "CORS_SUBDOMAIN_BYPASS",
    "CORS_PROTOCOL_DOWNGRADE",
    "CORS_INTERNAL_ORIGIN",
)


class TestWave2FindingsRegistered:
    def test_all_three_present_in_registry(self):
        for fid in WAVE2_IDS:
            assert fid in ALL_CORS_FINDINGS, f"{fid} missing"

    def test_get_finding_returns_deep_copy(self):
        a = get_finding("CORS_SUBDOMAIN_BYPASS")
        b = get_finding("CORS_SUBDOMAIN_BYPASS")
        assert a is not b  # deep copy — mutation safety
        a.title = "mutated"
        assert b.title != "mutated"


class TestWave2FindingsSeverities:
    """Matches spec §5 severity column."""

    def test_subdomain_bypass_is_high(self):
        f = get_finding("CORS_SUBDOMAIN_BYPASS")
        assert f.severity == Severity.HIGH

    def test_protocol_downgrade_is_high(self):
        f = get_finding("CORS_PROTOCOL_DOWNGRADE")
        assert f.severity == Severity.HIGH

    def test_internal_origin_is_high(self):
        f = get_finding("CORS_INTERNAL_ORIGIN")
        assert f.severity == Severity.HIGH


class TestWave2FindingsMetadata:
    def test_all_are_cors_category(self):
        for fid in WAVE2_IDS:
            f = get_finding(fid)
            assert f.category == HeaderCategory.CORS

    def test_all_have_non_empty_titles_and_descriptions(self):
        for fid in WAVE2_IDS:
            f = get_finding(fid)
            assert f.title, f"{fid} has empty title"
            assert len(f.description) > 50, (
                f"{fid} description too short ({len(f.description)} chars)"
            )

    def test_all_have_header_access_control_allow_origin(self):
        for fid in WAVE2_IDS:
            f = get_finding(fid)
            assert f.header == "Access-Control-Allow-Origin"

    def test_all_have_recommendations(self):
        for fid in WAVE2_IDS:
            f = get_finding(fid)
            assert f.recommendation, f"{fid} has no recommendation"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_cors_wave2_findings.py -v`
Expected: FAIL — `KeyError` or `AssertionError: CORS_SUBDOMAIN_BYPASS missing`.

- [ ] **Step 3: Add the three findings**

Edit `corsair/cors/findings.py`. Insert the three new `Finding` definitions after the Core 5 block and before the `# -- Meta findings` comment (after line 160 in the current file, inside the `# -- Core 5 ---` block style so Wave 2 sits next to related reflection findings):

```python
# -- Wave 2: bypass matrix ---------------------------------------------------

_CORS_SUBDOMAIN_BYPASS = Finding(
    header="Access-Control-Allow-Origin",
    category=HeaderCategory.CORS,
    severity=Severity.HIGH,
    title="Subdomain or regex bypass reflected",
    description=(
        "The server reflected an Origin crafted to bypass a naive "
        "subdomain or regex allowlist (e.g. 'evil.target.com', "
        "'target.com.evil.com', or a dot-confusion payload). This "
        "indicates the allowlist matcher is too permissive — typically "
        "a substring check, a .startswith() / .endswith() test, or an "
        "unescaped regex. Attackers who can register a matching domain "
        "gain cross-origin read access to this endpoint."
    ),
    current_value=None,
    recommendation=(
        "Validate Origin with exact-string comparison against a strict "
        "allowlist. If a regex is required, escape dots ('\\.'), anchor "
        "with ^ and $, and never use substring / prefix / suffix matching."
    ),
    example_value="Access-Control-Allow-Origin: https://trusted.example.com",
    reference_url=_PORTSWIGGER_URL,
    compliance_mappings=[_OWASP_A01, _OWASP_A05],
    cve_correlations=[_CWE_346, _CWE_942],
)

_CORS_PROTOCOL_DOWNGRADE = Finding(
    header="Access-Control-Allow-Origin",
    category=HeaderCategory.CORS,
    severity=Severity.HIGH,
    title="HTTP origin trusted on HTTPS target",
    description=(
        "The HTTPS endpoint reflects an Origin of 'http://{host}' — the "
        "same hostname over plaintext. An attacker on the network path "
        "(open Wi-Fi, compromised router, ISP-level MITM) can host a "
        "page at http://{host}, load the HTTPS endpoint cross-origin, "
        "and exfiltrate the response. The HTTPS protection on the "
        "target is negated whenever the browser happens to resolve the "
        "hostname to an attacker-served http:// page."
    ),
    current_value=None,
    recommendation=(
        "Reject Origin values whose scheme does not match the target's "
        "scheme. On HTTPS endpoints the allowlist should contain only "
        "https:// origins."
    ),
    example_value="Access-Control-Allow-Origin: https://trusted.example.com",
    reference_url=_PORTSWIGGER_URL,
    compliance_mappings=[_OWASP_A01, _OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_346],
)

_CORS_INTERNAL_ORIGIN = Finding(
    header="Access-Control-Allow-Origin",
    category=HeaderCategory.CORS,
    severity=Severity.HIGH,
    title="Internal or private-network origin trusted",
    description=(
        "The server reflects an Origin pointing at a private-network "
        "address (127.0.0.1, localhost, 10.0.0.0/8, 192.168.0.0/16). "
        "This typically means a development-time CORS config shipped "
        "to production. An attacker can trick a developer on the "
        "internal network into loading an attacker page that pivots "
        "through the browser to read internal responses; it also "
        "signals weak Origin validation overall."
    ),
    current_value=None,
    recommendation=(
        "Remove all internal-network origins from the production CORS "
        "allowlist. Keep a separate dev config if localhost access is "
        "needed during development."
    ),
    example_value="Access-Control-Allow-Origin: https://trusted.example.com",
    reference_url=_PORTSWIGGER_URL,
    compliance_mappings=[_OWASP_A01, _OWASP_A05],
    cve_correlations=[_CWE_346],
)
```

Then extend the `ALL_CORS_FINDINGS` registry (currently lines 204-212) to include the three new entries. The full registry should read:

```python
ALL_CORS_FINDINGS: dict[str, Finding] = {
    "CORS_ARBITRARY_ORIGIN_CRED": _CORS_ARBITRARY_ORIGIN_CRED,
    "CORS_ARBITRARY_ORIGIN": _CORS_ARBITRARY_ORIGIN,
    "CORS_NULL_ORIGIN_CRED": _CORS_NULL_ORIGIN_CRED,
    "CORS_NULL_ORIGIN": _CORS_NULL_ORIGIN,
    "CORS_WILDCARD_CRED": _CORS_WILDCARD_CRED,
    "CORS_SUBDOMAIN_BYPASS": _CORS_SUBDOMAIN_BYPASS,
    "CORS_PROTOCOL_DOWNGRADE": _CORS_PROTOCOL_DOWNGRADE,
    "CORS_INTERNAL_ORIGIN": _CORS_INTERNAL_ORIGIN,
    "CORS_PROBE_INCONCLUSIVE": _CORS_PROBE_INCONCLUSIVE,
    "CORS_PHASE_TIMEOUT": _CORS_PHASE_TIMEOUT,
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_cors_wave2_findings.py -v`
Expected: PASS — all 9 tests.

Also confirm Wave 1 registry tests still pass:
Run: `python3 -m pytest tests/test_cors_findings.py -v`
Expected: PASS — all Wave 1 tests unchanged.

- [ ] **Step 5: Commit**

```bash
git add corsair/cors/findings.py tests/test_cors_wave2_findings.py
git commit -m "feat(cors): add Wave 2 finding definitions

CORS_SUBDOMAIN_BYPASS (HIGH), CORS_PROTOCOL_DOWNGRADE (HIGH),
CORS_INTERNAL_ORIGIN (HIGH) registered in ALL_CORS_FINDINGS with
severities matching spec §5. Descriptions and recommendations
explain the exploitation path and fix for each class.

Wave 2 Task 2/5."
```

---

## Task 3: Classifier Extensions for Bypass Patterns

Extend `classify_reflection()` to recognize bypass-matrix payloads reflected in ACAO and map them to the new finding IDs. Only `CORS_SUBDOMAIN_BYPASS` is downgrade-eligible (spec §5 marks it ↓); `CORS_PROTOCOL_DOWNGRADE` and `CORS_INTERNAL_ORIGIN` do not downgrade.

**Files:**
- Modify: `corsair/cors/analyzers.py`
- Test: `tests/test_cors_wave2_classifier.py`

- [ ] **Step 1: Write the failing classifier tests**

Create `tests/test_cors_wave2_classifier.py`:

```python
"""Classifier tests for Wave 2 bypass reflections."""

from corsair.cors.analyzers import classify_reflection
from corsair.cors.probe import ProbeResult


def _result(label, origin, acao, acac=None, **kwargs):
    kwargs.setdefault("status_code", 200)
    return ProbeResult(
        label=label,
        origin_sent=origin,
        acao=acao,
        acac=acac,
        **kwargs,
    )


class TestSubdomainBypass:
    def test_evil_prefix_reflected_is_subdomain_bypass(self):
        r = _result(
            label="subdomain_evil_prefix",
            origin="https://evil.api.example.com",
            acao="https://evil.api.example.com",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is not None
        assert verdict.finding_id == "CORS_SUBDOMAIN_BYPASS"
        assert verdict.default_severity.value == "HIGH"

    def test_attacker_suffix_reflected(self):
        r = _result(
            label="subdomain_attacker_suffix",
            origin="https://api.example.com.evil.com",
            acao="https://api.example.com.evil.com",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_SUBDOMAIN_BYPASS"

    def test_dot_confusion_reflected(self):
        r = _result(
            label="subdomain_dot_confusion",
            origin="https://apiXexampleXcom.evil.com",
            acao="https://apiXexampleXcom.evil.com",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_SUBDOMAIN_BYPASS"

    def test_subdomain_bypass_without_signals_downgrades(self):
        # No Set-Cookie, no Auth header, no JSON, no login redirect → MEDIUM.
        r = _result(
            label="subdomain_evil_prefix",
            origin="https://evil.api.example.com",
            acao="https://evil.api.example.com",
        )
        verdict = classify_reflection(
            r,
            evil_origin="https://evil.example",
            request_headers={},
        )
        assert verdict.downgraded is True
        assert verdict.effective_severity.value == "MEDIUM"

    def test_subdomain_bypass_with_set_cookie_stays_high(self):
        r = _result(
            label="subdomain_evil_prefix",
            origin="https://evil.api.example.com",
            acao="https://evil.api.example.com",
            set_cookie="sess=abc",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.downgraded is False
        assert verdict.effective_severity.value == "HIGH"

    def test_no_reflection_returns_none(self):
        r = _result(
            label="subdomain_evil_prefix",
            origin="https://evil.api.example.com",
            acao="https://trusted.example.com",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None


class TestProtocolDowngrade:
    def test_http_origin_reflected_is_protocol_downgrade(self):
        r = _result(
            label="protocol_downgrade",
            origin="http://api.example.com",
            acao="http://api.example.com",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is not None
        assert verdict.finding_id == "CORS_PROTOCOL_DOWNGRADE"
        assert verdict.effective_severity.value == "HIGH"

    def test_protocol_downgrade_does_not_downgrade_severity(self):
        # Spec §5: only CORS_ARBITRARY_* and CORS_SUBDOMAIN_BYPASS downgrade.
        r = _result(
            label="protocol_downgrade",
            origin="http://api.example.com",
            acao="http://api.example.com",
        )
        verdict = classify_reflection(
            r,
            evil_origin="https://evil.example",
            request_headers={},
        )
        assert verdict.downgraded is False
        assert verdict.effective_severity.value == "HIGH"

    def test_no_match_when_acao_differs(self):
        r = _result(
            label="protocol_downgrade",
            origin="http://api.example.com",
            acao="https://api.example.com",  # server upgraded scheme — not a bypass
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None


class TestInternalOrigin:
    def test_loopback_ip_reflected(self):
        r = _result(
            label="internal_loopback_ip",
            origin="http://127.0.0.1",
            acao="http://127.0.0.1",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_INTERNAL_ORIGIN"

    def test_loopback_name_reflected(self):
        r = _result(
            label="internal_loopback_name",
            origin="http://localhost",
            acao="http://localhost",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_INTERNAL_ORIGIN"

    def test_rfc1918_10_reflected(self):
        r = _result(
            label="internal_rfc1918_10",
            origin="http://10.0.0.1",
            acao="http://10.0.0.1",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_INTERNAL_ORIGIN"

    def test_rfc1918_192_reflected(self):
        r = _result(
            label="internal_rfc1918_192",
            origin="http://192.168.0.1",
            acao="http://192.168.0.1",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_INTERNAL_ORIGIN"

    def test_internal_origin_does_not_downgrade(self):
        r = _result(
            label="internal_loopback_ip",
            origin="http://127.0.0.1",
            acao="http://127.0.0.1",
        )
        verdict = classify_reflection(
            r,
            evil_origin="https://evil.example",
            request_headers={},
        )
        assert verdict.downgraded is False
        assert verdict.effective_severity.value == "HIGH"


class TestWave1Unaffected:
    """Regression: Wave 1 classifier paths must still return the same verdicts."""

    def test_arbitrary_origin_still_fires(self):
        r = _result(
            label="arbitrary_origin",
            origin="https://evil.example",
            acao="https://evil.example",
            acac="true",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_ARBITRARY_ORIGIN_CRED"

    def test_null_origin_still_fires(self):
        r = _result(
            label="null_origin",
            origin="null",
            acao="null",
            acac="true",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_NULL_ORIGIN_CRED"

    def test_wildcard_still_skipped(self):
        r = _result(
            label="arbitrary_origin",
            origin="https://evil.example",
            acao="*",
            acac="true",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None

    def test_auth_gate_still_skipped(self):
        r = _result(
            label="subdomain_evil_prefix",
            origin="https://evil.api.example.com",
            acao="https://evil.api.example.com",
            status_code=401,
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_cors_wave2_classifier.py -v`
Expected: FAIL — Wave 2 branches not yet implemented, tests asserting `verdict.finding_id == "CORS_SUBDOMAIN_BYPASS"` etc. will fail with `verdict is None`.

- [ ] **Step 3: Extend `classify_reflection`**

Edit `corsair/cors/analyzers.py`. First extend the severity dicts (currently at lines 35-47). Replace the `_DEFAULTS` and `_DOWNGRADE` blocks with:

```python
# Default severities per finding ID, matching spec §5.
_DEFAULTS: Dict[str, Severity] = {
    "CORS_ARBITRARY_ORIGIN_CRED": Severity.CRITICAL,
    "CORS_ARBITRARY_ORIGIN": Severity.HIGH,
    "CORS_NULL_ORIGIN_CRED": Severity.HIGH,
    "CORS_NULL_ORIGIN": Severity.MEDIUM,
    # Wave 2
    "CORS_SUBDOMAIN_BYPASS": Severity.HIGH,
    "CORS_PROTOCOL_DOWNGRADE": Severity.HIGH,
    "CORS_INTERNAL_ORIGIN": Severity.HIGH,
}

# Downgrade map: CRITICAL→HIGH, HIGH→MEDIUM. Spec §5 marks only
# CORS_ARBITRARY_* and CORS_SUBDOMAIN_BYPASS with the ↓ indicator;
# protocol_downgrade / internal_origin / null_* do NOT downgrade.
_DOWNGRADE: Dict[str, Severity] = {
    "CORS_ARBITRARY_ORIGIN_CRED": Severity.HIGH,
    "CORS_ARBITRARY_ORIGIN": Severity.MEDIUM,
    "CORS_SUBDOMAIN_BYPASS": Severity.MEDIUM,
}
```

Next, add module-level label sets above `classify_reflection()` (just below the existing `_JSON_CT_MARKERS = ...` line at line 51):

```python
_SUBDOMAIN_BYPASS_LABELS = frozenset({
    "subdomain_evil_prefix",
    "subdomain_attacker_suffix",
    "subdomain_dot_confusion",
    "subdomain_tld_confusion",
    "subdomain_wildcard",
    "subdomain_contains_match",
})

_INTERNAL_ORIGIN_LABELS = frozenset({
    "internal_loopback_ip",
    "internal_loopback_name",
    "internal_rfc1918_10",
    "internal_rfc1918_192",
})
```

Then extend the classification logic inside `classify_reflection()`. Locate the existing `if`/`elif` block (currently lines 85-90):

```python
    if result.label == "arbitrary_origin" and acao_stripped == evil_origin:
        finding_id = (
            "CORS_ARBITRARY_ORIGIN_CRED" if acac_true else "CORS_ARBITRARY_ORIGIN"
        )
    elif result.label == "null_origin" and acao_stripped.lower() == "null":
        finding_id = "CORS_NULL_ORIGIN_CRED" if acac_true else "CORS_NULL_ORIGIN"
```

Replace it with:

```python
    if result.label == "arbitrary_origin" and acao_stripped == evil_origin:
        finding_id = (
            "CORS_ARBITRARY_ORIGIN_CRED" if acac_true else "CORS_ARBITRARY_ORIGIN"
        )
    elif result.label == "null_origin" and acao_stripped.lower() == "null":
        finding_id = "CORS_NULL_ORIGIN_CRED" if acac_true else "CORS_NULL_ORIGIN"
    elif (
        result.label in _SUBDOMAIN_BYPASS_LABELS
        and acao_stripped == result.origin_sent
    ):
        finding_id = "CORS_SUBDOMAIN_BYPASS"
    elif (
        result.label == "protocol_downgrade"
        and acao_stripped == result.origin_sent
    ):
        finding_id = "CORS_PROTOCOL_DOWNGRADE"
    elif (
        result.label in _INTERNAL_ORIGIN_LABELS
        and acao_stripped == result.origin_sent
    ):
        finding_id = "CORS_INTERNAL_ORIGIN"
```

The classifier fires only when ACAO exactly matches the probe's `origin_sent` — a stricter check than "reflects anything suspicious" and matches the Wave 1 pattern. This avoids false positives where a server rewrites the reflected origin (e.g., `protocol_downgrade` probe sends `http://api.example.com` but server echoes `https://api.example.com` as its canonical origin — not a bypass).

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_cors_wave2_classifier.py -v`
Expected: PASS — all 17 tests.

Also run the Wave 1 classifier suite for regression:
Run: `python3 -m pytest tests/test_cors_analyzers.py -v`
Expected: PASS — all 25 Wave 1 classifier tests unchanged.

- [ ] **Step 5: Commit**

```bash
git add corsair/cors/analyzers.py tests/test_cors_wave2_classifier.py
git commit -m "feat(cors): classify Wave 2 bypass reflections

Extends classify_reflection() with three new branches driven off probe
label: subdomain bypass (6 labels → CORS_SUBDOMAIN_BYPASS, ↓MEDIUM
when no sensitivity signal), protocol_downgrade (→ CORS_PROTOCOL_DOWNGRADE,
no downgrade), and internal_* (4 labels → CORS_INTERNAL_ORIGIN, no
downgrade). All use exact origin-echo match to avoid false positives
where servers normalize reflected origins. Wave 1 classifier paths
unaffected.

Wave 2 Task 3/5."
```

---

## Task 4: End-to-End Auditor Test

Verify each new finding fires through the full `CORSAuditor` pipeline with mocked httpx, including the auditor's severity-downgrade-description augmentation.

**Files:**
- Test: `tests/test_cors_wave2_auditor.py`

No production code changes — the existing `_active_reflection_phase` already loops over `ReflectionVerdict` instances and builds findings via `get_finding()`.

- [ ] **Step 1: Write the integration test**

Create `tests/test_cors_wave2_auditor.py`:

```python
"""End-to-end CORSAuditor tests for Wave 2 findings."""

from unittest.mock import AsyncMock, MagicMock, patch

from corsair.cors.auditor import CORSAuditor
from corsair.models import Severity


def _mock_response(headers=None, status_code=200):
    resp = MagicMock()
    resp.headers = headers or {}
    resp.status_code = status_code
    resp.text = ""
    return resp


def _audit_with_reflection(reflect_for_origin: str, headers_extra=None):
    """Helper: run auditor where ACAO reflects `reflect_for_origin` exactly.

    All other probes return a non-reflecting response so only the intended
    verdict fires.
    """
    headers_extra = headers_extra or {}
    auditor = CORSAuditor(active=True, evil_origin="https://evil.example")

    async def fake_get(*args, **kwargs):
        origin = kwargs.get("headers", {}).get("Origin")
        if origin == reflect_for_origin:
            hdrs = {
                "Access-Control-Allow-Origin": reflect_for_origin,
                **headers_extra,
            }
            return _mock_response(headers=hdrs)
        return _mock_response()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=fake_get)
        mock_client.__aenter__.return_value = mock_client
        mock_client_cls.return_value = mock_client

        return auditor.audit("https://api.example.com/v1", {})


class TestSubdomainBypassEndToEnd:
    def test_evil_prefix_fires(self):
        findings = _audit_with_reflection(
            "https://evil.api.example.com",
            headers_extra={"Set-Cookie": "sess=1"},
        )
        titles = [f.title for f in findings]
        assert "Subdomain or regex bypass reflected" in titles

    def test_subdomain_bypass_without_signals_downgrades_to_medium(self):
        findings = _audit_with_reflection("https://evil.api.example.com")
        bypass = [
            f for f in findings
            if f.title == "Subdomain or regex bypass reflected"
        ]
        assert len(bypass) == 1
        assert bypass[0].severity == Severity.MEDIUM
        assert "downgraded" in bypass[0].description.lower()


class TestProtocolDowngradeEndToEnd:
    def test_http_origin_reflected_fires(self):
        findings = _audit_with_reflection("http://api.example.com")
        titles = [f.title for f in findings]
        assert "HTTP origin trusted on HTTPS target" in titles

    def test_protocol_downgrade_stays_high_without_signals(self):
        findings = _audit_with_reflection("http://api.example.com")
        pd = [
            f for f in findings
            if f.title == "HTTP origin trusted on HTTPS target"
        ]
        assert len(pd) == 1
        assert pd[0].severity == Severity.HIGH


class TestInternalOriginEndToEnd:
    def test_loopback_reflected_fires(self):
        findings = _audit_with_reflection("http://127.0.0.1")
        titles = [f.title for f in findings]
        assert "Internal or private-network origin trusted" in titles

    def test_rfc1918_reflected_fires(self):
        findings = _audit_with_reflection("http://10.0.0.1")
        titles = [f.title for f in findings]
        assert "Internal or private-network origin trusted" in titles


class TestWave2CurrentValueIsPopulated:
    def test_current_value_includes_origin_and_acao(self):
        findings = _audit_with_reflection("http://127.0.0.1")
        f = [
            x for x in findings
            if x.title == "Internal or private-network origin trusted"
        ][0]
        assert "http://127.0.0.1" in (f.current_value or "")
        assert "ACAO" in (f.current_value or "")
```

- [ ] **Step 2: Run the test**

Run: `python3 -m pytest tests/test_cors_wave2_auditor.py -v`
Expected: PASS — all 7 tests.

- [ ] **Step 3: Run the Wave 1 auditor test for regression**

Run: `python3 -m pytest tests/test_cors_auditor_unit.py tests/test_scanner_cors_integration.py -v`
Expected: PASS — all Wave 1 auditor + scanner-integration tests unchanged.

- [ ] **Step 4: Commit**

```bash
git add tests/test_cors_wave2_auditor.py
git commit -m "test(cors): end-to-end Wave 2 auditor coverage

Verifies each of CORS_SUBDOMAIN_BYPASS, CORS_PROTOCOL_DOWNGRADE,
CORS_INTERNAL_ORIGIN fires through the full CORSAuditor pipeline with
mocked httpx. Confirms severity-downgrade description augmentation
still applies to CORS_SUBDOMAIN_BYPASS (↓MEDIUM) and that the other
two remain HIGH. current_value is populated with origin→ACAO.

Wave 2 Task 4/5."
```

---

## Task 5: Release — v0.5.1

Bump version, add changelog, final full-suite run, tag.

**Files:**
- Modify: `corsair/__init__.py`
- Modify: `pyproject.toml`
- Modify: `README.md`

- [ ] **Step 1: Bump `corsair/__init__.py`**

Replace line 27 (`__version__ = "0.5.0"`) with:

```python
__version__ = "0.5.1"
```

- [ ] **Step 2: Bump `pyproject.toml`**

Replace the line `version = "0.5.0"` (line 7) with:

```toml
version = "0.5.1"
```

- [ ] **Step 3: Add README changelog**

Edit `README.md`. Locate `### v0.5.0 — CORS DAST Wave 1 (2026-04-23)` and insert a new section immediately above it:

```markdown
### v0.5.1 — CORS DAST Wave 2 (2026-04-24)

**Bypass matrix** — CORSAuditor now ships 11 additional active probes (spec §4.2) covering the classic origin-allowlist bypass patterns:

- 6 subdomain/regex payloads: `evil.{host}`, `{host}.evil.com`, dot-confusion (`{hostX}.evil.com`), TLD-confusion (`{host}.evil`), wildcard (`anysub.{host}`), contains-match (`{prefix}-evil.{rest}`).
- Protocol downgrade (`http://{host}`, only when target is HTTPS).
- Four internal-network origins: `127.0.0.1`, `localhost`, `10.0.0.1`, `192.168.0.1`.

**New findings**
- `CORS_SUBDOMAIN_BYPASS` (HIGH, ↓MEDIUM when no sensitivity signal) — server reflects a crafted bypass payload, indicating allowlist logic is a substring/prefix/suffix match or an unescaped regex.
- `CORS_PROTOCOL_DOWNGRADE` (HIGH) — HTTPS endpoint accepts `http://{host}` as a trusted origin, negating transport protection on any network path that can MITM the http version.
- `CORS_INTERNAL_ORIGIN` (HIGH) — private-network origins (loopback, RFC1918) are on the production allowlist.

**Classifier**
- `classify_reflection()` recognizes the six bypass labels, the protocol-downgrade label, and the four internal-origin labels. Match is by exact ACAO-echo of the probe's sent origin to avoid false positives when servers normalize reflected origins.
- Only `CORS_SUBDOMAIN_BYPASS` participates in the sensitivity-signal downgrade (matches spec §5 — the `↓` indicator applies to arbitrary and subdomain classes only).

**Probe budget** — default scans now send ~13 CORS probes per target (Wave 1's 2 + Wave 2's 11). Protocol-downgrade probe is dropped for non-HTTPS targets. Matrix order is locked by a golden-file test.

**No new CLI flags** — Wave 2 reuses the existing `--cors-probe/--no-cors-probe` gate and the target URL's hostname.

**Deferred to later waves**
- Preflight divergence and CDN cache-key divergence probes (v0.5.2 — Wave 3).
- State-changing probes, framework-default heuristic, third-party XSS correlation (v0.5.3 — Wave 4).

```

- [ ] **Step 4: Run the full suite one last time**

Run: `python3 -m pytest -q --deselect tests/test_tls_auditor.py::TestBadSSLIntegration`
Expected: all pass. Previous Wave 1 baseline: 243 tests. Wave 2 adds: 5 bypass-matrix + 9 findings + 17 classifier + 7 auditor = 38 new tests. Expect **281 passed, 9 deselected**.

Note on deselection: `TestBadSSLIntegration` deselects 9 tests that hit real `badssl.com` — these have been flaky / network-drift-dependent throughout Wave 1 and are unrelated to CORS changes.

- [ ] **Step 5: Commit and tag**

```bash
git add corsair/__init__.py pyproject.toml README.md
git commit -m "chore(cors): release v0.5.1 — CORS DAST Wave 2

Version bump + changelog for the Wave 2 bypass matrix. Ships 3 new
findings (CORS_SUBDOMAIN_BYPASS ↓MEDIUM, CORS_PROTOCOL_DOWNGRADE HIGH,
CORS_INTERNAL_ORIGIN HIGH) and 11 new probes. Default scan sends ~13
CORS probes per target; protocol_downgrade dropped for non-HTTPS
targets. No CLI changes — reuses --cors-probe/--no-cors-probe.

Wave 2 Task 5/5 — closes CORS DAST v0.5.1."
```

---

## Self-Review Checklist

**1. Spec coverage.** Spec §8 Wave 2 definition (line 291-293): "Bypass-matrix payloads + 3 findings. `build_bypass_matrix(host)` with golden-file lock + `CORS_SUBDOMAIN_BYPASS`, `CORS_PROTOCOL_DOWNGRADE`, `CORS_INTERNAL_ORIGIN` findings + classifier extensions."

- [x] `build_bypass_matrix(host)` — Task 1
- [x] Golden-file lock — Task 1 step 1 (`test_matrix_for_host_api_example_com`)
- [x] `CORS_SUBDOMAIN_BYPASS` + `CORS_PROTOCOL_DOWNGRADE` + `CORS_INTERNAL_ORIGIN` — Task 2
- [x] Classifier extensions — Task 3
- [x] End-to-end verification — Task 4
- [x] Release — Task 5

Spec §4.2 (lines 96-104) payload set: covered verbatim in Task 1 step 3 (6 subdomain + 1 protocol + 4 internal = 11 probes).

Spec §5 severities (lines 174-176): `CORS_SUBDOMAIN_BYPASS` HIGH↓MEDIUM, `CORS_PROTOCOL_DOWNGRADE` HIGH, `CORS_INTERNAL_ORIGIN` HIGH. Matched in Task 2 and Task 3.

**2. Placeholder scan.** No "TBD", "implement later", or vague directives. Every step shows the exact code or command.

**3. Type consistency.**
- `OriginProbe` (from Task 1 existing in Wave 1 module) — used unchanged in Task 1, 3, 4.
- `ProbeResult.label`, `.acao`, `.origin_sent` (Wave 1) — referenced in Task 3 classifier and Task 4 tests.
- `ReflectionVerdict.finding_id`, `.default_severity`, `.effective_severity`, `.downgraded` (Wave 1) — referenced in Task 3 tests.
- New label strings used in `build_bypass_matrix` (Task 1) match exactly the labels enumerated in `_SUBDOMAIN_BYPASS_LABELS` and `_INTERNAL_ORIGIN_LABELS` (Task 3). Specifically: `subdomain_evil_prefix`, `subdomain_attacker_suffix`, `subdomain_dot_confusion`, `subdomain_tld_confusion`, `subdomain_wildcard`, `subdomain_contains_match`, `protocol_downgrade`, `internal_loopback_ip`, `internal_loopback_name`, `internal_rfc1918_10`, `internal_rfc1918_192` (11 total).
- New finding IDs in `findings.py` (Task 2) match the IDs registered in `_DEFAULTS` and returned by the classifier (Task 3): `CORS_SUBDOMAIN_BYPASS`, `CORS_PROTOCOL_DOWNGRADE`, `CORS_INTERNAL_ORIGIN`.

**4. TDD discipline.** Every task starts with a failing test, verifies it fails, implements, verifies it passes, then commits. Task 5 (release) is the only non-TDD task — release mechanics don't have meaningful tests beyond the full-suite run.

**5. Frequent commits.** 5 commits total, each independently shippable. Any task's commit could be reverted without breaking earlier ones.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-24-cors-dast-wave2-plan.md`. Two execution options:

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
