# Fetch Metadata Enforcement Probing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a new DAST module — `corsair/fetch_metadata/` — that probes whether a server enforces a Fetch Metadata resource isolation policy and emits three calibrated findings (`FM_NO_FETCH_METADATA_POLICY`, `FM_FETCH_METADATA_ENFORCED`, `FM_FETCH_METADATA_INCONCLUSIVE`).

**Architecture:** Four concurrent canary-extended HTTP probes (Baseline, Safe, Adversarial, Canary) against the target URL. A pure `classify_enforcement()` function maps the probe quartet onto an `EnforcementResult` enum. A `FetchMetadataAuditor` orchestrates the probes, infers context (cookie SameSite/CSRF, CDN fingerprint), and emits one of three findings via deepcopy factories. Wired into `HeadScanner` after the CORS auditor with a default-on `--fm-probe` CLI flag.

**Tech Stack:** Python 3.9+, `httpx` (async, no new deps), `asyncio.gather`, `dataclasses`, `enum`, `hashlib`. Test stack: `pytest`, `unittest.mock.AsyncMock`, `unittest.mock.patch("httpx.AsyncClient")`.

**Spec:** `docs/superpowers/specs/2026-04-26-fetch-metadata-probing-design.md`

---

## File Structure

| File | Responsibility | Created in |
|---|---|---|
| `corsair/fetch_metadata/__init__.py` | Re-export `FetchMetadataAuditor` | Task 3 |
| `corsair/fetch_metadata/probe.py` | Probe header sets, `EnforcementResult`, `classify_enforcement`, `_body_hash`, status sets | Task 1 |
| `corsair/fetch_metadata/findings.py` | `ALL_FM_FINDINGS` registry, `get_finding()`, severity-matrix builder, context dataclass | Task 2 |
| `corsair/fetch_metadata/auditor.py` | `FetchMetadataAuditor` orchestrator (sync `audit()` over async internals) | Task 3 |
| `corsair/cli.py` | Add `--fm-probe/--no-fm-probe` Click option (modify) | Task 4 |
| `corsair/scanner.py` | Wire `FetchMetadataAuditor` after CORS auditor block (modify) | Task 4 |
| `corsair/__init__.py` | Bump `__version__` to `"0.5.3"` (modify) | Task 5 |
| `pyproject.toml` | Bump `version` to `"0.5.3"` (modify) | Task 5 |
| `README.md` | Insert v0.5.3 changelog entry (modify) | Task 5 |
| `tests/test_fetch_metadata_probe.py` | ~25 unit tests for `classify_enforcement`, header sets, body hash, status sets | Task 1 |
| `tests/test_fetch_metadata_findings.py` | ~10 finding-factory tests for severity matrix + compliance mappings | Task 2 |
| `tests/test_fetch_metadata_auditor.py` | ~6 mocked-httpx integration tests | Task 3 |

---

## Task 1: Probe primitives + `classify_enforcement`

**Goal:** Pure-function classifier with full TDD coverage. No HTTP calls. No mocks needed (the function takes ints/strings and returns an enum).

**Files:**
- Create: `corsair/fetch_metadata/__init__.py`
- Create: `corsair/fetch_metadata/probe.py`
- Create: `tests/test_fetch_metadata_probe.py`

### Step 1.1 — Create empty package init

- [ ] **Step 1.1.1: Create `corsair/fetch_metadata/__init__.py` with placeholder content**

```python
"""Fetch Metadata enforcement probing module (v0.5.3)."""
```

(The `FetchMetadataAuditor` re-export is added in Task 3 to keep this file's edit history clean.)

### Step 1.2 — Write the failing tests for `classify_enforcement`

- [ ] **Step 1.2.1: Write `tests/test_fetch_metadata_probe.py` with the full test class skeleton**

```python
"""Unit tests for corsair.fetch_metadata.probe."""

import hashlib

import pytest

from corsair.fetch_metadata.probe import (
    ADVERSARIAL_PROBE_HEADERS,
    AUTH_STATUS_CODES,
    CANARY_PROBE_HEADERS,
    ENFORCEMENT_STATUS_CODES,
    EnforcementResult,
    REDIRECT_STATUS_CODES,
    SAFE_PROBE_HEADERS,
    _body_hash,
    classify_enforcement,
)


# Reusable body hashes for clarity in tests.
BASELINE_BODY = _body_hash(b"baseline body content")
ADVERSARIAL_BODY = _body_hash(b"adversarial body content")
SAME_AS_BASELINE = BASELINE_BODY


class TestEnforcementStatusSet:
    def test_canonical_codes_present(self):
        assert {400, 403, 405, 451} <= ENFORCEMENT_STATUS_CODES

    def test_non_enforcement_codes_absent(self):
        for code in (200, 418, 429, 503):
            assert code not in ENFORCEMENT_STATUS_CODES

    def test_redirect_set(self):
        assert {301, 302, 303, 307, 308} <= REDIRECT_STATUS_CODES

    def test_auth_set(self):
        assert AUTH_STATUS_CODES == {401}


class TestProbeHeaderSets:
    def test_safe_keys_exact(self):
        assert set(SAFE_PROBE_HEADERS.keys()) == {
            "Sec-Fetch-Site",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Dest",
        }

    def test_safe_values(self):
        assert SAFE_PROBE_HEADERS["Sec-Fetch-Site"] == "same-origin"
        assert SAFE_PROBE_HEADERS["Sec-Fetch-Mode"] == "cors"
        assert SAFE_PROBE_HEADERS["Sec-Fetch-Dest"] == "empty"

    def test_adversarial_values(self):
        assert ADVERSARIAL_PROBE_HEADERS["Sec-Fetch-Site"] == "cross-site"
        assert ADVERSARIAL_PROBE_HEADERS["Sec-Fetch-Mode"] == "cors"
        assert ADVERSARIAL_PROBE_HEADERS["Sec-Fetch-Dest"] == "empty"

    def test_canary_value_literal(self):
        assert CANARY_PROBE_HEADERS["Sec-Fetch-Site"] == "corsair-canary-invalid"

    def test_no_origin_header_in_any_probe(self):
        for probe in (SAFE_PROBE_HEADERS, ADVERSARIAL_PROBE_HEADERS, CANARY_PROBE_HEADERS):
            assert "Origin" not in probe
            assert "origin" not in probe

    def test_no_referer_header_in_any_probe(self):
        for probe in (SAFE_PROBE_HEADERS, ADVERSARIAL_PROBE_HEADERS, CANARY_PROBE_HEADERS):
            assert "Referer" not in probe
            assert "referer" not in probe


class TestBodyHash:
    def test_identical_first_4kb_hash_match_despite_tail_difference(self):
        prefix = b"A" * 4096
        a = prefix + b"tail-one"
        b = prefix + b"tail-two-different-length"
        assert _body_hash(a) == _body_hash(b)

    def test_one_byte_difference_in_first_4kb_diverges(self):
        a = b"A" * 4096
        b = b"A" * 4095 + b"B"
        assert _body_hash(a) != _body_hash(b)

    def test_returns_sha256_hex_64_chars(self):
        h = _body_hash(b"hello")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


class TestClassifyEnforcement:
    """Each rule from spec §4.3, applied in order."""

    def test_rule1_safe_rejected_is_inconclusive(self):
        # Rule 1: safe blanket-rejects → INCONCLUSIVE regardless of A/C.
        result = classify_enforcement(
            baseline_status=200,
            safe_status=403,
            adversarial_status=403,
            canary_status=403,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=BASELINE_BODY,
        )
        assert result == EnforcementResult.INCONCLUSIVE

    def test_rule2_baseline_5xx_inconclusive(self):
        result = classify_enforcement(
            baseline_status=500,
            safe_status=200,
            adversarial_status=403,
            canary_status=403,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=ADVERSARIAL_BODY,
        )
        assert result == EnforcementResult.INCONCLUSIVE

    def test_rule2_baseline_401_inconclusive(self):
        result = classify_enforcement(
            baseline_status=401,
            safe_status=200,
            adversarial_status=403,
            canary_status=403,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=BASELINE_BODY,
        )
        assert result == EnforcementResult.INCONCLUSIVE

    def test_rule3_strict_enforcement(self):
        # Both A and C rejected → ENFORCED (strongest signal).
        result = classify_enforcement(
            baseline_status=200,
            safe_status=200,
            adversarial_status=403,
            canary_status=400,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=ADVERSARIAL_BODY,
        )
        assert result == EnforcementResult.ENFORCED

    def test_rule4_allowlist_enforcement_canary_2xx_body_match(self):
        # A=4xx, C=200 matching baseline body → ENFORCED (allowlist pattern).
        result = classify_enforcement(
            baseline_status=200,
            safe_status=200,
            adversarial_status=403,
            canary_status=200,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=ADVERSARIAL_BODY,
        )
        assert result == EnforcementResult.ENFORCED

    def test_rule5_redirect_on_adversarial_inconclusive(self):
        # A=302 with baseline=200 → likely auth, not FM.
        result = classify_enforcement(
            baseline_status=200,
            safe_status=200,
            adversarial_status=302,
            canary_status=200,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=BASELINE_BODY,
        )
        assert result == EnforcementResult.INCONCLUSIVE

    def test_rule6_soft_enforcement_2xx_body_differs(self):
        # A=2xx but body differs from baseline → SOFT_ENFORCED.
        result = classify_enforcement(
            baseline_status=200,
            safe_status=200,
            adversarial_status=200,
            canary_status=200,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=ADVERSARIAL_BODY,
        )
        assert result == EnforcementResult.SOFT_ENFORCED

    def test_rule7_clean_not_enforced(self):
        # A=B, C=B, body matches → NOT_ENFORCED.
        result = classify_enforcement(
            baseline_status=200,
            safe_status=200,
            adversarial_status=200,
            canary_status=200,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=BASELINE_BODY,
        )
        assert result == EnforcementResult.NOT_ENFORCED

    def test_rule8_unclassified_status_inconclusive(self):
        # A=418 (a teapot), nothing else applies → INCONCLUSIVE.
        result = classify_enforcement(
            baseline_status=200,
            safe_status=200,
            adversarial_status=418,
            canary_status=200,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=BASELINE_BODY,
        )
        assert result == EnforcementResult.INCONCLUSIVE

    def test_rule3_takes_precedence_over_rule6(self):
        # Even if A body differs, A=4xx and C=4xx wins as ENFORCED.
        result = classify_enforcement(
            baseline_status=200,
            safe_status=200,
            adversarial_status=403,
            canary_status=400,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=ADVERSARIAL_BODY,
        )
        assert result == EnforcementResult.ENFORCED

    def test_rule1_takes_precedence_over_rule2(self):
        # Safe rejection wins even if baseline is also 500.
        result = classify_enforcement(
            baseline_status=500,
            safe_status=403,
            adversarial_status=403,
            canary_status=403,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=BASELINE_BODY,
        )
        assert result == EnforcementResult.INCONCLUSIVE
```

- [ ] **Step 1.2.2: Run the test file to confirm it fails on import**

Run: `python3 -m pytest tests/test_fetch_metadata_probe.py -q`

Expected: collection error / `ModuleNotFoundError: No module named 'corsair.fetch_metadata.probe'`.

### Step 1.3 — Implement `corsair/fetch_metadata/probe.py`

- [ ] **Step 1.3.1: Create `corsair/fetch_metadata/probe.py`**

```python
"""Fetch Metadata probe primitives and classifier.

Pure-function classifier for the four-probe canary-extended sequence:
  B = Baseline (no Sec-Fetch-* headers)
  S = Safe          (Sec-Fetch-Site: same-origin)
  A = Adversarial   (Sec-Fetch-Site: cross-site)
  C = Canary        (Sec-Fetch-Site: corsair-canary-invalid)

See docs/superpowers/specs/2026-04-26-fetch-metadata-probing-design.md §4.
"""

import hashlib
from enum import Enum
from typing import Mapping


class EnforcementResult(Enum):
    ENFORCED = "enforced"
    SOFT_ENFORCED = "soft_enforced"
    NOT_ENFORCED = "not_enforced"
    INCONCLUSIVE = "inconclusive"


SAFE_PROBE_HEADERS: Mapping[str, str] = {
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
}

ADVERSARIAL_PROBE_HEADERS: Mapping[str, str] = {
    "Sec-Fetch-Site": "cross-site",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
}

CANARY_PROBE_HEADERS: Mapping[str, str] = {
    "Sec-Fetch-Site": "corsair-canary-invalid",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
}


ENFORCEMENT_STATUS_CODES = frozenset({400, 403, 405, 451})
REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})
AUTH_STATUS_CODES = frozenset({401})


def _body_hash(body: bytes) -> str:
    """SHA-256 of the first 4 KB of body — sufficient to discriminate distinct
    responses without paying for very large pages."""
    return hashlib.sha256(body[:4096]).hexdigest()


def classify_enforcement(
    baseline_status: int,
    safe_status: int,
    adversarial_status: int,
    canary_status: int,
    baseline_body_hash: str,
    adversarial_body_hash: str,
) -> EnforcementResult:
    """Map a four-probe status/body quartet onto an EnforcementResult.

    Rules applied in order — first match wins. See spec §4.3.
    """
    # Rule 1: server blanket-rejects Sec-Fetch — signal poisoned.
    if safe_status in ENFORCEMENT_STATUS_CODES:
        return EnforcementResult.INCONCLUSIVE

    # Rule 2: target unhealthy or auth-walled.
    if baseline_status >= 500 or baseline_status in AUTH_STATUS_CODES:
        return EnforcementResult.INCONCLUSIVE

    # Rule 3: spec-strict enforcement (canary also rejected).
    if (
        adversarial_status in ENFORCEMENT_STATUS_CODES
        and canary_status in ENFORCEMENT_STATUS_CODES
    ):
        return EnforcementResult.ENFORCED

    # Rule 4: allowlist enforcement (canary not in spec enum is silently
    # treated as same as baseline by the server; A is rejected).
    if (
        adversarial_status in ENFORCEMENT_STATUS_CODES
        and canary_status == baseline_status
    ):
        return EnforcementResult.ENFORCED

    # Rule 5: adversarial redirected — likely auth, not FM.
    if (
        adversarial_status in REDIRECT_STATUS_CODES
        and baseline_status not in REDIRECT_STATUS_CODES
    ):
        return EnforcementResult.INCONCLUSIVE

    # Rule 6: 2xx but body modified for cross-site — soft enforcement.
    if (
        adversarial_status < 300
        and adversarial_body_hash != baseline_body_hash
    ):
        return EnforcementResult.SOFT_ENFORCED

    # Rule 7: clean A=B, C=B → no enforcement.
    if (
        adversarial_status == baseline_status
        and canary_status == baseline_status
    ):
        return EnforcementResult.NOT_ENFORCED

    # Rule 8: anything else — INCONCLUSIVE.
    return EnforcementResult.INCONCLUSIVE
```

### Step 1.4 — Run tests until green

- [ ] **Step 1.4.1: Run the probe tests**

Run: `python3 -m pytest tests/test_fetch_metadata_probe.py -q`

Expected: ~22 tests pass, 0 failures.

If any test fails, read the failure message, fix the bug in `probe.py` (do **not** weaken the test), re-run. Iterate until green.

### Step 1.5 — Commit

- [ ] **Step 1.5.1: Stage and commit Task 1**

```bash
git add corsair/fetch_metadata/__init__.py corsair/fetch_metadata/probe.py tests/test_fetch_metadata_probe.py
git commit -m "$(cat <<'EOF'
feat(fm): probe primitives and classify_enforcement

Adds the canary-extended four-probe classifier as a pure function with
~22 unit tests covering every decision rule from the design spec
(§4.3). No HTTP, no httpx — orchestration arrives in Task 3.

Spec: docs/superpowers/specs/2026-04-26-fetch-metadata-probing-design.md
EOF
)"
```

---

## Task 2: Finding factories + severity calibration

**Goal:** Three Finding templates registered in `ALL_FM_FINDINGS`, plus a context-aware severity-matrix builder for `FM_NO_FETCH_METADATA_POLICY`. Pure functions and dataclasses; tests exercise the matrix exhaustively.

**Files:**
- Create: `corsair/fetch_metadata/findings.py`
- Create: `tests/test_fetch_metadata_findings.py`

### Step 2.1 — Write the failing tests

- [ ] **Step 2.1.1: Create `tests/test_fetch_metadata_findings.py`**

```python
"""Unit tests for corsair.fetch_metadata.findings."""

import pytest

from corsair.fetch_metadata.findings import (
    ALL_FM_FINDINGS,
    FMContext,
    build_not_enforced_finding,
    build_inconclusive_finding,
    get_finding,
)
from corsair.models import HeaderCategory, Severity


class TestRegistry:
    def test_three_findings_registered(self):
        assert set(ALL_FM_FINDINGS.keys()) == {
            "FM_NO_FETCH_METADATA_POLICY",
            "FM_FETCH_METADATA_ENFORCED",
            "FM_FETCH_METADATA_INCONCLUSIVE",
        }

    def test_get_finding_returns_deepcopy(self):
        a = get_finding("FM_FETCH_METADATA_ENFORCED")
        b = get_finding("FM_FETCH_METADATA_ENFORCED")
        assert a is not b
        a.title = "mutated"
        assert b.title != "mutated"

    def test_get_finding_unknown_returns_none(self):
        assert get_finding("FM_DOES_NOT_EXIST") is None


class TestPositiveFinding:
    def test_enforced_is_pass(self):
        f = get_finding("FM_FETCH_METADATA_ENFORCED")
        assert f.severity == Severity.PASS
        assert f.category == HeaderCategory.ISOLATION
        assert "enforced" in f.title.lower() or "enforcement" in f.title.lower()


class TestInconclusiveFinding:
    def test_inconclusive_is_info(self):
        f = build_inconclusive_finding(reason="Network error during probe sequence")
        assert f.severity == Severity.INFO
        assert "Network error during probe sequence" in f.description

    def test_inconclusive_template_unmodified(self):
        # Building a finding from the template must not mutate it.
        original = ALL_FM_FINDINGS["FM_FETCH_METADATA_INCONCLUSIVE"]
        original_desc = original.description
        build_inconclusive_finding(reason="Some specific reason")
        assert ALL_FM_FINDINGS["FM_FETCH_METADATA_INCONCLUSIVE"].description == original_desc


class TestSeverityMatrix:
    """All six rows from spec §5.1."""

    def test_no_mitigations_no_cdn_high(self):
        ctx = FMContext(
            has_samesite_strict=False,
            has_samesite_lax=False,
            has_csrf_token=False,
            cdn_detected=False,
        )
        f = build_not_enforced_finding(ctx, soft=False)
        assert f.severity == Severity.HIGH

    def test_no_mitigations_with_cdn_medium(self):
        ctx = FMContext(False, False, False, cdn_detected=True)
        f = build_not_enforced_finding(ctx, soft=False)
        assert f.severity == Severity.MEDIUM

    def test_lax_no_csrf_no_cdn_medium(self):
        ctx = FMContext(False, True, False, False)
        f = build_not_enforced_finding(ctx, soft=False)
        assert f.severity == Severity.MEDIUM

    def test_csrf_no_lax_no_cdn_medium(self):
        # XOR partial — CSRF token only.
        ctx = FMContext(False, False, True, False)
        f = build_not_enforced_finding(ctx, soft=False)
        assert f.severity == Severity.MEDIUM

    def test_lax_no_csrf_with_cdn_low(self):
        ctx = FMContext(False, True, False, True)
        f = build_not_enforced_finding(ctx, soft=False)
        assert f.severity == Severity.LOW

    def test_strict_and_csrf_low(self):
        ctx = FMContext(True, False, True, False)
        f = build_not_enforced_finding(ctx, soft=False)
        assert f.severity == Severity.LOW

    def test_strict_and_csrf_with_cdn_low(self):
        ctx = FMContext(True, False, True, True)
        f = build_not_enforced_finding(ctx, soft=False)
        assert f.severity == Severity.LOW

    def test_soft_enforcement_emits_info(self):
        # SOFT_ENFORCED collapses to INFO regardless of context.
        ctx = FMContext(False, False, False, False)
        f = build_not_enforced_finding(ctx, soft=True)
        assert f.severity == Severity.INFO


class TestComplianceMappings:
    def test_high_includes_pci_and_nist(self):
        ctx = FMContext(False, False, False, False)
        f = build_not_enforced_finding(ctx, soft=False)
        frameworks = {m.framework for m in f.compliance_mappings}
        assert "OWASP_TOP_10_2025" in frameworks
        assert "PCI_DSS_4_0" in frameworks
        assert "NIST_SP_800_53" in frameworks

    def test_medium_includes_nist_not_pci(self):
        ctx = FMContext(False, True, False, False)  # MEDIUM (lax only, no CDN)
        f = build_not_enforced_finding(ctx, soft=False)
        frameworks = {m.framework for m in f.compliance_mappings}
        assert "NIST_SP_800_53" in frameworks
        assert "PCI_DSS_4_0" not in frameworks

    def test_low_excludes_pci_and_nist(self):
        ctx = FMContext(True, False, True, False)  # LOW
        f = build_not_enforced_finding(ctx, soft=False)
        frameworks = {m.framework for m in f.compliance_mappings}
        assert "PCI_DSS_4_0" not in frameworks
        assert "NIST_SP_800_53" not in frameworks
        # OWASP and CWE always present.
        assert "OWASP_TOP_10_2025" in frameworks

    def test_cwe_correlations_present(self):
        ctx = FMContext(False, False, False, False)
        f = build_not_enforced_finding(ctx, soft=False)
        cwe_ids = {c.cve_id for c in f.cve_correlations}
        assert "CWE-352" in cwe_ids
        assert "CWE-693" in cwe_ids


class TestNonBrowserCaveat:
    def test_caveat_in_description(self):
        ctx = FMContext(False, False, False, False)
        f = build_not_enforced_finding(ctx, soft=False)
        assert "non-browser scripted clients" in f.description


class TestCdnDowngradeDescription:
    def test_cdn_warning_appended_when_cdn(self):
        ctx = FMContext(False, False, False, True)
        f = build_not_enforced_finding(ctx, soft=False)
        assert "CDN" in f.description or "direct-origin" in f.description

    def test_no_cdn_warning_when_no_cdn(self):
        ctx = FMContext(False, False, False, False)
        f = build_not_enforced_finding(ctx, soft=False)
        assert "direct-origin" not in f.description
```

- [ ] **Step 2.1.2: Run the test file to confirm it fails on import**

Run: `python3 -m pytest tests/test_fetch_metadata_findings.py -q`

Expected: `ModuleNotFoundError: No module named 'corsair.fetch_metadata.findings'`.

### Step 2.2 — Implement `corsair/fetch_metadata/findings.py`

- [ ] **Step 2.2.1: Create `corsair/fetch_metadata/findings.py`**

```python
"""Fetch Metadata finding templates, registry, and severity-matrix builder."""

import copy
from dataclasses import dataclass
from typing import Optional

from ..models import (
    ComplianceMapping,
    CVECorrelation,
    Finding,
    HeaderCategory,
    Severity,
)


def _compliance(framework: str, req_id: str, req_name: str, status: str = "FAIL") -> ComplianceMapping:
    return ComplianceMapping(
        framework=framework,
        requirement_id=req_id,
        requirement_name=req_name,
        status=status,
    )


def _cwe(cwe_id: str, desc: str) -> CVECorrelation:
    return CVECorrelation(cve_id=cwe_id, cvss_score=0.0, description=desc)


_OWASP_A01 = _compliance("OWASP_TOP_10_2025", "A01", "Broken Access Control")
_PCI_6_2_4 = _compliance("PCI_DSS_4_0", "6.2.4", "Common Software Attack Mitigations")
_NIST_SC_23 = _compliance("NIST_SP_800_53", "SC-23", "Session Authenticity")
_CWE_352 = _cwe("CWE-352", "Cross-Site Request Forgery (CSRF)")
_CWE_693 = _cwe("CWE-693", "Protection Mechanism Failure")

_REFERENCE_URL = "https://web.dev/articles/fetch-metadata"

_NON_BROWSER_CAVEAT = (
    "Caveat: non-browser scripted clients can bypass this control regardless "
    "of enforcement status. Fetch Metadata defends against browser-based CSRF "
    "and cross-origin data leaks, not API abuse or server-to-server attacks."
)

_CDN_WARNING = (
    " A CDN was fingerprinted on the response; in rare cases the CDN may strip "
    "Sec-Fetch-* headers before reaching origin. Verify on a direct-origin scan."
)

_EXAMPLE_POLICY = """\
# Pseudo-code: reference Fetch Metadata resource isolation policy.
def is_allowed(request):
    site = request.headers.get('Sec-Fetch-Site', '')
    mode = request.headers.get('Sec-Fetch-Mode', '')
    dest = request.headers.get('Sec-Fetch-Dest', '')
    if site in ('', 'same-origin', 'same-site', 'none'):
        return True
    if mode == 'navigate' and request.method == 'GET' and dest not in ('object', 'embed'):
        return True
    return False  # cross-site non-navigate GET / cross-site POST → reject
"""


# ----------------------------------------------------------------------------
# Templates
# ----------------------------------------------------------------------------

# Stored at HIGH severity so deepcopy + downgrade is the worst-case path.
_FM_NO_POLICY_TEMPLATE = Finding(
    header="Sec-Fetch-Site",
    category=HeaderCategory.ISOLATION,
    severity=Severity.HIGH,
    title="No Fetch Metadata Resource Isolation Policy",
    description=(
        "The server returned the same response to a Sec-Fetch-Site: cross-site "
        "probe as to a Sec-Fetch-Site: same-origin probe, indicating no Fetch "
        "Metadata resource isolation policy is enforced. Browser-initiated "
        "cross-site requests (CSRF via fetch, cross-origin data leaks via "
        "no-cors) are not blocked at the server layer.\n\n"
        "{mitigation_note}\n\n" + _NON_BROWSER_CAVEAT
    ),
    current_value=None,
    recommendation=(
        "Implement a server-side resource isolation policy that rejects requests "
        "where Sec-Fetch-Site is cross-site and Sec-Fetch-Mode is not navigate. "
        "Start in logging mode to identify endpoints that need cross-site "
        "exemptions, then switch to blocking. Reference: "
        "https://web.dev/articles/fetch-metadata"
    ),
    example_value=_EXAMPLE_POLICY,
    reference_url=_REFERENCE_URL,
    compliance_mappings=[_OWASP_A01, _PCI_6_2_4, _NIST_SC_23],
    cve_correlations=[_CWE_352, _CWE_693],
)

_FM_ENFORCED_TEMPLATE = Finding(
    header="Sec-Fetch-Site",
    category=HeaderCategory.ISOLATION,
    severity=Severity.PASS,
    title="Fetch Metadata Resource Isolation Policy Enforced",
    description=(
        "The server returned a rejection response (4xx) to a cross-site Fetch "
        "Metadata probe while allowing the same-origin probe. A resource "
        "isolation policy is active and blocking browser-initiated cross-site "
        "requests."
    ),
    current_value=None,
    recommendation=(
        "No action required. Consider logging enforcement rejections for "
        "threat intelligence and reviewing whether sensitive endpoints would "
        "benefit from stricter Sec-Fetch-Mode constraints."
    ),
    example_value="(positive coverage — no remediation needed)",
    reference_url=_REFERENCE_URL,
    compliance_mappings=[],
    cve_correlations=[_cwe("CWE-352", "Cross-Site Request Forgery (positive coverage)")],
)

_FM_INCONCLUSIVE_TEMPLATE = Finding(
    header="Sec-Fetch-Site",
    category=HeaderCategory.ISOLATION,
    severity=Severity.INFO,
    title="Fetch Metadata Probe Inconclusive",
    description=(
        "The Fetch Metadata enforcement probe produced an ambiguous result: "
        "{reason}. This may indicate CDN or reverse proxy header stripping, an "
        "authentication wall preventing probe differentiation, or a "
        "non-standard enforcement response. Manual verification is required."
    ),
    current_value=None,
    recommendation=(
        "Scan the origin directly (bypassing CDN) to confirm or rule out "
        "enforcement. Check application middleware for Fetch Metadata policy "
        "implementation."
    ),
    example_value="N/A",
    reference_url=_REFERENCE_URL,
    compliance_mappings=[],
    cve_correlations=[],
)


ALL_FM_FINDINGS: dict[str, Finding] = {
    "FM_NO_FETCH_METADATA_POLICY": _FM_NO_POLICY_TEMPLATE,
    "FM_FETCH_METADATA_ENFORCED": _FM_ENFORCED_TEMPLATE,
    "FM_FETCH_METADATA_INCONCLUSIVE": _FM_INCONCLUSIVE_TEMPLATE,
}


def get_finding(finding_id: str) -> Optional[Finding]:
    """Return a deep copy of a finding template, or None if unknown."""
    template = ALL_FM_FINDINGS.get(finding_id)
    if template is None:
        return None
    return copy.deepcopy(template)


# ----------------------------------------------------------------------------
# Severity calibration
# ----------------------------------------------------------------------------

@dataclass(frozen=True)
class FMContext:
    has_samesite_strict: bool
    has_samesite_lax: bool
    has_csrf_token: bool
    cdn_detected: bool


def _calibrate_severity(ctx: FMContext) -> Severity:
    """Apply spec §5.1 matrix. SameSite=Strict + CSRF token → LOW.
    Partial mitigations (Lax XOR token) → MEDIUM (or LOW with CDN downgrade).
    No mitigations → HIGH (or MEDIUM with CDN downgrade).
    """
    full_mitigations = ctx.has_samesite_strict and ctx.has_csrf_token
    partial_mitigations = (
        ctx.has_samesite_lax or ctx.has_csrf_token
    ) and not full_mitigations
    no_mitigations = not (full_mitigations or partial_mitigations)

    if full_mitigations:
        return Severity.LOW

    if partial_mitigations:
        return Severity.LOW if ctx.cdn_detected else Severity.MEDIUM

    # no_mitigations
    return Severity.MEDIUM if ctx.cdn_detected else Severity.HIGH


def _build_mitigation_note(ctx: FMContext) -> str:
    full_mitigations = ctx.has_samesite_strict and ctx.has_csrf_token
    partial_mitigations = (
        ctx.has_samesite_lax or ctx.has_csrf_token
    ) and not full_mitigations

    if full_mitigations:
        note = (
            "SameSite=Strict cookies and a CSRF token were detected. Fetch "
            "Metadata enforcement would add a third independent layer."
        )
    elif partial_mitigations:
        signals = []
        if ctx.has_samesite_lax:
            signals.append("SameSite=Lax")
        if ctx.has_csrf_token:
            signals.append("CSRF token")
        note = (
            "Partial CSRF mitigations detected: "
            + " and ".join(signals)
            + ". Adding Fetch Metadata enforcement would strengthen "
            "defense-in-depth."
        )
    else:
        note = (
            "No CSRF token cookie or SameSite=Strict cookie was detected on "
            "this endpoint."
        )

    if ctx.cdn_detected:
        note += _CDN_WARNING

    return note


def build_not_enforced_finding(ctx: FMContext, soft: bool) -> Finding:
    """Construct an FM_NO_FETCH_METADATA_POLICY finding calibrated to context.

    `soft=True` collapses severity to INFO (SOFT_ENFORCED case).
    """
    f = get_finding("FM_NO_FETCH_METADATA_POLICY")
    assert f is not None  # template is registered.

    if soft:
        f.severity = Severity.INFO
        soft_prefix = (
            "Soft enforcement detected — server returned modified content "
            "rather than 4xx; verify the policy actively blocks unauthorized "
            "cross-site access. "
        )
        f.description = soft_prefix + f.description.replace(
            "{mitigation_note}", _build_mitigation_note(ctx)
        )
        f.compliance_mappings = []
        return f

    severity = _calibrate_severity(ctx)
    f.severity = severity
    f.description = f.description.replace(
        "{mitigation_note}", _build_mitigation_note(ctx)
    )

    # Compliance mappings vary by severity per spec §5.1.
    mappings: list[ComplianceMapping] = [_OWASP_A01]
    if severity == Severity.HIGH:
        mappings.extend([_PCI_6_2_4, _NIST_SC_23])
    elif severity == Severity.MEDIUM:
        mappings.append(_NIST_SC_23)
    f.compliance_mappings = mappings

    return f


def build_inconclusive_finding(reason: str) -> Finding:
    """Construct an FM_FETCH_METADATA_INCONCLUSIVE finding with the given reason."""
    f = get_finding("FM_FETCH_METADATA_INCONCLUSIVE")
    assert f is not None
    f.description = f.description.replace("{reason}", reason)
    return f


def build_enforced_finding() -> Finding:
    """Construct an FM_FETCH_METADATA_ENFORCED PASS finding."""
    f = get_finding("FM_FETCH_METADATA_ENFORCED")
    assert f is not None
    return f
```

### Step 2.3 — Run tests until green

- [ ] **Step 2.3.1: Run the findings tests**

Run: `python3 -m pytest tests/test_fetch_metadata_findings.py -q`

Expected: ~17 tests pass, 0 failures.

If a test fails, fix the implementation (do **not** weaken the test). Re-run.

### Step 2.4 — Commit

- [ ] **Step 2.4.1: Stage and commit Task 2**

```bash
git add corsair/fetch_metadata/findings.py tests/test_fetch_metadata_findings.py
git commit -m "$(cat <<'EOF'
feat(fm): finding templates and severity calibration

Three Finding templates registered in ALL_FM_FINDINGS with the
get_finding() deepcopy pattern. build_not_enforced_finding() applies
the §5.1 severity matrix (cookie SameSite × CSRF token × CDN
fingerprint) with corresponding compliance-mapping calibration.
SOFT_ENFORCED collapses to INFO. ~17 tests cover the matrix exhaustively.

Spec: docs/superpowers/specs/2026-04-26-fetch-metadata-probing-design.md
EOF
)"
```

---

## Task 3: `FetchMetadataAuditor` orchestrator

**Goal:** Sync `audit()` over async internals — gather four probes concurrently, infer context from baseline cookies + CDN fingerprint, classify, emit findings. Mocked-`httpx.AsyncClient` integration tests cover all four `EnforcementResult` branches.

**Files:**
- Modify: `corsair/fetch_metadata/__init__.py` (add `FetchMetadataAuditor` re-export)
- Create: `corsair/fetch_metadata/auditor.py`
- Create: `tests/test_fetch_metadata_auditor.py`

### Step 3.1 — Write the failing tests

- [ ] **Step 3.1.1: Create `tests/test_fetch_metadata_auditor.py`**

```python
"""Integration tests for FetchMetadataAuditor with mocked httpx.AsyncClient."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from corsair.fetch_metadata import FetchMetadataAuditor
from corsair.models import Severity


def _mock_response(status_code=200, headers=None, body=b"baseline body"):
    response = MagicMock()
    response.status_code = status_code
    response.headers = headers or {}
    response.content = body
    return response


def _audit_with_responses(url, baseline_headers, response_sequence):
    """response_sequence: list of (status, headers_dict, body_bytes) tuples
    delivered in the order probes are issued (B, S, A, C — order-independent
    because the auditor classifies on the labelled result, but the mock simply
    returns whatever AsyncMock yields next)."""
    auditor = FetchMetadataAuditor(active=True)
    responses = [_mock_response(s, h, b) for (s, h, b) in response_sequence]
    call_log = {"n": 0}

    async def fake_get(*args, **kwargs):
        n = call_log["n"]
        call_log["n"] = n + 1
        return responses[n]

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=fake_get)
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client_cls.return_value = mock_client
        return auditor.audit(url, baseline_headers)


class TestEnforcedEmitsPassFinding:
    def test_strict_4xx_emits_pass(self):
        # B=200, S=200, A=403, C=403 → ENFORCED.
        findings = _audit_with_responses(
            "https://api.example.com/v1",
            baseline_headers={},
            response_sequence=[
                (200, {}, b"baseline"),
                (200, {}, b"safe"),
                (403, {}, b"forbidden"),
                (403, {}, b"forbidden"),
            ],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS
        assert "Enforced" in findings[0].title or "enforced" in findings[0].title.lower()


class TestNotEnforcedNoCdnHigh:
    def test_no_cookies_no_cdn_high_severity(self):
        # All probes 200, no Set-Cookie, no CDN headers → HIGH.
        findings = _audit_with_responses(
            "https://api.example.com/v1",
            baseline_headers={},
            response_sequence=[
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
            ],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


class TestNotEnforcedWithCdnDowngrades:
    def test_cloudflare_downgrades_to_medium(self):
        # All probes 200, baseline CF headers → MEDIUM.
        findings = _audit_with_responses(
            "https://api.example.com/v1",
            baseline_headers={"cf-ray": "abc-123", "cf-cache-status": "DYNAMIC"},
            response_sequence=[
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
            ],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM


class TestInconclusiveWhenSafeRejects:
    def test_safe_rejected_emits_info(self):
        findings = _audit_with_responses(
            "https://api.example.com/v1",
            baseline_headers={},
            response_sequence=[
                (200, {}, b"baseline"),
                (403, {}, b"forbidden-by-blanket-rule"),
                (403, {}, b"forbidden"),
                (403, {}, b"forbidden"),
            ],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "Inconclusive" in findings[0].title


class TestSeverityMatrixViaCookies:
    def test_strict_session_and_csrf_token_low(self):
        baseline_headers = {
            "set-cookie": "sessionid=abc; SameSite=Strict; Secure; HttpOnly",
        }
        # Two cookies require two Set-Cookie headers via httpx multi-value.
        # Simulate that by stuffing both into a single header value separated
        # by the standard delimiter that the auditor must split on.
        findings = _audit_with_responses(
            "https://api.example.com/v1",
            baseline_headers={
                "set-cookie": "sessionid=abc; SameSite=Strict; Secure; HttpOnly, csrftoken=xyz; Secure",
            },
            response_sequence=[
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
            ],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_lax_session_only_medium(self):
        findings = _audit_with_responses(
            "https://api.example.com/v1",
            baseline_headers={
                "set-cookie": "sessionid=abc; SameSite=Lax; Secure; HttpOnly",
            },
            response_sequence=[
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
            ],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM


class TestDisabledWhenActiveFalse:
    def test_active_false_returns_empty(self):
        auditor = FetchMetadataAuditor(active=False)
        result = auditor.audit("https://api.example.com/v1", {})
        assert result == []


class TestNetworkErrorEmitsInconclusive:
    def test_httpx_request_error_emits_inconclusive(self):
        import httpx

        auditor = FetchMetadataAuditor(active=True)

        async def fake_get(*args, **kwargs):
            raise httpx.RequestError("simulated network failure")

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=fake_get)
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_cls.return_value = mock_client

            findings = auditor.audit("https://api.example.com/v1", {})
            assert len(findings) == 1
            assert findings[0].severity == Severity.INFO
            assert "Network error" in findings[0].description or "network" in findings[0].description.lower()
```

- [ ] **Step 3.1.2: Run the auditor tests**

Run: `python3 -m pytest tests/test_fetch_metadata_auditor.py -q`

Expected: `ImportError: cannot import name 'FetchMetadataAuditor' from 'corsair.fetch_metadata'`.

### Step 3.2 — Implement `corsair/fetch_metadata/auditor.py`

- [ ] **Step 3.2.1: Create `corsair/fetch_metadata/auditor.py`**

```python
"""FetchMetadataAuditor — orchestrates the four-probe canary-extended sequence.

Sync entry point `audit()` runs `_audit_async()` via `asyncio.run`. Mirrors
the established pattern in corsair.cors.auditor and corsair.cache.auditor.
"""

import asyncio
import logging
from typing import List, Mapping

import httpx

from ..cache.oracle import fingerprint_cdn
from ..models import Finding
from .findings import (
    FMContext,
    build_enforced_finding,
    build_inconclusive_finding,
    build_not_enforced_finding,
)
from .probe import (
    ADVERSARIAL_PROBE_HEADERS,
    CANARY_PROBE_HEADERS,
    EnforcementResult,
    SAFE_PROBE_HEADERS,
    _body_hash,
    classify_enforcement,
)

logger = logging.getLogger(__name__)


_CSRF_COOKIE_NAMES = frozenset({
    "csrftoken",
    "xsrf-token",
    "_csrf",
    "__requestverificationtoken",
    "csrf",
})

_SESSION_COOKIE_NAMES = ("session", "sessionid", "sid", "auth", "token", "jwt")


class FetchMetadataAuditor:
    def __init__(self, timeout: float = 10.0, active: bool = True):
        self.timeout = timeout
        self.active = active

    def audit(self, url: str, baseline_headers: Mapping[str, str]) -> List[Finding]:
        if not self.active:
            return []
        try:
            return asyncio.run(self._audit_async(url, baseline_headers))
        except Exception as e:
            logger.error(f"FetchMetadata audit failed for {url}: {e}")
            return []

    async def _audit_async(
        self, url: str, baseline_headers: Mapping[str, str]
    ) -> List[Finding]:
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            verify=True,
        ) as client:
            try:
                baseline_resp, safe_resp, adv_resp, canary_resp = await asyncio.gather(
                    client.get(url),
                    client.get(url, headers=dict(SAFE_PROBE_HEADERS)),
                    client.get(url, headers=dict(ADVERSARIAL_PROBE_HEADERS)),
                    client.get(url, headers=dict(CANARY_PROBE_HEADERS)),
                )
            except httpx.RequestError as e:
                logger.warning(f"FM probe network error on {url}: {e}")
                return [build_inconclusive_finding("Network error during probe sequence")]

        baseline_body = _body_hash(baseline_resp.content)
        adversarial_body = _body_hash(adv_resp.content)

        result = classify_enforcement(
            baseline_status=baseline_resp.status_code,
            safe_status=safe_resp.status_code,
            adversarial_status=adv_resp.status_code,
            canary_status=canary_resp.status_code,
            baseline_body_hash=baseline_body,
            adversarial_body_hash=adversarial_body,
        )

        ctx = self._infer_context(baseline_headers)

        if result == EnforcementResult.ENFORCED:
            return [build_enforced_finding()]

        if result == EnforcementResult.SOFT_ENFORCED:
            return [build_not_enforced_finding(ctx, soft=True)]

        if result == EnforcementResult.NOT_ENFORCED:
            return [build_not_enforced_finding(ctx, soft=False)]

        # INCONCLUSIVE
        reason = self._inconclusive_reason(
            baseline_resp.status_code,
            safe_resp.status_code,
            adv_resp.status_code,
        )
        return [build_inconclusive_finding(reason)]

    @staticmethod
    def _infer_context(headers: Mapping[str, str]) -> FMContext:
        cdn = fingerprint_cdn(dict(headers))
        cookies = _iter_set_cookies(headers)

        has_strict = any(
            _is_session_cookie(c) and "samesite=strict" in c.lower() for c in cookies
        )
        has_lax = any(
            _is_session_cookie(c) and "samesite=lax" in c.lower() for c in cookies
        )
        has_csrf = any(_is_csrf_cookie(c) for c in cookies)

        return FMContext(
            has_samesite_strict=has_strict,
            has_samesite_lax=has_lax,
            has_csrf_token=has_csrf,
            cdn_detected=cdn is not None,
        )

    @staticmethod
    def _inconclusive_reason(baseline_status: int, safe_status: int, adv_status: int) -> str:
        if safe_status in {400, 403, 405, 451}:
            return "Safe-probe rejected — server appears to blanket-reject Sec-Fetch headers"
        if baseline_status >= 500 or baseline_status == 401:
            return f"Baseline target returned {baseline_status} — cannot probe meaningfully"
        if adv_status in {301, 302, 303, 307, 308}:
            return f"Adversarial probe redirected ({adv_status}); likely auth, not enforcement"
        return f"Unclassified probe pattern (baseline={baseline_status}, adversarial={adv_status})"


def _iter_set_cookies(headers: Mapping[str, str]) -> list[str]:
    """Extract individual Set-Cookie strings from a header mapping.

    Comma-splits a single Set-Cookie value containing multiple cookies (the
    httpx response.headers may collapse duplicates). The split is naive but
    sufficient for SameSite / cookie-name detection.
    """
    cookies: list[str] = []
    for key, value in headers.items():
        if key.lower() != "set-cookie":
            continue
        # Cookie attributes contain commas only inside `Expires=...` dates,
        # but those use `, ` after the day name. We split on `, ` (comma+space)
        # only when the next chunk starts with a token=value pattern.
        parts = _split_multicookie(value)
        cookies.extend(parts)
    return cookies


def _split_multicookie(raw: str) -> list[str]:
    """Split a comma-joined multi-cookie Set-Cookie value into individual cookies.
    Robust against `Expires=Wed, 09 Jun 2027 ...` by requiring `, name=` shape."""
    out: list[str] = []
    buf: list[str] = []
    pending = raw
    while pending:
        idx = pending.find(", ")
        if idx == -1:
            buf.append(pending)
            break
        head, tail = pending[:idx], pending[idx + 2 :]
        # If the tail begins with a `name=value` pattern (not `09 Jun 2027`),
        # this is a cookie boundary.
        eq = tail.find("=")
        sp = tail.find(" ")
        if eq != -1 and (sp == -1 or eq < sp):
            buf.append(head)
            out.append("".join(buf).strip())
            buf = []
            pending = tail
        else:
            buf.append(head + ", ")
            pending = tail
    if buf:
        out.append("".join(buf).strip())
    return [c for c in out if c]


def _is_session_cookie(cookie: str) -> bool:
    name = cookie.split("=", 1)[0].strip().lower()
    return any(s in name for s in _SESSION_COOKIE_NAMES)


def _is_csrf_cookie(cookie: str) -> bool:
    name = cookie.split("=", 1)[0].strip().lower()
    return name in _CSRF_COOKIE_NAMES
```

- [ ] **Step 3.2.2: Update `corsair/fetch_metadata/__init__.py` to re-export the auditor**

Replace the placeholder content with:

```python
"""Fetch Metadata enforcement probing module (v0.5.3)."""

from .auditor import FetchMetadataAuditor

__all__ = ["FetchMetadataAuditor"]
```

### Step 3.3 — Run tests until green

- [ ] **Step 3.3.1: Run the auditor tests**

Run: `python3 -m pytest tests/test_fetch_metadata_auditor.py -q`

Expected: 8 tests pass, 0 failures.

If a test fails, debug — common causes:
- `_split_multicookie` not splitting correctly. Test with `python3 -c "from corsair.fetch_metadata.auditor import _split_multicookie; print(_split_multicookie('a=1; SameSite=Strict, b=2; SameSite=Lax'))"`.
- `asyncio.run` re-entry issue (none expected — auditor is the only `asyncio.run` caller in this code path).

- [ ] **Step 3.3.2: Run the full FM test suite**

Run: `python3 -m pytest tests/test_fetch_metadata_probe.py tests/test_fetch_metadata_findings.py tests/test_fetch_metadata_auditor.py -q`

Expected: ~47 tests pass.

### Step 3.4 — Commit

- [ ] **Step 3.4.1: Stage and commit Task 3**

```bash
git add corsair/fetch_metadata/__init__.py corsair/fetch_metadata/auditor.py tests/test_fetch_metadata_auditor.py
git commit -m "$(cat <<'EOF'
feat(fm): FetchMetadataAuditor orchestrator

Async four-probe gather (B/S/A/C) over a single httpx.AsyncClient with
follow_redirects=False (so adversarial 302s are visible to the
classifier). Context inference from baseline Set-Cookie + CDN
fingerprint; routing to the correct finding factory per
EnforcementResult. Network errors collapse to an INCONCLUSIVE finding.
8 mocked-httpx integration tests cover all four result branches plus
disabled mode.

Spec: docs/superpowers/specs/2026-04-26-fetch-metadata-probing-design.md
EOF
)"
```

---

## Task 4: CLI flag + scanner wiring + scanner-integration verification

**Goal:** Default-on `--fm-probe / --no-fm-probe` flag plumbed through `HeadScanner.__init__` to the `FetchMetadataAuditor` invocation. Existing scanner tests must continue to pass.

**Files:**
- Modify: `corsair/cli.py` (add Click option + scanner kwarg)
- Modify: `corsair/scanner.py` (add `__init__` kwarg + auditor block after CORS)

### Step 4.1 — Modify `corsair/cli.py` — add Click option

- [ ] **Step 4.1.1: Add `--fm-probe/--no-fm-probe` option after the `--cors-probe` line**

In `corsair/cli.py` at line 173 (after the `--cors-probe` Click decorator), add a new decorator:

```python
@click.option("--fm-probe/--no-fm-probe", default=True, help="Run Fetch Metadata enforcement probing")
```

The block from line 172 onward should read:

```python
@click.option("--cache-probe/--no-cache-probe", default=True, help="Run cache poisoning detection")
@click.option("--cors-probe/--no-cors-probe", default=True, help="Run CORS DAST probing")
@click.option("--fm-probe/--no-fm-probe", default=True, help="Run Fetch Metadata enforcement probing")
@click.option(
    "--cors-evil-origin",
    default="https://evil.example",
    help="Origin value used to probe for arbitrary-origin reflection",
)
def scan(
    targets: tuple,
    file: Optional[str],
    output: str,
    out_file: Optional[str],
    timeout: int,
    follow_redirects: bool,
    max_redirects: int,
    quiet: bool,
    verbose: bool,
    no_color: bool,
    no_banner: bool,
    user_agent: str,
    min_score: int,
    save_history: bool,
    fingerprint: bool,
    correlate_cve: bool,
    cache_probe: bool,
    cors_probe: bool,
    fm_probe: bool,
    cors_evil_origin: str,
) -> None:
```

(The new `fm_probe: bool` parameter goes between `cors_probe` and `cors_evil_origin` to mirror the decorator order.)

- [ ] **Step 4.1.2: Pass `fm_probe` to `HeadScanner` constructor**

The `HeadScanner(...)` instantiation at lines 234–242 of `corsair/cli.py` currently reads:

```python
scanner = HeadScanner(
    timeout=timeout,
    follow_redirects=follow_redirects,
    max_redirects=max_redirects,
    user_agent=user_agent,
    cache_probe=cache_probe,
    cors_probe=cors_probe,
    cors_evil_origin=cors_evil_origin,
)
```

Replace with:

```python
scanner = HeadScanner(
    timeout=timeout,
    follow_redirects=follow_redirects,
    max_redirects=max_redirects,
    user_agent=user_agent,
    cache_probe=cache_probe,
    cors_probe=cors_probe,
    cors_evil_origin=cors_evil_origin,
    fm_probe=fm_probe,
)
```

### Step 4.2 — Modify `corsair/scanner.py`

- [ ] **Step 4.2.1: Import `FetchMetadataAuditor`**

Add this import line after the existing `from .cors.auditor import CORSAuditor` line (around line 19):

```python
from .fetch_metadata import FetchMetadataAuditor
```

- [ ] **Step 4.2.2: Add `fm_probe` parameter to `HeadScanner.__init__`**

The current signature at `corsair/scanner.py:27-36`:

```python
def __init__(
    self,
    timeout: int = 10,
    follow_redirects: bool = True,
    max_redirects: int = 5,
    user_agent: str = "HeadScan/1.0 (Security Header Analyzer)",
    cache_probe: bool = True,
    cors_probe: bool = True,
    cors_evil_origin: str = "https://evil.example",
):
```

Becomes:

```python
def __init__(
    self,
    timeout: int = 10,
    follow_redirects: bool = True,
    max_redirects: int = 5,
    user_agent: str = "HeadScan/1.0 (Security Header Analyzer)",
    cache_probe: bool = True,
    cors_probe: bool = True,
    cors_evil_origin: str = "https://evil.example",
    fm_probe: bool = True,
):
```

And add the storage line — just after `self.cors_evil_origin = cors_evil_origin` at line 55:

```python
        self.fm_probe = fm_probe
```

- [ ] **Step 4.2.3: Add the FM auditor block after the CORS auditor block**

Currently `scanner.py` ends the CORS block at line 196 (`logger.error(f"CORS audit failed: {e}")`) and immediately moves to `# Calculate score` at line 198.

Insert this new block between lines 196 and 198 (i.e. after the CORS try/except, before `# Calculate score`):

```python

        # Fetch Metadata enforcement probe (v0.5.3)
        if self.fm_probe:
            try:
                fm_auditor = FetchMetadataAuditor(timeout=self.timeout, active=True)
                fm_findings = fm_auditor.audit(final_url, headers)
                findings.extend(fm_findings)
            except Exception as e:
                logger.error(f"Fetch Metadata audit failed: {e}")
```

### Step 4.3 — Verify scanner integration tests still pass

- [ ] **Step 4.3.1: Run the existing scanner-integration suite**

Run: `python3 -m pytest tests/ --ignore=tests/test_tls_auditor.py -q -k "scanner or scan_target or scan_report"`

Expected: all existing scanner tests pass. If a test fails because the auditor emits an unexpected finding for a mocked target (e.g. a NOT_ENFORCED finding bumps a finding count or changes the grade), the fix is to set `fm_probe=False` on the test's `HeadScanner` fixture (do **not** weaken the assertion — the existing tests pin specific finding lists / scores that pre-date FM probing).

**Mechanical fix recipe** for any failing test that constructs `HeadScanner(...)`:

```python
# Before:
scanner = HeadScanner(timeout=5)
# After:
scanner = HeadScanner(timeout=5, fm_probe=False)
```

Re-run the failing test until green. Repeat for each affected test.

- [ ] **Step 4.3.2: Run the full suite**

Run: `python3 -m pytest tests/ --ignore=tests/test_tls_auditor.py -q`

Expected: ≥360 passing (was 320 before this branch; +47 new FM tests; if any pre-existing scanner test needed the `fm_probe=False` fixture-side fix, it remains in the count).

### Step 4.4 — Smoke-test the CLI flag

- [ ] **Step 4.4.1: Confirm `--help` shows the new flag**

Run: `python3 -m corsair scan --help | grep -A1 fm-probe`

Expected: a line like `--fm-probe / --no-fm-probe   Run Fetch Metadata enforcement probing`.

### Step 4.5 — Commit

- [ ] **Step 4.5.1: Stage and commit Task 4**

```bash
git add corsair/cli.py corsair/scanner.py
# Plus any test files modified to opt out via fm_probe=False:
# git add tests/<modified_files>
git commit -m "$(cat <<'EOF'
feat(fm): wire FetchMetadataAuditor into scanner with --fm-probe flag

HeadScanner gains fm_probe: bool = True. The CLI exposes it as
--fm-probe / --no-fm-probe (default on). The auditor runs after the
CORS auditor block, before score calculation. Test fixtures that pin
specific finding lists opt out via fm_probe=False rather than absorbing
new findings into their assertions.

Spec: docs/superpowers/specs/2026-04-26-fetch-metadata-probing-design.md
EOF
)"
```

---

## Task 5: v0.5.3 release

**Goal:** Bump version, write README changelog entry, commit as the release artifact.

**Files:**
- Modify: `corsair/__init__.py`
- Modify: `pyproject.toml`
- Modify: `README.md`

### Step 5.1 — Bump `corsair/__init__.py`

- [ ] **Step 5.1.1: Replace the version line**

In `corsair/__init__.py` line 27, change:

```python
__version__ = "0.5.2"
```

to:

```python
__version__ = "0.5.3"
```

### Step 5.2 — Bump `pyproject.toml`

- [ ] **Step 5.2.1: Replace the version line**

In `pyproject.toml` line 7, change:

```toml
version = "0.5.2"
```

to:

```toml
version = "0.5.3"
```

### Step 5.3 — Insert v0.5.3 changelog entry

- [ ] **Step 5.3.1: Insert a new section above v0.5.2 in `README.md`**

In `README.md`, find the line `### v0.5.2 — Alt-Svc Hardening (2026-04-25)` (currently line 159). Insert the following block immediately above it (preserving the blank line that separates from `## Changelog`):

```markdown
### v0.5.3 — Fetch Metadata Probing (2026-04-26)

**New DAST module:** `corsair/fetch_metadata/` — actively probes whether a server enforces a Fetch Metadata resource isolation policy. Four concurrent canary-extended HTTP probes (Baseline, Safe, Adversarial, Canary) on the target URL feed a pure `classify_enforcement()` function that returns `ENFORCED`, `SOFT_ENFORCED`, `NOT_ENFORCED`, or `INCONCLUSIVE`.

**Three new findings:**
- `FM_NO_FETCH_METADATA_POLICY` (HIGH / MEDIUM / LOW depending on cookie SameSite × CSRF token × CDN fingerprint) — server does not block browser-initiated cross-site requests at the FM layer.
- `FM_FETCH_METADATA_ENFORCED` (PASS) — positive coverage marker when the server rejects the cross-site probe.
- `FM_FETCH_METADATA_INCONCLUSIVE` (INFO) — ambiguous probe result (network error, blanket Sec-Fetch rejection, auth redirect).

**Severity calibration:**
- `SameSite=Strict` session cookie + CSRF token cookie → LOW.
- Partial mitigations (Lax XOR token) → MEDIUM (LOW with CDN downgrade).
- No mitigations → HIGH (MEDIUM with CDN downgrade).
- `SOFT_ENFORCED` (server returns modified body for cross-site) → INFO.

**False-positive defenses:**
- Canary probe (`Sec-Fetch-Site: corsair-canary-invalid`) discriminates spec-strict enforcement from allowlist enforcement and from proxy stripping.
- CDN-fingerprint severity downgrade for Cloudflare / Fastly / Akamai / Varnish / Nginx / CloudFront / generic.

**CLI:** `--fm-probe / --no-fm-probe` (default on). Plumbed through `HeadScanner(fm_probe=True)`.

**No new dependencies.** Reuses `httpx` and `corsair.cache.oracle.fingerprint_cdn`.

**Spec:** `docs/superpowers/specs/2026-04-26-fetch-metadata-probing-design.md`

```

(The trailing blank line preserves the gap before the existing `### v0.5.2` heading.)

### Step 5.4 — Verify version-bump consistency

- [ ] **Step 5.4.1: Confirm `__version__` matches `pyproject.toml`**

Run: `python3 -c "import corsair; print(corsair.__version__)"`

Expected output: `0.5.3`

Run: `python3 -c "import tomllib; print(tomllib.loads(open('pyproject.toml','rb').read().decode())['project']['version'])"`

(On Python 3.10 or earlier, replace `tomllib` with `tomli`. If neither is available, fall back to `grep '^version' pyproject.toml`.)

Expected output: `0.5.3`

### Step 5.5 — Final regression run

- [ ] **Step 5.5.1: Run full suite**

Run: `python3 -m pytest tests/ --ignore=tests/test_tls_auditor.py -q`

Expected: ≥360 passing, 0 failures.

### Step 5.6 — Release commit

- [ ] **Step 5.6.1: Stage and commit the release**

```bash
git add corsair/__init__.py pyproject.toml README.md
git commit -m "$(cat <<'EOF'
release: v0.5.3 — Fetch Metadata Enforcement Probing

Ships the new corsair/fetch_metadata/ DAST module with three findings
(FM_NO_FETCH_METADATA_POLICY, FM_FETCH_METADATA_ENFORCED,
FM_FETCH_METADATA_INCONCLUSIVE), four-probe canary-extended
classification, and CDN-fingerprint severity downgrade. CLI flag
--fm-probe / --no-fm-probe defaults on.

No new dependencies. ~47 new tests; full suite ≥360 passing.

Spec: docs/superpowers/specs/2026-04-26-fetch-metadata-probing-design.md
EOF
)"
```

---

## Summary

| Task | Lines added (approx) | Tests added | Commit |
|---|---|---|---|
| 1 — Probe primitives | ~120 (probe) + ~220 (test) | ~22 | `feat(fm): probe primitives and classify_enforcement` |
| 2 — Findings | ~280 (findings) + ~180 (test) | ~17 | `feat(fm): finding templates and severity calibration` |
| 3 — Auditor | ~180 (auditor) + ~180 (test) | ~8 | `feat(fm): FetchMetadataAuditor orchestrator` |
| 4 — Wiring | ~15 (cli + scanner) | (regression) | `feat(fm): wire FetchMetadataAuditor into scanner with --fm-probe flag` |
| 5 — Release | ~30 (README + version bumps) | (none) | `release: v0.5.3 — Fetch Metadata Enforcement Probing` |

Total: 5 commits, ~47 new tests, 0 new dependencies.
