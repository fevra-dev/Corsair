# CORS DAST Wave 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Wave 1 of the CORS DAST module (Core 5 findings — arbitrary-origin reflection ±creds, null-origin ±creds, wildcard+creds) as Corsair v0.5.0, wired into `HeadScanner.scan_target()` with a `--no-cors-probe` opt-out.

**Architecture:** New `corsair/cors/` package that mirrors `corsair/cache/`. Three-phase pipeline (passive headers → active reflection probes → preflight+cache-key) with `asyncio.Semaphore` + `asyncio.Event` abort pattern copied from the post-v0.4.1 `CacheAuditor`. Wave 1 implements the passive phase, the reflection phase, and the 5 most-impactful finding classes; Phase 3, bypass matrix, preflight, and state-changing probes are stubbed empty and ship in later waves. The legacy static `corsair/analyzers/cors.py` is migrated into `corsair/cors/passive.py` as a pure function; the `CORSAnalyzer` class becomes a thin adapter so existing analyzer-registry consumers keep working.

**Tech Stack:** Python 3.9+ (required by `pyproject.toml`), `httpx.AsyncClient`, `asyncio`, `click` (CLI). Tests: `pytest` with `asyncio_mode = "auto"`, `unittest.mock.AsyncMock/MagicMock` (matching existing cache test style — not `respx`). No new runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-04-19-cors-dast-design.md`
**Pattern to mirror:** `corsair/cache/` (auditor, oracle, probe, findings modules)

---

## File Structure

**Create:**
- `corsair/cors/__init__.py` — exports `CORSAuditor`
- `corsair/cors/passive.py` — migrated static header analyzer as pure function `analyze(headers, url) -> list[Finding]`
- `corsair/cors/probe.py` — `ProbeResult` dataclass, `build_origin_probe()`, `run_probe()` with semaphore-bounded httpx calls, `abort_event` plumbing
- `corsair/cors/analyzers.py` — `classify_reflection()`, `classify_sensitivity()` pure functions (Core 5 logic)
- `corsair/cors/auditor.py` — `CORSAuditor` orchestrator with `audit()` sync entry + `_audit_async()` + `_passive_checks()` + `_active_reflection_probes()` + stubs for `_preflight_probes()` and `_cache_key_probes()` (raise `NotImplementedError` / return `[]` for Wave 1)
- `corsair/cors/findings.py` — 5 Core + 2 meta = **7** `Finding` templates + `ALL_CORS_FINDINGS` dict + `get_finding(id)`
- `tests/test_cors_findings.py` — registry integrity
- `tests/test_cors_passive.py` — migrated tests for static analyzer
- `tests/test_cors_probe.py` — probe building + execution
- `tests/test_cors_analyzers.py` — `classify_reflection` + 4×2 sensitivity truth table
- `tests/test_cors_auditor_unit.py` — 3-phase orchestration, abort path, opt-out
- `tests/test_scanner_cors_integration.py` — `HeadScanner.scan_target()` CORS integration smoke

**Modify:**
- `corsair/__init__.py:27` — bump `__version__` to `"0.5.0"`
- `corsair/analyzers/cors.py` — replace with a 15-line adapter that calls `corsair.cors.passive.analyze`
- `corsair/scanner.py:18,26-52,115-197` — add `cors_probe`, `cors_evil_origin` scanner args; run `CORSAuditor` after `CacheAuditor`
- `corsair/cli.py:160-232` — add `--cors-probe/--no-cors-probe` and `--cors-evil-origin` flags, pass into `HeadScanner`
- `pyproject.toml` — bump version to `0.5.0`
- `README.md` — add v0.5.0 changelog section

**Delete:** nothing in Wave 1 (the old `corsair/analyzers/cors.py` is *rewritten* as an adapter, not removed, so the analyzer registry still imports it).

---

## Task 1: Worktree + package skeleton

**Files:**
- Create worktree: `.worktrees/cors-dast-wave1`
- Create: `corsair/cors/__init__.py`
- Create: `corsair/cors/passive.py` (empty stub)
- Create: `corsair/cors/probe.py` (empty stub)
- Create: `corsair/cors/analyzers.py` (empty stub)
- Create: `corsair/cors/auditor.py` (empty stub)
- Create: `corsair/cors/findings.py` (empty stub)
- Create: `tests/test_cors_smoke.py`

- [ ] **Step 1: Create isolated worktree from main**

```bash
cd /Users/fevra/apps/headscan
git worktree add .worktrees/cors-dast-wave1 -b feature/cors-dast-wave1 main
cd .worktrees/cors-dast-wave1
```

Expected: `HEAD is now at <sha> feat: TLS Auditor v0.2.0 — TLS/SSL configuration auditing` (or whatever is tip of main after v0.4.1 release).

- [ ] **Step 2: Verify baseline is green**

Run: `pytest -x -q`
Expected: all existing tests pass (~380+ collected). If anything fails, STOP and escalate — do not start on a red baseline.

- [ ] **Step 3: Write the failing smoke test**

Create `tests/test_cors_smoke.py`:

```python
"""Wave 1 smoke test: corsair.cors package is importable."""


def test_cors_package_imports():
    from corsair.cors import CORSAuditor

    assert CORSAuditor is not None


def test_cors_findings_module_imports():
    from corsair.cors import findings

    assert hasattr(findings, "ALL_CORS_FINDINGS")


def test_cors_submodules_exist():
    from corsair.cors import analyzers, auditor, passive, probe

    assert analyzers is not None
    assert auditor is not None
    assert passive is not None
    assert probe is not None
```

- [ ] **Step 4: Run the smoke test to verify it fails**

Run: `pytest tests/test_cors_smoke.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'corsair.cors'`.

- [ ] **Step 5: Create the package skeleton**

Create `corsair/cors/__init__.py`:

```python
"""
Corsair CORS DAST module.

Dynamic Application Security Testing for CORS misconfigurations.
Detects arbitrary-origin reflection, null-origin trust, wildcard+credentials,
and (in later waves) subdomain bypass, preflight divergence, and CDN
cache-key poisoning.

Safe by default: no state-changing probes, no credentialed probes,
no traffic to internal networks.
"""

from .auditor import CORSAuditor

__all__ = ["CORSAuditor"]
```

Create empty stubs in `corsair/cors/passive.py`, `probe.py`, `analyzers.py`, `findings.py`, and a minimal `auditor.py`:

```python
# corsair/cors/passive.py
"""Passive CORS header analysis (no network calls)."""
```

```python
# corsair/cors/probe.py
"""Active CORS reflection probing over httpx.AsyncClient."""
```

```python
# corsair/cors/analyzers.py
"""Response classification: reflection detection + sensitivity heuristic."""
```

```python
# corsair/cors/findings.py
"""CORS DAST finding definitions (Core 5 + meta)."""

ALL_CORS_FINDINGS: dict = {}
```

```python
# corsair/cors/auditor.py
"""CORSAuditor -- orchestrates CORS DAST for Corsair."""

from typing import List

from ..models import Finding


class CORSAuditor:
    def __init__(
        self,
        timeout: int = 10,
        max_concurrency: int = 5,
        active: bool = True,
        evil_origin: str = "https://evil.example",
    ):
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.active = active
        self.evil_origin = evil_origin

    def audit(self, url: str, headers: dict) -> List[Finding]:
        return []
```

- [ ] **Step 6: Run the smoke test to verify it passes**

Run: `pytest tests/test_cors_smoke.py -v`
Expected: PASS — 3/3 tests.

- [ ] **Step 7: Confirm nothing else regressed**

Run: `pytest -q`
Expected: all prior tests still pass, +3 new.

- [ ] **Step 8: Commit**

```bash
git add corsair/cors/ tests/test_cors_smoke.py
git commit -m "feat(cors): scaffold CORS DAST package skeleton

Empty CORSAuditor + submodule stubs, import smoke test in place.
Wave 1 Task 1/6."
```

---

## Task 2: Core 5 finding definitions

**Files:**
- Modify: `corsair/cors/findings.py`
- Create: `tests/test_cors_findings.py`

- [ ] **Step 1: Write the failing registry test**

Create `tests/test_cors_findings.py`:

```python
"""Test CORS DAST finding registry integrity (Wave 1)."""

from corsair.cors.findings import ALL_CORS_FINDINGS, get_finding
from corsair.models import HeaderCategory, Severity


class TestCORSFindingRegistry:
    def test_wave1_finding_count(self):
        # Wave 1 ships 5 Core findings + 2 meta = 7 total.
        assert len(ALL_CORS_FINDINGS) == 7

    def test_all_findings_use_cors_category(self):
        for fid, finding in ALL_CORS_FINDINGS.items():
            assert finding.category == HeaderCategory.CORS, (
                f"{fid} has category {finding.category}, expected CORS"
            )

    def test_all_findings_have_required_fields(self):
        for fid, finding in ALL_CORS_FINDINGS.items():
            assert finding.header, f"{fid} missing header"
            assert finding.title, f"{fid} missing title"
            assert finding.description, f"{fid} missing description"
            assert finding.recommendation, f"{fid} missing recommendation"
            assert finding.reference_url, f"{fid} missing reference_url"

    def test_all_findings_have_valid_severity(self):
        for fid, finding in ALL_CORS_FINDINGS.items():
            assert finding.severity in Severity, f"{fid} invalid severity"

    def test_core5_finding_ids_exist(self):
        core5 = [
            "CORS_ARBITRARY_ORIGIN_CRED",
            "CORS_ARBITRARY_ORIGIN",
            "CORS_NULL_ORIGIN_CRED",
            "CORS_NULL_ORIGIN",
            "CORS_WILDCARD_CRED",
        ]
        for fid in core5:
            assert fid in ALL_CORS_FINDINGS, f"Missing Core-5 finding: {fid}"

    def test_meta_findings_exist(self):
        for fid in ("CORS_PROBE_INCONCLUSIVE", "CORS_PHASE_TIMEOUT"):
            assert fid in ALL_CORS_FINDINGS, f"Missing meta finding: {fid}"

    def test_severity_mapping_matches_spec(self):
        # Spec §5 severity defaults (before signal-driven downgrade).
        assert ALL_CORS_FINDINGS["CORS_ARBITRARY_ORIGIN_CRED"].severity == Severity.CRITICAL
        assert ALL_CORS_FINDINGS["CORS_ARBITRARY_ORIGIN"].severity == Severity.HIGH
        assert ALL_CORS_FINDINGS["CORS_NULL_ORIGIN_CRED"].severity == Severity.HIGH
        assert ALL_CORS_FINDINGS["CORS_NULL_ORIGIN"].severity == Severity.MEDIUM
        assert ALL_CORS_FINDINGS["CORS_WILDCARD_CRED"].severity == Severity.MEDIUM
        assert ALL_CORS_FINDINGS["CORS_PROBE_INCONCLUSIVE"].severity == Severity.INFO
        assert ALL_CORS_FINDINGS["CORS_PHASE_TIMEOUT"].severity == Severity.INFO

    def test_get_finding_returns_copy(self):
        f1 = get_finding("CORS_WILDCARD_CRED")
        f2 = get_finding("CORS_WILDCARD_CRED")
        assert f1 is not f2
        assert f1.title == f2.title

    def test_get_finding_unknown_returns_none(self):
        assert get_finding("CORS_NONEXISTENT") is None

    def test_no_duplicate_ids(self):
        ids = list(ALL_CORS_FINDINGS.keys())
        assert len(ids) == len(set(ids))

    def test_all_ids_use_cors_prefix(self):
        for fid in ALL_CORS_FINDINGS:
            assert fid.startswith("CORS_"), f"{fid} missing CORS_ prefix"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cors_findings.py -v`
Expected: FAIL — `get_finding` import error and `len(ALL_CORS_FINDINGS) == 7` assertion fails.

- [ ] **Step 3: Write the findings module**

Replace `corsair/cors/findings.py` contents:

```python
"""
CORS DAST finding definitions (Wave 1).

Ships 5 Core finding classes covering the highest-impact CORS misconfigurations:
- Arbitrary-origin reflection (±credentials)
- Null-origin trust (±credentials)
- Wildcard ACAO + credentials

Plus 2 meta findings for inconclusive runs and phase timeouts.

Additional 11 findings (subdomain bypass, protocol downgrade, internal origin,
preflight divergence, cache-key divergence, framework default, third-party XSS,
broad methods/headers, post leak) ship in Waves 2-4.
"""

import copy
from typing import Optional

from ..models import (
    ComplianceMapping,
    CVECorrelation,
    Finding,
    HeaderCategory,
    Severity,
)


def _compliance(framework: str, req_id: str, req_name: str, status: str = "FAIL"):
    return ComplianceMapping(
        framework=framework,
        requirement_id=req_id,
        requirement_name=req_name,
        status=status,
    )


def _cwe(cwe_id: str, desc: str):
    return CVECorrelation(cve_id=cwe_id, cvss_score=0.0, description=desc)


_OWASP_A05 = _compliance("OWASP_TOP_10_2025", "A05", "Security Misconfiguration")
_OWASP_A01 = _compliance("OWASP_TOP_10_2025", "A01", "Broken Access Control")
_PCI_6_2 = _compliance("PCI_DSS_4_0", "6.2", "Secure Development")
_CWE_942 = _cwe("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains")
_CWE_346 = _cwe("CWE-346", "Origin Validation Error")

_MDN_URL = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
_PORTSWIGGER_URL = "https://portswigger.net/web-security/cors"


# -- Core 5 -----------------------------------------------------------------

_CORS_ARBITRARY_ORIGIN_CRED = Finding(
    header="Access-Control-Allow-Origin",
    category=HeaderCategory.CORS,
    severity=Severity.CRITICAL,
    title="Arbitrary origin reflected with credentials",
    description=(
        "The server reflected an attacker-controlled Origin value in "
        "Access-Control-Allow-Origin AND returned Access-Control-Allow-Credentials: "
        "true. Any website a victim visits can read authenticated responses from "
        "this endpoint, enabling account takeover and data theft. This is the "
        "highest-impact CORS misconfiguration."
    ),
    current_value=None,
    recommendation=(
        "Never reflect Origin blindly when ACAC: true. Maintain a strict allowlist "
        "of trusted origins and reject all others. If dynamic allowlisting is "
        "required, validate against a known-good list before echoing Origin."
    ),
    example_value="Access-Control-Allow-Origin: https://trusted.example.com",
    reference_url=_PORTSWIGGER_URL,
    compliance_mappings=[_OWASP_A01, _OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_346, _CWE_942],
)

_CORS_ARBITRARY_ORIGIN = Finding(
    header="Access-Control-Allow-Origin",
    category=HeaderCategory.CORS,
    severity=Severity.HIGH,
    title="Arbitrary origin reflected (no credentials)",
    description=(
        "The server reflected an attacker-controlled Origin value in "
        "Access-Control-Allow-Origin without Access-Control-Allow-Credentials. "
        "Attackers can read responses from this endpoint. Impact depends on what "
        "the endpoint returns under anonymous access — a public API echoing "
        "Origin is low-risk, but any endpoint leaking IP, tokens, or internal data "
        "to any origin is a material finding."
    ),
    current_value=None,
    recommendation=(
        "Reflect Origin only from a strict allowlist. If the endpoint truly needs "
        "any-origin access, use Access-Control-Allow-Origin: * instead of echoing."
    ),
    example_value="Access-Control-Allow-Origin: https://trusted.example.com",
    reference_url=_PORTSWIGGER_URL,
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_346],
)

_CORS_NULL_ORIGIN_CRED = Finding(
    header="Access-Control-Allow-Origin",
    category=HeaderCategory.CORS,
    severity=Severity.HIGH,
    title="Null origin trusted with credentials",
    description=(
        "The server accepts Origin: null AND returns ACAC: true. The null origin "
        "is sent by sandboxed iframes, data: URLs, and file: contexts — all of "
        "which can be attacker-controlled. This grants attackers credentialed "
        "cross-origin access through a sandboxed iframe."
    ),
    current_value=None,
    recommendation=(
        "Never allow Origin: null. Reject it explicitly in your CORS middleware."
    ),
    example_value="Access-Control-Allow-Origin: https://trusted.example.com",
    reference_url=_PORTSWIGGER_URL,
    compliance_mappings=[_OWASP_A01, _OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_346, _CWE_942],
)

_CORS_NULL_ORIGIN = Finding(
    header="Access-Control-Allow-Origin",
    category=HeaderCategory.CORS,
    severity=Severity.MEDIUM,
    title="Null origin trusted (no credentials)",
    description=(
        "The server accepts Origin: null without credentials. Attackers can read "
        "responses from sandboxed iframe contexts. Impact is limited to what the "
        "endpoint returns anonymously, but null should not be on any allowlist."
    ),
    current_value=None,
    recommendation="Reject Origin: null explicitly in CORS middleware.",
    example_value="Access-Control-Allow-Origin: https://trusted.example.com",
    reference_url=_PORTSWIGGER_URL,
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_346],
)

_CORS_WILDCARD_CRED = Finding(
    header="Access-Control-Allow-Origin",
    category=HeaderCategory.CORS,
    severity=Severity.MEDIUM,
    title="Wildcard Access-Control-Allow-Origin with credentials",
    description=(
        "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials "
        "is 'true'. Browsers reject this combination, so it is not directly "
        "exploitable — but the configuration reveals a security misunderstanding "
        "that likely applies to adjacent endpoints and warrants manual review."
    ),
    current_value=None,
    recommendation=(
        "Use a specific origin instead of wildcard when credentials are needed. "
        "Audit other endpoints on the same service for similar misconfiguration."
    ),
    example_value="Access-Control-Allow-Origin: https://trusted.example.com",
    reference_url=_MDN_URL,
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_346],
)


# -- Meta findings ----------------------------------------------------------

_CORS_PROBE_INCONCLUSIVE = Finding(
    header="Access-Control-Allow-Origin",
    category=HeaderCategory.CORS,
    severity=Severity.INFO,
    title="CORS probing inconclusive",
    description=(
        "Active CORS probing could not reach a verdict. The target returned 401, "
        "403, or 5xx on every probe, or the probes were skipped because the "
        "target is not HTTP-reachable. Manual testing is recommended if the "
        "endpoint is expected to support CORS."
    ),
    current_value=None,
    recommendation=(
        "Verify manually with an authenticated request if CORS behavior is "
        "expected. Otherwise no action required."
    ),
    example_value="N/A",
    reference_url=_PORTSWIGGER_URL,
)

_CORS_PHASE_TIMEOUT = Finding(
    header="Access-Control-Allow-Origin",
    category=HeaderCategory.CORS,
    severity=Severity.INFO,
    title="CORS probe phase timed out",
    description=(
        "A CORS probing phase exceeded the 60-second global timeout and was "
        "cancelled. Partial findings (if any) are still reported. Consider "
        "re-running with a longer --timeout or scanning a more responsive endpoint."
    ),
    current_value=None,
    recommendation="Re-scan with --timeout 30 if the target is known to be slow.",
    example_value="N/A",
    reference_url=_PORTSWIGGER_URL,
)


# -- Registry ---------------------------------------------------------------

ALL_CORS_FINDINGS: dict[str, Finding] = {
    "CORS_ARBITRARY_ORIGIN_CRED": _CORS_ARBITRARY_ORIGIN_CRED,
    "CORS_ARBITRARY_ORIGIN": _CORS_ARBITRARY_ORIGIN,
    "CORS_NULL_ORIGIN_CRED": _CORS_NULL_ORIGIN_CRED,
    "CORS_NULL_ORIGIN": _CORS_NULL_ORIGIN,
    "CORS_WILDCARD_CRED": _CORS_WILDCARD_CRED,
    "CORS_PROBE_INCONCLUSIVE": _CORS_PROBE_INCONCLUSIVE,
    "CORS_PHASE_TIMEOUT": _CORS_PHASE_TIMEOUT,
}


def get_finding(finding_id: str) -> Optional[Finding]:
    """Return a deep copy of a finding template, or None if unknown."""
    template = ALL_CORS_FINDINGS.get(finding_id)
    if template is None:
        return None
    return copy.deepcopy(template)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cors_findings.py -v`
Expected: PASS — 11 tests.

- [ ] **Step 5: Run full suite to confirm nothing regressed**

Run: `pytest -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add corsair/cors/findings.py tests/test_cors_findings.py
git commit -m "feat(cors): add Core 5 finding definitions + meta

CORS_ARBITRARY_ORIGIN_CRED/ORIGIN, CORS_NULL_ORIGIN_CRED/ORIGIN,
CORS_WILDCARD_CRED + CORS_PROBE_INCONCLUSIVE, CORS_PHASE_TIMEOUT.
Registry integrity test covers count, severity mapping, ID prefix.
Wave 1 Task 2/6."
```

---

## Task 3: Migrate `analyzers/cors.py` → `corsair/cors/passive.py`

**Goal:** Move the static CORS analyzer's logic into a pure function on the new module, preserve behavior exactly, and keep the old `CORSAnalyzer` class working as a thin adapter so `ALL_ANALYZERS` keeps importing it.

**Files:**
- Create: `corsair/cors/passive.py` (full implementation)
- Create: `tests/test_cors_passive.py`
- Modify: `corsair/analyzers/cors.py` (becomes a 15-line adapter)

- [ ] **Step 1: Write the failing passive test**

Create `tests/test_cors_passive.py`:

```python
"""Passive (header-only) CORS analysis tests.

These tests exercise corsair.cors.passive.analyze. They are the regression
gate for the migration from corsair/analyzers/cors.py: behavior must match
exactly so that the adapter in corsair/analyzers/cors.py keeps returning
the same findings for the same inputs.
"""

from corsair.cors.passive import analyze
from corsair.models import Severity


class TestPassiveCORS:
    def test_no_cors_headers_emits_pass(self):
        findings = analyze({}, "https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS
        assert "Same-Origin" in findings[0].title or "not configured" in findings[0].title.lower()

    def test_wildcard_no_creds_is_medium(self):
        findings = analyze(
            {"Access-Control-Allow-Origin": "*"},
            "https://example.com",
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "*" in findings[0].current_value

    def test_wildcard_with_creds_uses_wildcard_cred_finding(self):
        findings = analyze(
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
            "https://example.com",
        )
        assert len(findings) == 1
        # Migrated finding uses CORS_WILDCARD_CRED severity (MEDIUM per spec §5).
        assert findings[0].severity == Severity.MEDIUM
        assert "Wildcard" in findings[0].title

    def test_null_origin_is_high(self):
        findings = analyze(
            {"Access-Control-Allow-Origin": "null"},
            "https://example.com",
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "null" in findings[0].title.lower()

    def test_specific_origin_emits_pass(self):
        findings = analyze(
            {"Access-Control-Allow-Origin": "https://trusted.example.com"},
            "https://example.com",
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS

    def test_case_insensitive_header_lookup(self):
        findings = analyze(
            {"access-control-allow-origin": "*"},
            "https://example.com",
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM


class TestLegacyAdapter:
    """The old CORSAnalyzer class must still work for the analyzer registry."""

    def test_adapter_returns_same_findings(self):
        from corsair.analyzers.cors import CORSAnalyzer

        headers = {"Access-Control-Allow-Origin": "*"}
        analyzer = CORSAnalyzer(headers, "https://example.com")
        findings = analyzer.analyze()
        passive_findings = analyze(headers, "https://example.com")

        assert len(findings) == len(passive_findings)
        assert findings[0].severity == passive_findings[0].severity
        assert findings[0].title == passive_findings[0].title
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cors_passive.py -v`
Expected: FAIL — `analyze` is not defined.

- [ ] **Step 3: Write `corsair/cors/passive.py`**

Replace the empty stub with:

```python
"""
Passive CORS analysis — inspects response headers already collected by the
scanner. Never issues network requests.

This module is the migration target for the legacy corsair/analyzers/cors.py
static analyzer. The legacy CORSAnalyzer class is now a thin adapter that
delegates to analyze() here, so the analyzer registry keeps working unchanged.

Wave 1 scope: CORS_WILDCARD_CRED + wildcard-no-creds + null-origin + specific-
origin PASS + no-CORS PASS. CORS_FRAMEWORK_DEFAULT ships in Wave 4.
"""

import logging
from typing import Dict, List, Optional

from ..models import Finding, HeaderCategory, Severity
from .findings import get_finding

logger = logging.getLogger(__name__)

_MDN_URL = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"


def _lookup_header(headers: Dict[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup."""
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return None


def _make_pass_finding(current_value: str) -> Finding:
    return Finding(
        header="Access-Control-Allow-Origin",
        category=HeaderCategory.CORS,
        severity=Severity.PASS,
        title="CORS correctly configured",
        description=(
            f"Access-Control-Allow-Origin is set to a specific origin "
            f"({current_value}), which is the recommended configuration for "
            f"endpoints that need cross-origin access from a trusted domain."
        ),
        current_value=current_value,
        recommendation="No action required.",
        example_value=current_value,
        reference_url=_MDN_URL,
    )


def _make_no_cors_pass() -> Finding:
    return Finding(
        header="Access-Control-Allow-Origin",
        category=HeaderCategory.CORS,
        severity=Severity.PASS,
        title="CORS Not Configured (Same-Origin Policy)",
        description="No CORS headers are set. Same-origin policy is in effect.",
        current_value=None,
        recommendation="No action needed unless cross-origin access is required.",
        example_value="N/A",
        reference_url=_MDN_URL,
    )


def _make_wildcard_finding() -> Finding:
    return Finding(
        header="Access-Control-Allow-Origin",
        category=HeaderCategory.CORS,
        severity=Severity.MEDIUM,
        title="CORS Allows All Origins",
        description=(
            "Access-Control-Allow-Origin is set to '*', allowing any origin to "
            "access resources. This may be intentional for public APIs, but "
            "ensure no sensitive data is exposed."
        ),
        current_value="*",
        recommendation="If not a public API, restrict to specific origins.",
        example_value="Access-Control-Allow-Origin: https://trusted.example.com",
        reference_url=_MDN_URL,
    )


def _make_null_origin_finding() -> Finding:
    return Finding(
        header="Access-Control-Allow-Origin",
        category=HeaderCategory.CORS,
        severity=Severity.HIGH,
        title="CORS Allows Null Origin",
        description=(
            "Access-Control-Allow-Origin is set to 'null'. The null origin can "
            "be sent from sandboxed iframes and data: URLs, which can be "
            "controlled by attackers."
        ),
        current_value="null",
        recommendation="Never allow the null origin.",
        example_value="Access-Control-Allow-Origin: https://trusted.example.com",
        reference_url=_MDN_URL,
    )


def analyze(headers: Dict[str, str], url: str) -> List[Finding]:
    """
    Passive CORS header analysis.

    Args:
        headers: Response headers from the scan target (any casing).
        url: Target URL (used for logging only).

    Returns:
        List of Finding objects. Always returns at least one finding (PASS
        when no CORS headers present).
    """
    findings: List[Finding] = []

    acao = _lookup_header(headers, "Access-Control-Allow-Origin")
    acac = _lookup_header(headers, "Access-Control-Allow-Credentials")

    if not acao:
        logger.info("[CORS] No CORS headers (using same-origin policy)")
        findings.append(_make_no_cors_pass())
        return findings

    logger.info(f"[CORS] Access-Control-Allow-Origin: {acao}")

    acao_stripped = acao.strip()

    if acao_stripped == "*":
        if acac and acac.strip().lower() == "true":
            finding = get_finding("CORS_WILDCARD_CRED")
            if finding is not None:
                finding.current_value = f"ACAO: {acao}, ACAC: {acac}"
                findings.append(finding)
        else:
            findings.append(_make_wildcard_finding())
    elif acao_stripped.lower() == "null":
        findings.append(_make_null_origin_finding())
    else:
        findings.append(_make_pass_finding(acao))

    return findings
```

- [ ] **Step 4: Rewrite `corsair/analyzers/cors.py` as an adapter**

Replace the file contents with:

```python
"""
CORS headers analyzer (legacy adapter).

The real logic lives in corsair.cors.passive. This adapter preserves the
BaseAnalyzer contract so corsair.analyzers.ALL_ANALYZERS keeps working
unchanged — existing consumers of the analyzer registry see the same
findings they did before the migration.
"""

from typing import List

from ..cors.passive import analyze as passive_analyze
from ..models import Finding, HeaderCategory
from .base import BaseAnalyzer


class CORSAnalyzer(BaseAnalyzer):
    """Thin adapter around corsair.cors.passive.analyze."""

    HEADER_NAME = "Access-Control-Allow-Origin"
    CATEGORY = HeaderCategory.CORS

    def analyze(self) -> List[Finding]:
        return passive_analyze(self.headers, self.url)
```

- [ ] **Step 5: Run the passive tests to verify they pass**

Run: `pytest tests/test_cors_passive.py -v`
Expected: PASS — 7 tests.

- [ ] **Step 6: Run the full suite to ensure migration didn't break anything**

Run: `pytest -q`
Expected: all pass. If any existing analyzer registry test fails, STOP — the adapter contract is broken.

- [ ] **Step 7: Commit**

```bash
git add corsair/cors/passive.py corsair/analyzers/cors.py tests/test_cors_passive.py
git commit -m "refactor(cors): migrate static analyzer to corsair.cors.passive

Move legacy analyzers/cors.py logic into corsair/cors/passive.py as a pure
analyze(headers, url) function. Old CORSAnalyzer becomes a thin adapter so
the analyzer registry (ALL_ANALYZERS) still works unchanged. Wildcard+creds
now reuses CORS_WILDCARD_CRED from the new registry for consistency across
passive and DAST findings.

Wave 1 Task 3/6."
```

---

## Task 4: Active probe infrastructure

**Files:**
- Modify: `corsair/cors/probe.py`
- Create: `tests/test_cors_probe.py`

- [ ] **Step 1: Write the failing probe test**

Create `tests/test_cors_probe.py`:

```python
"""CORS active probe infrastructure tests."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

from corsair.cors.probe import (
    ProbeResult,
    build_probes,
    run_probe,
    run_probes,
)


def _mock_response(headers: dict = None, status_code: int = 200, body: str = ""):
    resp = MagicMock()
    resp.headers = headers or {}
    resp.status_code = status_code
    resp.text = body
    return resp


class TestBuildProbes:
    def test_wave1_probe_set_is_two_items(self):
        # Wave 1 scope: arbitrary origin + null origin. Bypass/protocol/
        # internal probes ship in Wave 2.
        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://evil.example",
        )
        assert len(probes) == 2
        origins = [p.origin for p in probes]
        assert "https://evil.example" in origins
        assert "null" in origins

    def test_arbitrary_origin_probe_uses_configured_evil_origin(self):
        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://attacker.test",
        )
        arbitrary = [p for p in probes if p.label == "arbitrary_origin"][0]
        assert arbitrary.origin == "https://attacker.test"

    def test_each_probe_has_unique_cache_buster(self):
        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://evil.example",
        )
        busters = [p.cache_buster for p in probes]
        assert len(set(busters)) == len(busters)


class TestRunProbe:
    def test_captures_acao_acac_vary(self):
        client = AsyncMock()
        client.get.return_value = _mock_response(
            headers={
                "Access-Control-Allow-Origin": "https://evil.example",
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
            }
        )
        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://evil.example",
        )
        probe = [p for p in probes if p.label == "arbitrary_origin"][0]

        result = asyncio.run(run_probe(client, probe, timeout=5.0))

        assert isinstance(result, ProbeResult)
        assert result.origin_sent == "https://evil.example"
        assert result.acao == "https://evil.example"
        assert result.acac == "true"
        assert result.vary == "Origin"
        assert result.status_code == 200

    def test_sends_origin_header_and_cache_buster_param(self):
        client = AsyncMock()
        client.get.return_value = _mock_response()
        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://evil.example",
        )
        probe = [p for p in probes if p.label == "arbitrary_origin"][0]

        asyncio.run(run_probe(client, probe, timeout=5.0))

        call_kwargs = client.get.call_args.kwargs
        assert call_kwargs["headers"]["Origin"] == "https://evil.example"
        # Cache buster should appear in params.
        assert "_cb" in call_kwargs["params"]
        assert call_kwargs["params"]["_cb"] == probe.cache_buster

    def test_null_origin_probe_sends_literal_null(self):
        client = AsyncMock()
        client.get.return_value = _mock_response()
        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://evil.example",
        )
        probe = [p for p in probes if p.label == "null_origin"][0]

        asyncio.run(run_probe(client, probe, timeout=5.0))
        assert client.get.call_args.kwargs["headers"]["Origin"] == "null"

    def test_5xx_response_is_returned_not_raised(self):
        client = AsyncMock()
        client.get.return_value = _mock_response(status_code=503)
        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://evil.example",
        )

        result = asyncio.run(run_probe(client, probes[0], timeout=5.0))
        assert result.status_code == 503
        assert result.error is None


class TestRunProbes:
    def test_runs_probes_concurrently_with_semaphore(self):
        client = AsyncMock()
        client.get.return_value = _mock_response(
            headers={"Access-Control-Allow-Origin": "null"}
        )
        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://evil.example",
        )

        results = asyncio.run(
            run_probes(client, probes, timeout=5.0, max_concurrency=5)
        )
        assert len(results) == 2
        assert all(isinstance(r, ProbeResult) for r in results)

    def test_abort_event_cancels_pending_probes(self):
        slow_client = AsyncMock()

        async def slow_get(*args, **kwargs):
            await asyncio.sleep(3.0)
            return _mock_response()

        slow_client.get = AsyncMock(side_effect=slow_get)

        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://evil.example",
        )
        abort_event = asyncio.Event()

        async def run_and_abort():
            # Set abort immediately; run_probes should return quickly.
            abort_event.set()
            return await run_probes(
                slow_client,
                probes,
                timeout=5.0,
                max_concurrency=5,
                abort_event=abort_event,
            )

        import time

        start = time.monotonic()
        results = asyncio.run(run_and_abort())
        elapsed = time.monotonic() - start
        # 2.5s bound (same headroom as cache v0.4.1 test) with 3s sleep target.
        assert elapsed < 2.5, f"Abort did not cancel in time: {elapsed:.2f}s"
        # Cancelled probes return ProbeResult with error='aborted' or are absent.
        for r in results:
            if r is not None:
                assert r.error == "aborted" or r.status_code == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cors_probe.py -v`
Expected: FAIL — `ProbeResult`, `build_probes`, `run_probe`, `run_probes` not defined.

- [ ] **Step 3: Implement `corsair/cors/probe.py`**

Replace the empty stub with:

```python
"""
Active CORS reflection probing.

Builds Origin-varied probe requests, executes them over httpx.AsyncClient
under a semaphore-bounded gather() with an abort_event escape hatch. Pattern
mirrors corsair.cache.auditor._active_probes() post-v0.4.1.
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass
from typing import List, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class OriginProbe:
    """A single Origin-varied probe to send."""

    url: str
    origin: str  # Value to send in the Origin request header.
    label: str  # Classifier tag, e.g. "arbitrary_origin", "null_origin".
    cache_buster: str  # UUID-based unique query param value.


@dataclass
class ProbeResult:
    """Outcome of executing a single OriginProbe."""

    label: str
    origin_sent: str
    acao: Optional[str] = None
    acac: Optional[str] = None
    vary: Optional[str] = None
    set_cookie: Optional[str] = None
    content_type: Optional[str] = None
    status_code: int = 0
    location: Optional[str] = None
    error: Optional[str] = None


def _make_cache_buster() -> str:
    return uuid.uuid4().hex[:16]


def build_probes(url: str, evil_origin: str) -> List[OriginProbe]:
    """
    Build the Wave 1 probe set: arbitrary origin + null origin.

    Later waves extend this with the bypass matrix, protocol downgrade,
    and internal-network origins.
    """
    return [
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


async def run_probe(
    client: httpx.AsyncClient,
    probe: OriginProbe,
    timeout: float = 10.0,
) -> ProbeResult:
    """Execute one probe and capture the CORS-relevant response metadata."""
    try:
        response = await client.get(
            probe.url,
            headers={"Origin": probe.origin},
            params={"_cb": probe.cache_buster},
            timeout=timeout,
        )
    except (httpx.TimeoutException, httpx.HTTPError) as e:
        logger.debug(f"[cors-probe] {probe.label} failed: {e}")
        return ProbeResult(
            label=probe.label,
            origin_sent=probe.origin,
            error=str(e),
        )

    h = {k.lower(): v for k, v in response.headers.items()}
    return ProbeResult(
        label=probe.label,
        origin_sent=probe.origin,
        acao=h.get("access-control-allow-origin"),
        acac=h.get("access-control-allow-credentials"),
        vary=h.get("vary"),
        set_cookie=h.get("set-cookie"),
        content_type=h.get("content-type"),
        status_code=response.status_code,
        location=h.get("location"),
    )


async def run_probes(
    client: httpx.AsyncClient,
    probes: List[OriginProbe],
    timeout: float = 10.0,
    max_concurrency: int = 5,
    abort_event: Optional[asyncio.Event] = None,
) -> List[ProbeResult]:
    """
    Run all probes concurrently under a semaphore with abort support.

    If abort_event is set before or during execution, pending probes are
    cancelled and returned as ProbeResult(error='aborted').
    """
    if abort_event is None:
        abort_event = asyncio.Event()

    semaphore = asyncio.Semaphore(max_concurrency)

    async def limited(probe: OriginProbe) -> ProbeResult:
        async with semaphore:
            if abort_event.is_set():
                return ProbeResult(
                    label=probe.label,
                    origin_sent=probe.origin,
                    error="aborted",
                )
            return await run_probe(client, probe, timeout=timeout)

    tasks = [asyncio.create_task(limited(p)) for p in probes]

    async def abort_watcher():
        await abort_event.wait()
        for t in tasks:
            if not t.done():
                t.cancel()

    watcher = asyncio.create_task(abort_watcher())
    try:
        raw = await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        watcher.cancel()
        try:
            await watcher
        except (asyncio.CancelledError, Exception):
            pass

    results: List[ProbeResult] = []
    for probe, r in zip(probes, raw):
        if isinstance(r, asyncio.CancelledError):
            results.append(
                ProbeResult(
                    label=probe.label,
                    origin_sent=probe.origin,
                    error="aborted",
                )
            )
        elif isinstance(r, Exception):
            logger.warning(f"[cors-probe] {probe.label} raised: {r}")
            results.append(
                ProbeResult(
                    label=probe.label,
                    origin_sent=probe.origin,
                    error=str(r),
                )
            )
        else:
            results.append(r)
    return results
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cors_probe.py -v`
Expected: PASS — 8 tests.

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add corsair/cors/probe.py tests/test_cors_probe.py
git commit -m "feat(cors): active probe infrastructure

OriginProbe + ProbeResult dataclasses, build_probes() for Wave 1 payload
set (arbitrary origin + null), run_probe/run_probes with semaphore-bounded
gather + abort_event cancellation. Mirrors cache v0.4.1 pattern.

Wave 1 Task 4/6."
```

---

## Task 5: Reflection classifier + sensitivity heuristic

**Files:**
- Modify: `corsair/cors/analyzers.py`
- Create: `tests/test_cors_analyzers.py`

- [ ] **Step 1: Write the failing classifier tests**

Create `tests/test_cors_analyzers.py`:

```python
"""Reflection classifier and sensitivity heuristic tests."""

from corsair.cors.analyzers import (
    SensitivitySignal,
    classify_reflection,
    classify_sensitivity,
)
from corsair.cors.probe import ProbeResult


def _result(label="arbitrary_origin", origin="https://evil.example", **kwargs):
    return ProbeResult(label=label, origin_sent=origin, status_code=200, **kwargs)


class TestClassifyReflection:
    def test_arbitrary_origin_reflected_with_creds_is_critical(self):
        r = _result(
            acao="https://evil.example",
            acac="true",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_ARBITRARY_ORIGIN_CRED"

    def test_arbitrary_origin_reflected_without_creds_is_high(self):
        r = _result(acao="https://evil.example")
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_ARBITRARY_ORIGIN"

    def test_null_origin_trusted_with_creds(self):
        r = _result(
            label="null_origin",
            origin="null",
            acao="null",
            acac="true",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_NULL_ORIGIN_CRED"

    def test_null_origin_trusted_without_creds(self):
        r = _result(label="null_origin", origin="null", acao="null")
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_NULL_ORIGIN"

    def test_no_reflection_returns_none(self):
        r = _result(acao="https://trusted.example.com")
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None

    def test_acao_wildcard_is_not_a_reflection(self):
        # Wildcard is handled by the passive phase (CORS_WILDCARD_CRED),
        # not the reflection classifier.
        r = _result(acao="*", acac="true")
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None

    def test_no_acao_at_all_returns_none(self):
        r = _result(acao=None)
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None

    def test_error_probe_returns_none(self):
        r = ProbeResult(
            label="arbitrary_origin",
            origin_sent="https://evil.example",
            error="timeout",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None

    def test_auth_gate_status_returns_none(self):
        # 401/403 on the probe signals the endpoint is authenticated and our
        # anonymous probe cannot verdict it. Caller will emit
        # CORS_PROBE_INCONCLUSIVE based on the meta-aggregation.
        r = _result(acao="https://evil.example", acac="true", status_code=401)
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None


class TestSensitivityHeuristic:
    """4x2 truth table: 4 signals x (present, absent)."""

    # --- Signal 1: Set-Cookie on response
    def test_set_cookie_present_is_sensitive(self):
        r = _result(set_cookie="sessionid=abc123")
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.SENSITIVE

    def test_set_cookie_absent_is_unknown(self):
        r = _result()
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.UNKNOWN

    # --- Signal 2: Authorization header in request
    def test_authorization_header_present_is_sensitive(self):
        r = _result()
        signal = classify_sensitivity(r, request_headers={"Authorization": "Bearer xyz"})
        assert signal == SensitivitySignal.SENSITIVE

    def test_authorization_header_absent_is_unknown(self):
        r = _result()
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.UNKNOWN

    # --- Signal 3: JSON Content-Type
    def test_json_content_type_is_sensitive(self):
        r = _result(content_type="application/json; charset=utf-8")
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.SENSITIVE

    def test_vendor_json_content_type_is_sensitive(self):
        r = _result(content_type="application/vnd.api+json")
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.SENSITIVE

    def test_html_content_type_absent_json_is_unknown(self):
        r = _result(content_type="text/html; charset=utf-8")
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.UNKNOWN

    # --- Signal 4: Login redirect
    def test_login_redirect_is_sensitive(self):
        r = _result(status_code=302, location="https://target.example.com/login?next=/")
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.SENSITIVE

    def test_signin_redirect_is_sensitive(self):
        r = _result(status_code=303, location="/auth/signin")
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.SENSITIVE

    def test_sso_redirect_is_sensitive(self):
        r = _result(status_code=302, location="/sso/start")
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.SENSITIVE

    def test_non_auth_redirect_is_unknown(self):
        r = _result(status_code=302, location="/dashboard")
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.UNKNOWN

    # --- Combination: any signal present wins
    def test_multiple_signals_all_sensitive(self):
        r = _result(
            set_cookie="x=1",
            content_type="application/json",
        )
        signal = classify_sensitivity(
            r,
            request_headers={"Authorization": "Bearer z"},
        )
        assert signal == SensitivitySignal.SENSITIVE

    def test_no_signals_is_unknown(self):
        r = _result()
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.UNKNOWN


class TestSeverityDowngradeIntegration:
    """classify_reflection should return the severity-adjusted finding ID."""

    def test_arbitrary_origin_cred_with_signals_stays_critical(self):
        r = _result(
            acao="https://evil.example",
            acac="true",
            set_cookie="sess=1",  # signal present
        )
        verdict = classify_reflection(
            r,
            evil_origin="https://evil.example",
            request_headers={},
        )
        assert verdict.finding_id == "CORS_ARBITRARY_ORIGIN_CRED"
        assert verdict.downgraded is False

    def test_arbitrary_origin_cred_without_signals_downgrades_to_high(self):
        # No Set-Cookie, no Authorization, no JSON, no login redirect
        # → downgrade CRITICAL → HIGH per spec §5.1.
        r = _result(acao="https://evil.example", acac="true")
        verdict = classify_reflection(
            r,
            evil_origin="https://evil.example",
            request_headers={},
        )
        assert verdict.finding_id == "CORS_ARBITRARY_ORIGIN_CRED"
        assert verdict.downgraded is True
        assert verdict.effective_severity.value == "HIGH"

    def test_arbitrary_origin_without_creds_downgrades_to_medium(self):
        # HIGH → MEDIUM when no signals.
        r = _result(acao="https://evil.example")
        verdict = classify_reflection(
            r,
            evil_origin="https://evil.example",
            request_headers={},
        )
        assert verdict.finding_id == "CORS_ARBITRARY_ORIGIN"
        assert verdict.downgraded is True
        assert verdict.effective_severity.value == "MEDIUM"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cors_analyzers.py -v`
Expected: FAIL — `classify_reflection`, `classify_sensitivity`, `SensitivitySignal` not defined.

- [ ] **Step 3: Implement `corsair/cors/analyzers.py`**

Replace the stub with:

```python
"""
Response classification for CORS DAST.

classify_reflection(): maps a ProbeResult to a finding ID (or None).
classify_sensitivity(): signal-driven heuristic for severity downgrade.
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional

from ..models import Severity
from .probe import ProbeResult

logger = logging.getLogger(__name__)


class SensitivitySignal(Enum):
    SENSITIVE = "sensitive"
    UNKNOWN = "unknown"


@dataclass
class ReflectionVerdict:
    """Outcome of classify_reflection."""

    finding_id: str
    default_severity: Severity
    effective_severity: Severity
    downgraded: bool


# Default severities for Core 5 reflection findings, matching spec §5.
_DEFAULTS: Dict[str, Severity] = {
    "CORS_ARBITRARY_ORIGIN_CRED": Severity.CRITICAL,
    "CORS_ARBITRARY_ORIGIN": Severity.HIGH,
    "CORS_NULL_ORIGIN_CRED": Severity.HIGH,
    "CORS_NULL_ORIGIN": Severity.MEDIUM,
}

# Downgrade map: CRITICAL→HIGH, HIGH→MEDIUM. NULL/NULL_CRED do not downgrade
# (spec §5: only CORS_ARBITRARY_* are marked with the ↓ downgrade indicator).
_DOWNGRADE: Dict[str, Severity] = {
    "CORS_ARBITRARY_ORIGIN_CRED": Severity.HIGH,
    "CORS_ARBITRARY_ORIGIN": Severity.MEDIUM,
}

_AUTH_GATE_STATUSES = {401, 403}
_LOGIN_PATH_MARKERS = ("login", "signin", "auth", "sso")
_JSON_CT_MARKERS = ("application/json", "+json")


def classify_reflection(
    result: ProbeResult,
    evil_origin: str,
    request_headers: Optional[Dict[str, str]] = None,
) -> Optional[ReflectionVerdict]:
    """
    Map a ProbeResult to a finding ID for Wave 1.

    Returns None when:
    - Probe errored
    - Response was 401/403 (auth gate — handled by CORS_PROBE_INCONCLUSIVE
      meta aggregation in the auditor)
    - ACAO is absent, wildcard, or didn't reflect the probe's origin
    """
    if result.error:
        return None
    if result.status_code in _AUTH_GATE_STATUSES:
        return None
    if not result.acao:
        return None

    acao_stripped = result.acao.strip()
    # Wildcard is a passive-phase finding (CORS_WILDCARD_CRED), not a
    # reflection finding — classifier should skip it here.
    if acao_stripped == "*":
        return None

    acac_true = (result.acac or "").strip().lower() == "true"

    finding_id: Optional[str] = None

    if result.label == "arbitrary_origin" and acao_stripped == evil_origin:
        finding_id = (
            "CORS_ARBITRARY_ORIGIN_CRED" if acac_true else "CORS_ARBITRARY_ORIGIN"
        )
    elif result.label == "null_origin" and acao_stripped.lower() == "null":
        finding_id = "CORS_NULL_ORIGIN_CRED" if acac_true else "CORS_NULL_ORIGIN"

    if finding_id is None:
        return None

    default = _DEFAULTS[finding_id]
    sensitivity = classify_sensitivity(result, request_headers or {})

    if finding_id in _DOWNGRADE and sensitivity == SensitivitySignal.UNKNOWN:
        effective = _DOWNGRADE[finding_id]
        downgraded = True
    else:
        effective = default
        downgraded = False

    return ReflectionVerdict(
        finding_id=finding_id,
        default_severity=default,
        effective_severity=effective,
        downgraded=downgraded,
    )


def classify_sensitivity(
    result: ProbeResult,
    request_headers: Dict[str, str],
) -> SensitivitySignal:
    """
    Signal-driven sensitivity heuristic (spec §5.1).

    Returns SENSITIVE if ANY of:
      1. Set-Cookie header on the response.
      2. Authorization header in the scan's original request headers.
      3. Response Content-Type is application/json or application/*+json.
      4. Anonymous probe returned 302/303 to a path containing
         login/signin/auth/sso.

    Otherwise UNKNOWN.
    """
    if result.set_cookie:
        return SensitivitySignal.SENSITIVE

    req_headers_lower = {k.lower(): v for k, v in request_headers.items()}
    if "authorization" in req_headers_lower:
        return SensitivitySignal.SENSITIVE

    ct = (result.content_type or "").lower()
    if any(marker in ct for marker in _JSON_CT_MARKERS):
        return SensitivitySignal.SENSITIVE

    if result.status_code in (302, 303) and result.location:
        loc_lower = result.location.lower()
        if any(marker in loc_lower for marker in _LOGIN_PATH_MARKERS):
            return SensitivitySignal.SENSITIVE

    return SensitivitySignal.UNKNOWN
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cors_analyzers.py -v`
Expected: PASS — 20 tests.

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add corsair/cors/analyzers.py tests/test_cors_analyzers.py
git commit -m "feat(cors): reflection classifier + sensitivity heuristic

classify_reflection maps ProbeResult to Core 5 finding IDs with severity
downgrade when no sensitivity signal (Set-Cookie, Authorization, JSON
content-type, or login redirect) is observed. 4x2 truth-table tests
cover every signal in both directions.

Wave 1 Task 5/6."
```

---

## Task 6: CORSAuditor wiring + CLI + v0.5.0 release

**Files:**
- Modify: `corsair/cors/auditor.py` (full orchestrator)
- Modify: `corsair/scanner.py` (integration)
- Modify: `corsair/cli.py` (new flags)
- Modify: `corsair/__init__.py` (version bump)
- Modify: `pyproject.toml` (version bump)
- Modify: `README.md` (changelog)
- Create: `tests/test_cors_auditor_unit.py`
- Create: `tests/test_scanner_cors_integration.py`

- [ ] **Step 1: Write the failing auditor test**

Create `tests/test_cors_auditor_unit.py`:

```python
"""CORSAuditor orchestration tests (Wave 1)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from corsair.cors.auditor import CORSAuditor
from corsair.cors.probe import ProbeResult
from corsair.models import Severity


def _mock_response(headers: dict = None, status_code: int = 200):
    resp = MagicMock()
    resp.headers = headers or {}
    resp.status_code = status_code
    resp.text = ""
    return resp


class TestCORSAuditorPassive:
    def test_passive_only_when_active_disabled(self):
        auditor = CORSAuditor(active=False)
        findings = auditor.audit(
            "https://example.com",
            {"Access-Control-Allow-Origin": "*"},
        )
        # Passive wildcard emits CORS_WILDCARD_CRED (if creds) or wildcard
        # finding; no probes fire.
        assert len(findings) >= 1
        assert all(f.category.value == "cors" for f in findings)

    def test_passive_no_cors_emits_pass(self):
        auditor = CORSAuditor(active=False)
        findings = auditor.audit("https://example.com", {})
        assert any(f.severity == Severity.PASS for f in findings)


class TestCORSAuditorActiveReflection:
    def test_arbitrary_origin_cred_fires_critical(self):
        auditor = CORSAuditor(active=True, evil_origin="https://evil.example")

        async def fake_get(*args, **kwargs):
            origin = kwargs.get("headers", {}).get("Origin")
            if origin == "https://evil.example":
                return _mock_response(
                    headers={
                        "Access-Control-Allow-Origin": "https://evil.example",
                        "Access-Control-Allow-Credentials": "true",
                        "Set-Cookie": "sess=abc",
                    }
                )
            return _mock_response()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=fake_get)
            mock_client.__aenter__.return_value = mock_client
            mock_client_cls.return_value = mock_client

            findings = auditor.audit("https://api.example.com", {})

        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert any("arbitrary origin" in f.title.lower() for f in critical)

    def test_null_origin_trusted_fires(self):
        auditor = CORSAuditor(active=True, evil_origin="https://evil.example")

        async def fake_get(*args, **kwargs):
            origin = kwargs.get("headers", {}).get("Origin")
            if origin == "null":
                return _mock_response(
                    headers={
                        "Access-Control-Allow-Origin": "null",
                        "Access-Control-Allow-Credentials": "true",
                    }
                )
            return _mock_response()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=fake_get)
            mock_client.__aenter__.return_value = mock_client
            mock_client_cls.return_value = mock_client

            findings = auditor.audit("https://api.example.com", {})

        assert any(f.title == "Null origin trusted with credentials" for f in findings)

    def test_no_reflection_no_active_findings(self):
        auditor = CORSAuditor(active=True, evil_origin="https://evil.example")

        async def fake_get(*args, **kwargs):
            return _mock_response(
                headers={"Access-Control-Allow-Origin": "https://trusted.example.com"}
            )

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=fake_get)
            mock_client.__aenter__.return_value = mock_client
            mock_client_cls.return_value = mock_client

            findings = auditor.audit("https://api.example.com", {})

        # Only passive PASS from initial header set (empty headers) — no
        # reflection findings.
        active_findings = [
            f for f in findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
        ]
        assert len(active_findings) == 0


class TestCORSAuditorAbortPath:
    def test_critical_finding_sets_abort_event(self):
        """When CORS_ARBITRARY_ORIGIN_CRED fires, the abort event is set."""
        auditor = CORSAuditor(active=True, evil_origin="https://evil.example")

        # Fast arbitrary probe triggers CRITICAL; null probe would be slow.
        async def fake_get(*args, **kwargs):
            origin = kwargs.get("headers", {}).get("Origin")
            if origin == "https://evil.example":
                return _mock_response(
                    headers={
                        "Access-Control-Allow-Origin": "https://evil.example",
                        "Access-Control-Allow-Credentials": "true",
                        "Set-Cookie": "x=1",
                    }
                )
            # null probe sleeps — should be cancelled via abort_event.
            await asyncio.sleep(3.0)
            return _mock_response()

        import time

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=fake_get)
            mock_client.__aenter__.return_value = mock_client
            mock_client_cls.return_value = mock_client

            start = time.monotonic()
            findings = auditor.audit("https://api.example.com", {})
            elapsed = time.monotonic() - start

        # Abort should keep total wall-clock well under the 3s null-probe sleep.
        assert elapsed < 2.5, f"Abort did not short-circuit: {elapsed:.2f}s"
        assert any(f.severity == Severity.CRITICAL for f in findings)


class TestCORSAuditorMetaFindings:
    def test_all_probes_auth_gated_emits_inconclusive(self):
        auditor = CORSAuditor(active=True, evil_origin="https://evil.example")

        async def fake_get(*args, **kwargs):
            return _mock_response(status_code=401)

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=fake_get)
            mock_client.__aenter__.return_value = mock_client
            mock_client_cls.return_value = mock_client

            findings = auditor.audit("https://api.example.com", {})

        assert any(
            f.title == "CORS probing inconclusive" for f in findings
        ), f"Expected CORS_PROBE_INCONCLUSIVE, got: {[f.title for f in findings]}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cors_auditor_unit.py -v`
Expected: FAIL — stub `CORSAuditor.audit` returns `[]`.

- [ ] **Step 3: Implement the full `CORSAuditor`**

Replace `corsair/cors/auditor.py`:

```python
"""
CORSAuditor — orchestrates CORS DAST for Corsair.

Three-phase pipeline:
  Phase 1 (passive): header-only analysis (always runs).
  Phase 2 (active reflection): Origin-varied GETs, ~2 probes in Wave 1.
  Phase 3 (preflight + cache-key): stub in Wave 1, lit up in Wave 3.

Mirrors corsair.cache.auditor.CacheAuditor post-v0.4.1 (asyncio.Event
abort + semaphore + gather(return_exceptions=True) + finally-cancelled
watcher).
"""

import asyncio
import logging
from typing import Dict, List, Optional

import httpx

from ..models import Finding
from .analyzers import classify_reflection
from .findings import get_finding
from .passive import analyze as passive_analyze
from .probe import ProbeResult, build_probes, run_probes

logger = logging.getLogger(__name__)


class CORSAuditor:
    def __init__(
        self,
        timeout: int = 10,
        max_concurrency: int = 5,
        active: bool = True,
        evil_origin: str = "https://evil.example",
        phase_timeout: int = 60,
    ):
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.active = active
        self.evil_origin = evil_origin
        self.phase_timeout = phase_timeout

    def audit(self, url: str, headers: Dict[str, str]) -> List[Finding]:
        try:
            return asyncio.run(self._audit_async(url, headers))
        except Exception as e:
            logger.error(f"CORS audit failed for {url}: {e}")
            return []

    async def _audit_async(
        self, url: str, headers: Dict[str, str]
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Phase 1: passive, always runs.
        findings.extend(passive_analyze(headers, url))

        if not self.active:
            return findings

        # Phase 2: active reflection probes.
        async with httpx.AsyncClient(
            follow_redirects=False,  # We need to inspect 302 locations.
            verify=True,
        ) as client:
            try:
                phase2_findings = await asyncio.wait_for(
                    self._active_reflection_phase(client, url, headers),
                    timeout=self.phase_timeout,
                )
                findings.extend(phase2_findings)
            except asyncio.TimeoutError:
                logger.warning(f"[cors] reflection phase timeout on {url}")
                timeout_finding = get_finding("CORS_PHASE_TIMEOUT")
                if timeout_finding:
                    findings.append(timeout_finding)

        # Phase 3: preflight + cache-key — Wave 3. Stub returns no findings.

        return findings

    async def _active_reflection_phase(
        self,
        client: httpx.AsyncClient,
        url: str,
        request_headers: Dict[str, str],
    ) -> List[Finding]:
        findings: List[Finding] = []
        abort_event = asyncio.Event()

        probes = build_probes(url=url, evil_origin=self.evil_origin)

        results = await run_probes(
            client,
            probes,
            timeout=self.timeout,
            max_concurrency=self.max_concurrency,
            abort_event=abort_event,
        )

        # Check for auth-gate: all non-aborted probes returned 401/403 with
        # no reflection → inconclusive.
        non_aborted = [r for r in results if r.error != "aborted"]
        all_auth_gated = (
            len(non_aborted) > 0
            and all(r.status_code in (401, 403) for r in non_aborted)
        )
        if all_auth_gated:
            incon = get_finding("CORS_PROBE_INCONCLUSIVE")
            if incon:
                findings.append(incon)
            return findings

        for result in results:
            if result.error == "aborted":
                continue
            verdict = classify_reflection(
                result,
                evil_origin=self.evil_origin,
                request_headers=request_headers,
            )
            if verdict is None:
                continue

            finding = get_finding(verdict.finding_id)
            if finding is None:
                continue
            finding.severity = verdict.effective_severity
            finding.current_value = (
                f"Origin: {result.origin_sent} → "
                f"ACAO: {result.acao}, ACAC: {result.acac or 'absent'}"
            )
            if verdict.downgraded:
                finding.description = (
                    f"{finding.description} "
                    f"Severity downgraded from {verdict.default_severity.value} "
                    f"to {verdict.effective_severity.value} because no "
                    f"sensitivity signal (authenticated session, JSON API, or "
                    f"login redirect) was observed. If this endpoint returns "
                    f"sensitive data under authentication, manually confirm "
                    f"and escalate."
                )
            findings.append(finding)

            # Preemptive abort on CRITICAL verdicts.
            if verdict.effective_severity.value == "CRITICAL":
                abort_event.set()

        return findings
```

- [ ] **Step 4: Run the auditor tests to verify they pass**

Run: `pytest tests/test_cors_auditor_unit.py -v`
Expected: PASS — 6 tests.

- [ ] **Step 5: Wire into `HeadScanner`**

Modify `corsair/scanner.py`:

Change the imports near line 18:

```python
from .cache.auditor import CacheAuditor
from .cors.auditor import CORSAuditor
```

Extend `__init__` signature (around line 26-52):

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
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self.cache_probe = cache_probe
        self.cors_probe = cors_probe
        self.cors_evil_origin = cors_evil_origin

        logger.info(
            f"Scanner initialized: timeout={timeout}s, "
            f"follow_redirects={follow_redirects}"
        )
```

Add CORS audit block in `scan_target` immediately after the cache audit block (right after the `except Exception as e: logger.error(f"Cache audit failed: {e}")` line, before `# Calculate score`):

```python
        # CORS DAST audit
        try:
            cors_auditor = CORSAuditor(
                timeout=self.timeout,
                active=self.cors_probe,
                evil_origin=self.cors_evil_origin,
            )
            cors_findings = cors_auditor.audit(final_url, headers)
            # De-dupe: the passive phase inside CORSAuditor produces the
            # same PASS/wildcard findings as the legacy CORSAnalyzer
            # (which is a thin adapter). Keep the CORSAuditor output as
            # the source of truth for CORS findings; strip CORS findings
            # emitted by ALL_ANALYZERS to avoid double-reporting.
            findings = [
                f for f in findings
                if f.category.value != "cors"
            ]
            findings.extend(cors_findings)
        except Exception as e:
            logger.error(f"CORS audit failed: {e}")
```

- [ ] **Step 6: Add the integration test**

Create `tests/test_scanner_cors_integration.py`:

```python
"""HeadScanner ↔ CORSAuditor integration smoke tests."""

from unittest.mock import patch

from corsair.scanner import HeadScanner


def _mock_fetch(headers=None, status=200, final_url="https://example.com"):
    def _fetch(self, url):
        return (status, headers or {}, final_url, None)

    return _fetch


class TestScannerCORSIntegration:
    def test_scanner_invokes_cors_auditor(self):
        scanner = HeadScanner(cors_probe=False, cache_probe=False)
        with patch.object(
            HeadScanner,
            "_fetch_headers",
            _mock_fetch(headers={"Access-Control-Allow-Origin": "*"}),
        ):
            result = scanner.scan_target("https://example.com")

        cors_findings = [f for f in result.findings if f.category.value == "cors"]
        assert len(cors_findings) >= 1
        # Wildcard without creds → CORS Allows All Origins.
        assert any(f.title == "CORS Allows All Origins" for f in cors_findings)

    def test_scanner_cors_opt_out_still_runs_passive(self):
        scanner = HeadScanner(cors_probe=False, cache_probe=False)
        with patch.object(
            HeadScanner,
            "_fetch_headers",
            _mock_fetch(headers={}),
        ):
            result = scanner.scan_target("https://example.com")
        # Passive phase still runs even when cors_probe=False, emits PASS.
        cors_findings = [f for f in result.findings if f.category.value == "cors"]
        assert len(cors_findings) == 1
        assert cors_findings[0].severity.value == "PASS"

    def test_scanner_no_double_reporting_of_cors(self):
        scanner = HeadScanner(cors_probe=False, cache_probe=False)
        with patch.object(
            HeadScanner,
            "_fetch_headers",
            _mock_fetch(headers={"Access-Control-Allow-Origin": "null"}),
        ):
            result = scanner.scan_target("https://example.com")
        null_findings = [
            f for f in result.findings
            if f.category.value == "cors" and "null" in f.title.lower()
        ]
        # Exactly one — CORSAuditor's passive replaces the legacy analyzer.
        assert len(null_findings) == 1
```

- [ ] **Step 7: Run the integration test**

Run: `pytest tests/test_scanner_cors_integration.py -v`
Expected: PASS — 3 tests.

- [ ] **Step 8: Add CLI flags**

Modify `corsair/cli.py`. Add two new `@click.option` lines immediately after the existing `--cache-probe/--no-cache-probe` option (around line 172):

```python
@click.option("--cors-probe/--no-cors-probe", default=True, help="Run CORS DAST probing")
@click.option(
    "--cors-evil-origin",
    default="https://evil.example",
    help="Origin value used to probe for arbitrary-origin reflection",
)
```

Add two new parameters to the `scan()` function signature (after `cache_probe: bool,`):

```python
    cors_probe: bool,
    cors_evil_origin: str,
```

Pass them into `HeadScanner(...)` (around line 226-232):

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

- [ ] **Step 9: Verify CLI smoke**

Run: `corsair scan --help | grep -i cors`
Expected output includes:

```
--cors-probe / --no-cors-probe  Run CORS DAST probing
--cors-evil-origin TEXT         Origin value used to probe for arbitrary-origin reflection
```

- [ ] **Step 10: Run the full test suite**

Run: `pytest -q`
Expected: all tests pass — old cache/analyzer suite + all new CORS tests (~45 new).

- [ ] **Step 11: Bump version to 0.5.0**

Modify `corsair/__init__.py` line 27:

```python
__version__ = "0.5.0"
```

Modify `pyproject.toml` (the `[project]` section — search for `version = "0.4.1"`):

```toml
version = "0.5.0"
```

- [ ] **Step 12: Add README changelog**

Edit `README.md`. Locate the existing `## v0.4.1 Changelog` section and add a new `## v0.5.0 Changelog` section immediately above it:

```markdown
## v0.5.0 Changelog

### Features

- **CORS DAST module** (Wave 1) — new `corsair/cors/` package that actively
  probes CORS misconfigurations by sending Origin-varied GETs and analyzing
  ACAO/ACAC reflection. Ships 5 Core finding classes:
  - `CORS_ARBITRARY_ORIGIN_CRED` (CRITICAL) — arbitrary origin reflected with
    credentials
  - `CORS_ARBITRARY_ORIGIN` (HIGH) — arbitrary origin reflected without creds
  - `CORS_NULL_ORIGIN_CRED` (HIGH) — null origin trusted with credentials
  - `CORS_NULL_ORIGIN` (MEDIUM) — null origin trusted without creds
  - `CORS_WILDCARD_CRED` (MEDIUM) — ACAO `*` + ACAC `true`
- **Signal-driven severity heuristic** — CRITICAL/HIGH findings on the
  arbitrary-origin class downgrade one step when no sensitivity signal
  (Set-Cookie, Authorization request header, JSON response, or login
  redirect) is observed.
- **CLI flags**: `--cors-probe/--no-cors-probe` (default on) and
  `--cors-evil-origin URL` (default `https://evil.example`).
- **Preemptive abort** on confirmed CRITICAL — same pattern as cache v0.4.1.
- **Safe by default**: no state-changing probes, no credentialed probes, no
  traffic to internal networks.

### Refactors

- Static CORS analyzer migrated from `corsair/analyzers/cors.py` into
  `corsair/cors/passive.py` as a pure function. The legacy `CORSAnalyzer`
  class remains a thin adapter so the analyzer registry keeps working.
  `CORSAuditor` is now the source of truth for CORS findings; duplicates
  from the legacy analyzer path are stripped during `scan_target()`.

### Deferred to later waves

- Subdomain/regex bypass matrix, protocol downgrade, internal-network
  origin probes (v0.5.1 — Wave 2).
- Preflight divergence and CDN cache-key divergence probes (v0.5.2 — Wave 3).
- State-changing probes, framework-default heuristic, third-party XSS
  correlation (v0.5.3 — Wave 4).
```

- [ ] **Step 13: Run the full suite one last time**

Run: `pytest -q`
Expected: all pass.

- [ ] **Step 14: Commit and tag**

```bash
git add corsair/cors/auditor.py corsair/scanner.py corsair/cli.py \
        corsair/__init__.py pyproject.toml README.md \
        tests/test_cors_auditor_unit.py tests/test_scanner_cors_integration.py
git commit -m "feat(cors): v0.5.0 — CORS DAST Wave 1

CORSAuditor orchestrator wired into HeadScanner.scan_target() with
--cors-probe/--no-cors-probe and --cors-evil-origin CLI flags. Phase 1
(passive) always runs; Phase 2 (active reflection, 2 probes) runs by
default. Preemptive abort on CRITICAL reuses the cache v0.4.1 pattern.
Legacy analyzers/cors.py now a thin adapter; CORSAuditor is source of
truth for CORS findings.

Ships 5 Core finding classes + 2 meta. Bypass matrix, preflight, and
cache-key probes ship in Waves 2-3.

Wave 1 Task 6/6 — closes CORS DAST v0.5.0."
```

---

## Self-Review Checklist

Run this pass before handing the plan off for execution.

**1. Spec coverage.** Walk through the spec §8 Wave 1 definition and confirm every requirement is in a task:
- [x] Package skeleton (Task 1)
- [x] 5 Core findings + 2 meta (Task 2)
- [x] Passive migration with zero-behavior-change (Task 3)
- [x] Active probe infrastructure with abort_event (Task 4)
- [x] Reflection classifier + 4×2 sensitivity heuristic (Task 5)
- [x] CORSAuditor 3-phase pipeline (Task 6)
- [x] HeadScanner integration (Task 6 step 5)
- [x] `--no-cors-probe` and `--cors-evil-origin` flags (Task 6 steps 8-9)
- [x] v0.5.0 version bump + changelog (Task 6 steps 11-12)

**2. Placeholder scan.** No "TBD", "implement later", "add error handling" — every step contains the actual code or exact command.

**3. Type/name consistency.** The types defined in earlier tasks match later references:
- `OriginProbe`, `ProbeResult` (Task 4) used in Task 5 tests and Task 6 orchestrator.
- `ReflectionVerdict.effective_severity`, `.downgraded` (Task 5) used in Task 6 auditor.
- `build_probes`, `run_probes` (Task 4) called by auditor (Task 6).
- `classify_reflection`, `classify_sensitivity` (Task 5) imported in auditor (Task 6).
- `ALL_CORS_FINDINGS`, `get_finding` (Task 2) used in passive (Task 3) and auditor (Task 6).

**4. TDD discipline.** Every task starts with a failing test, verifies it fails, then implements, then verifies it passes, then commits.

**5. Frequent commits.** Each task ends with its own commit. Six Wave 1 commits total, each independently shippable.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-20-cors-dast-plan.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
