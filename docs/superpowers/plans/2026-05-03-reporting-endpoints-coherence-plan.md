# Reporting-Endpoints Coherence Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a static-analysis Corsair analyzer that flags orphaned reporting endpoint references — names referenced by CSP/COOP/COEP/DIP/NEL/Integrity-Policy (and Report-Only siblings) but not defined in `Reporting-Endpoints` or `Report-To`.

**Architecture:** Single new file `corsair/analyzers/reporting.py` containing module constants, seven parser helpers, three Finding templates, a `_build_finding` builder, and the `ReportingCoherenceAnalyzer(BaseAnalyzer)` class. Registered in `corsair/analyzers/__init__.py` `ALL_ANALYZERS`. Pure static analysis — no new HTTP requests, no async, no new dependencies. Discriminates non-navigation responses by `Content-Type` to suppress SPA-sub-resource false positives. Appends a CDN caveat to findings when `corsair.cache.oracle.fingerprint_cdn` returns truthy.

**Tech Stack:** Python 3.9+, `re` and `json` from stdlib, existing `corsair.models.Finding`/`Severity`/`HeaderCategory`, existing `corsair.analyzers.base.BaseAnalyzer`, existing `corsair.cache.oracle.fingerprint_cdn`. Tests via `pytest` with `monkeypatch`. No new external dependencies.

**Spec:** `docs/superpowers/specs/2026-05-03-reporting-endpoints-coherence-design.md`

---

## File Structure

| File | Action | Purpose |
|---|---|---|
| `corsair/analyzers/reporting.py` | Create | Module constants, parser helpers, finding templates + builder, `ReportingCoherenceAnalyzer` class |
| `tests/test_reporting_coherence.py` | Create | All four test layers (parsers, classification, analyzer, scanner-integration smoke) |
| `corsair/analyzers/__init__.py` | Modify | Import + register `ReportingCoherenceAnalyzer` in `ALL_ANALYZERS` |
| `corsair/__init__.py` | Modify | Bump `__version__` to `"0.5.4"` |
| `pyproject.toml` | Modify | Bump `version` to `"0.5.4"` |
| `README.md` | Modify | Add v0.5.4 changelog entry above v0.5.3 |

**Tasks (5 total):**
1. Parser primitives + navigation discriminator + module constants
2. Finding templates + builder
3. `ReportingCoherenceAnalyzer` class with full orchestration
4. Register in `ALL_ANALYZERS` + scanner-integration smoke tests
5. v0.5.4 release commit (version bump + changelog)

---

## Task 1: Parser primitives + navigation discriminator

**Files:**
- Create: `corsair/analyzers/reporting.py`
- Create: `tests/test_reporting_coherence.py`

This task implements the seven pure-function helpers and the module-level constants. The class itself comes in Task 3.

### Step 1.1: Create the module skeleton with constants

- [ ] **Write the file skeleton with constants only**

Create `corsair/analyzers/reporting.py`:

```python
"""
Reporting-Endpoints Coherence Analyzer.

Cross-references endpoint-name references in policy headers (CSP, CSP-RO, COOP,
COOP-RO, COEP, COEP-RO, DIP, NEL, Integrity-Policy, Integrity-Policy-RO) against
endpoint-name definitions in Reporting-Endpoints and Report-To. Browsers silently
discard reports for unresolved names, so an orphaned reference is a complete
loss of security violation visibility with no surface signal.

Pure static analysis. No new HTTP requests.

Spec: docs/superpowers/specs/2026-05-03-reporting-endpoints-coherence-design.md
"""

import copy
import json
import re
from typing import Dict, List, Optional, Set

from .base import BaseAnalyzer
from ..models import (
    ComplianceMapping,
    CVECorrelation,
    Finding,
    HeaderCategory,
    Severity,
)
from ..cache.oracle import fingerprint_cdn
from ..utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

DEFINITION_HEADERS = ("reporting-endpoints", "report-to")

REFERENCE_HEADERS_CSP_STYLE = (
    "content-security-policy",
    "content-security-policy-report-only",
)

REFERENCE_HEADERS_PARAM_STYLE = (
    "cross-origin-opener-policy",
    "cross-origin-opener-policy-report-only",
    "cross-origin-embedder-policy",
    "cross-origin-embedder-policy-report-only",
    "document-isolation-policy",
)

REFERENCE_HEADERS_NEL = ("nel",)

REFERENCE_HEADERS_INTEGRITY = (
    "integrity-policy",
    "integrity-policy-report-only",
)

NAVIGATION_CONTENT_TYPES = (
    "text/html",
    "application/xhtml+xml",
    "application/xml",
    "text/xml",
)

PLACEHOLDER_NAMES = frozenset({"none", "todo", "dummy", "test", "placeholder"})

REFERENCE_URL = "https://www.w3.org/TR/reporting-1/"
```

- [ ] **Verify the file imports cleanly**

Run: `python3 -c "from corsair.analyzers import reporting"`
Expected: no output, no errors.

- [ ] **Commit the skeleton**

```bash
git add corsair/analyzers/reporting.py
git commit -m "$(cat <<'EOF'
feat(reporting): add module skeleton with constants

Empty module with imports and the constant tuples for definition headers,
reference headers (CSP/param-style/NEL/integrity), navigation Content-Type
allowlist, and placeholder-name set. No logic yet.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

### Step 1.2: TDD `_parse_reporting_endpoints`

- [ ] **Write the failing tests**

Create `tests/test_reporting_coherence.py`:

```python
"""Tests for the Reporting-Endpoints Coherence Analyzer."""

import pytest

from corsair.analyzers.reporting import (
    _extract_csp_report_to,
    _extract_integrity_endpoints,
    _extract_nel_report_to,
    _extract_param_report_to,
    _is_navigation_response,
    _parse_report_to,
    _parse_reporting_endpoints,
)


# ---------------------------------------------------------------------------
# _parse_reporting_endpoints
# ---------------------------------------------------------------------------

class TestParseReportingEndpoints:
    def test_empty_string_returns_empty_set(self):
        assert _parse_reporting_endpoints("") == set()

    def test_single_endpoint(self):
        assert _parse_reporting_endpoints('main="https://example.com/r"') == {"main"}

    def test_multiple_endpoints(self):
        value = 'main="https://a.example.com/r", backup="https://b.example.com/r"'
        assert _parse_reporting_endpoints(value) == {"main", "backup"}

    def test_quoted_url_with_commas(self):
        # Some URLs contain commas in query strings — must not split on them.
        value = 'main="https://example.com/r?a=1,b=2", other="https://b.example.com"'
        assert _parse_reporting_endpoints(value) == {"main", "other"}

    def test_trailing_whitespace(self):
        assert _parse_reporting_endpoints('main="https://example.com/r"   ') == {"main"}

    def test_case_mixed_keys_lowercased(self):
        # RFC 8941 keys are nominally lowercase; normalize defensively.
        assert _parse_reporting_endpoints('Main="https://example.com/r"') == {"main"}

    def test_malformed_returns_empty_set(self):
        assert _parse_reporting_endpoints("this is not a structured field") == set()
```

- [ ] **Run tests to verify they fail**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestParseReportingEndpoints -v`
Expected: FAIL with `ImportError: cannot import name '_parse_reporting_endpoints'`.

- [ ] **Implement `_parse_reporting_endpoints`**

Append to `corsair/analyzers/reporting.py`:

```python
# ---------------------------------------------------------------------------
# Parser helpers — definitions
# ---------------------------------------------------------------------------

# RFC 8941 dictionary key: starts with lowercase alpha or asterisk, followed
# by lowercase alphanumeric, '_', '-', '.', or '*'. Value is either a quoted
# string or a token until the next comma at depth 0.
_REPORTING_ENDPOINTS_KEY_RE = re.compile(
    r'(?P<key>[a-z*][a-z0-9_.*\-]*)\s*=\s*(?:"[^"]*"|[^,]+)'
)


def _parse_reporting_endpoints(value: str) -> Set[str]:
    """Parse an RFC 8941 Structured Fields Dictionary, returning the key set.

    The Reporting-Endpoints header has the form:
        main-endpoint="https://reports.example.com/main", backup="https://b/r"

    Returns a set of lowercased endpoint names. Returns an empty set on empty
    or malformed input.
    """
    if not value:
        return set()
    try:
        return {m.group("key") for m in _REPORTING_ENDPOINTS_KEY_RE.finditer(value.lower())}
    except Exception:  # defensive — regex shouldn't raise on str input
        return set()
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestParseReportingEndpoints -v`
Expected: PASS, 7/7 passing.

### Step 1.3: TDD `_parse_report_to`

- [ ] **Append the failing tests**

Append to `tests/test_reporting_coherence.py`:

```python
# ---------------------------------------------------------------------------
# _parse_report_to
# ---------------------------------------------------------------------------

class TestParseReportTo:
    def test_empty_string_returns_empty_set(self):
        assert _parse_report_to("") == set()

    def test_bare_object_auto_wrapped(self):
        # Some servers send Report-To as a single object, not an array.
        value = '{"group": "main", "max_age": 10886400, "endpoints": [{"url": "https://r.example.com"}]}'
        assert _parse_report_to(value) == {"main"}

    def test_array_of_objects(self):
        value = '[{"group": "main", "endpoints": [{"url": "https://a"}]}, {"group": "alt", "endpoints": [{"url": "https://b"}]}]'
        assert _parse_report_to(value) == {"main", "alt"}

    def test_missing_group_defaults_to_default(self):
        # W3C spec: missing group name defaults to "default".
        value = '{"endpoints": [{"url": "https://r.example.com"}]}'
        assert _parse_report_to(value) == {"default"}

    def test_malformed_json_returns_empty_set(self):
        assert _parse_report_to("not json at all {{{") == set()

    def test_mixed_case_names_lowercased(self):
        value = '{"group": "MainGroup", "endpoints": [{"url": "https://r"}]}'
        assert _parse_report_to(value) == {"maingroup"}
```

- [ ] **Run tests to verify they fail**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestParseReportTo -v`
Expected: FAIL with `ImportError: cannot import name '_parse_report_to'`.

- [ ] **Implement `_parse_report_to`**

Append to `corsair/analyzers/reporting.py`:

```python
def _parse_report_to(value: str) -> Set[str]:
    """Parse a legacy Report-To JSON header, returning group names.

    The Report-To header is a JSON array of objects, but some implementations
    send a bare object. This parser auto-wraps a bare object so both forms
    work. Group names are lowercased on extraction.

    Returns an empty set on empty or malformed input.
    """
    if not value:
        return set()

    raw = value.strip()
    if not raw.startswith("["):
        raw = f"[{raw}]"

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return set()

    if not isinstance(data, list):
        return set()

    groups: Set[str] = set()
    for entry in data:
        if not isinstance(entry, dict):
            continue
        group_name = entry.get("group", "default")
        if isinstance(group_name, str):
            groups.add(group_name.lower())
    return groups
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestParseReportTo -v`
Expected: PASS, 6/6 passing.

### Step 1.4: TDD `_extract_csp_report_to`

- [ ] **Append the failing tests**

Append to `tests/test_reporting_coherence.py`:

```python
# ---------------------------------------------------------------------------
# _extract_csp_report_to
# ---------------------------------------------------------------------------

class TestExtractCSPReportTo:
    def test_directive_present(self):
        value = "default-src 'self'; report-to my-endpoint"
        assert _extract_csp_report_to(value) == "my-endpoint"

    def test_directive_absent(self):
        value = "default-src 'self'; img-src *"
        assert _extract_csp_report_to(value) is None

    def test_multiple_directives_only_report_to_extracted(self):
        value = "default-src 'self'; script-src 'self'; report-to csp-endpoint; report-uri /legacy"
        assert _extract_csp_report_to(value) == "csp-endpoint"

    def test_extra_whitespace(self):
        value = "default-src 'self';   report-to    my-endpoint  "
        assert _extract_csp_report_to(value) == "my-endpoint"

    def test_case_normalized(self):
        value = "default-src 'self'; report-to MyEndpoint"
        assert _extract_csp_report_to(value) == "myendpoint"
```

- [ ] **Run tests to verify they fail**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestExtractCSPReportTo -v`
Expected: FAIL with `ImportError`.

- [ ] **Implement `_extract_csp_report_to`**

Append to `corsair/analyzers/reporting.py`:

```python
# ---------------------------------------------------------------------------
# Parser helpers — references
# ---------------------------------------------------------------------------

_CSP_REPORT_TO_RE = re.compile(r"report-to\s+([a-z0-9_.\-*]+)", re.IGNORECASE)


def _extract_csp_report_to(value: str) -> Optional[str]:
    """Extract the report-to token from a CSP/CSP-RO directive value.

    CSP form: 'default-src 'self'; report-to my-endpoint'
    Returns the lowercased token or None if no report-to directive is present.
    """
    if not value:
        return None
    m = _CSP_REPORT_TO_RE.search(value)
    return m.group(1).lower() if m else None
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestExtractCSPReportTo -v`
Expected: PASS, 5/5 passing.

### Step 1.5: TDD `_extract_param_report_to`

- [ ] **Append the failing tests**

Append to `tests/test_reporting_coherence.py`:

```python
# ---------------------------------------------------------------------------
# _extract_param_report_to
# ---------------------------------------------------------------------------

class TestExtractParamReportTo:
    def test_quoted_name(self):
        value = 'same-origin; report-to="my-endpoint"'
        assert _extract_param_report_to(value) == "my-endpoint"

    def test_unquoted_name(self):
        value = "same-origin; report-to=my-endpoint"
        assert _extract_param_report_to(value) == "my-endpoint"

    def test_missing_parameter(self):
        assert _extract_param_report_to("same-origin") is None

    def test_report_to_not_first_parameter(self):
        value = 'require-corp; some-other-param=value; report-to="rt-endpoint"'
        assert _extract_param_report_to(value) == "rt-endpoint"

    def test_empty_value(self):
        assert _extract_param_report_to("") is None
```

- [ ] **Run tests to verify they fail**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestExtractParamReportTo -v`
Expected: FAIL with `ImportError`.

- [ ] **Implement `_extract_param_report_to`**

Append to `corsair/analyzers/reporting.py`:

```python
def _extract_param_report_to(value: str) -> Optional[str]:
    """Extract the report-to parameter from semicolon-delimited isolation headers.

    Format: 'same-origin; report-to="my-endpoint"' (also accepts unquoted names).
    Used by COOP, COOP-RO, COEP, COEP-RO, DIP.

    Returns the lowercased name or None if no report-to parameter is present.
    """
    if not value or "report-to" not in value.lower():
        return None
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("report-to") and "=" in part:
            _, name = part.split("=", 1)
            return name.strip().strip('"').strip("'")
    return None
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestExtractParamReportTo -v`
Expected: PASS, 5/5 passing.

### Step 1.6: TDD `_extract_nel_report_to`

- [ ] **Append the failing tests**

Append to `tests/test_reporting_coherence.py`:

```python
# ---------------------------------------------------------------------------
# _extract_nel_report_to
# ---------------------------------------------------------------------------

class TestExtractNELReportTo:
    def test_valid_json(self):
        value = '{"report_to": "nel-endpoint", "max_age": 86400}'
        assert _extract_nel_report_to(value) == "nel-endpoint"

    def test_malformed_json(self):
        assert _extract_nel_report_to("not json {") is None

    def test_missing_report_to_field(self):
        value = '{"max_age": 86400, "include_subdomains": true}'
        assert _extract_nel_report_to(value) is None

    def test_empty_value(self):
        assert _extract_nel_report_to("") is None

    def test_case_normalized(self):
        value = '{"report_to": "NELEndpoint"}'
        assert _extract_nel_report_to(value) == "nelendpoint"
```

- [ ] **Run tests to verify they fail**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestExtractNELReportTo -v`
Expected: FAIL with `ImportError`.

- [ ] **Implement `_extract_nel_report_to`**

Append to `corsair/analyzers/reporting.py`:

```python
def _extract_nel_report_to(value: str) -> Optional[str]:
    """Extract the report_to field from a Network-Error-Logging JSON header.

    Format: '{"report_to": "nel-endpoint", "max_age": 86400}'
    Returns the lowercased name or None if missing or malformed.
    """
    if not value:
        return None
    try:
        data = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    name = data.get("report_to")
    return name.lower() if isinstance(name, str) else None
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestExtractNELReportTo -v`
Expected: PASS, 5/5 passing.

### Step 1.7: TDD `_extract_integrity_endpoints`

- [ ] **Append the failing tests**

Append to `tests/test_reporting_coherence.py`:

```python
# ---------------------------------------------------------------------------
# _extract_integrity_endpoints
# ---------------------------------------------------------------------------

class TestExtractIntegrityEndpoints:
    def test_single_endpoint(self):
        value = "blocked-destinations=(script), endpoints=(my-endpoint)"
        assert _extract_integrity_endpoints(value) == {"my-endpoint"}

    def test_multiple_endpoints(self):
        value = "blocked-destinations=(script), endpoints=(ep1 ep2 ep3)"
        assert _extract_integrity_endpoints(value) == {"ep1", "ep2", "ep3"}

    def test_missing_endpoints_param(self):
        assert _extract_integrity_endpoints("blocked-destinations=(script)") == set()

    def test_malformed_inner_list(self):
        # Unclosed parenthesis — should not crash.
        assert _extract_integrity_endpoints("endpoints=(ep1 ep2") == set()

    def test_empty_value(self):
        assert _extract_integrity_endpoints("") == set()

    def test_case_normalized(self):
        value = "endpoints=(MyEndpoint OtherEP)"
        assert _extract_integrity_endpoints(value) == {"myendpoint", "otherep"}
```

- [ ] **Run tests to verify they fail**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestExtractIntegrityEndpoints -v`
Expected: FAIL with `ImportError`.

- [ ] **Implement `_extract_integrity_endpoints`**

Append to `corsair/analyzers/reporting.py`:

```python
_INTEGRITY_ENDPOINTS_RE = re.compile(r"endpoints\s*=\s*\(([^)]*)\)", re.IGNORECASE)


def _extract_integrity_endpoints(value: str) -> Set[str]:
    """Extract endpoint names from an Integrity-Policy or Integrity-Policy-RO header.

    Format: 'blocked-destinations=(script), endpoints=(ep1 ep2)'
    The endpoints parameter is an RFC 8941 Inner List of tokens.

    Returns a set of lowercased names (empty if missing or malformed).
    """
    if not value:
        return set()
    m = _INTEGRITY_ENDPOINTS_RE.search(value)
    if not m:
        return set()
    inner = m.group(1).strip().lower()
    if not inner:
        return set()
    return {tok for tok in inner.split() if tok}
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestExtractIntegrityEndpoints -v`
Expected: PASS, 6/6 passing.

### Step 1.8: TDD `_is_navigation_response`

- [ ] **Append the failing tests**

Append to `tests/test_reporting_coherence.py`:

```python
# ---------------------------------------------------------------------------
# _is_navigation_response
# ---------------------------------------------------------------------------

class TestIsNavigationResponse:
    def test_text_html(self):
        assert _is_navigation_response({"content-type": "text/html"}) is True

    def test_text_html_with_charset(self):
        assert _is_navigation_response({"content-type": "text/html; charset=utf-8"}) is True

    def test_application_xhtml(self):
        assert _is_navigation_response({"content-type": "application/xhtml+xml"}) is True

    def test_application_xml(self):
        assert _is_navigation_response({"content-type": "application/xml"}) is True

    def test_application_json_excluded(self):
        assert _is_navigation_response({"content-type": "application/json"}) is False

    def test_javascript_excluded(self):
        assert _is_navigation_response({"content-type": "application/javascript"}) is False

    def test_css_excluded(self):
        assert _is_navigation_response({"content-type": "text/css"}) is False

    def test_image_excluded(self):
        assert _is_navigation_response({"content-type": "image/png"}) is False

    def test_text_plain_excluded(self):
        assert _is_navigation_response({"content-type": "text/plain"}) is False

    def test_missing_content_type_treated_as_navigation(self):
        # Default per RFC 7231 is application/octet-stream, but in practice many
        # origins serving HTML omit Content-Type. Err toward running the check.
        assert _is_navigation_response({}) is True

    def test_empty_content_type_treated_as_navigation(self):
        assert _is_navigation_response({"content-type": ""}) is True

    def test_case_insensitive_content_type_header_name(self):
        assert _is_navigation_response({"Content-Type": "text/html"}) is True
```

- [ ] **Run tests to verify they fail**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestIsNavigationResponse -v`
Expected: FAIL with `ImportError`.

- [ ] **Implement `_is_navigation_response`**

Append to `corsair/analyzers/reporting.py`:

```python
# ---------------------------------------------------------------------------
# Discriminator
# ---------------------------------------------------------------------------

def _is_navigation_response(headers: Dict[str, str]) -> bool:
    """Return True if the response Content-Type indicates a navigation context.

    Navigation context = Reporting-Endpoints / Report-To definitions are
    expected on this response. Restricts the coherence check to top-level
    document responses (HTML/XHTML/XML), suppressing false positives on
    sub-resources where definitions live on the originating HTML response.

    Missing or empty Content-Type defaults to True (analyze) since many origins
    serving HTML omit it in practice.
    """
    # Case-insensitive header lookup.
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = (v or "").strip().lower()
            break
    if not ct:
        return True
    # Strip parameters: 'text/html; charset=utf-8' -> 'text/html'
    main = ct.split(";", 1)[0].strip()
    return main in NAVIGATION_CONTENT_TYPES
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestIsNavigationResponse -v`
Expected: PASS, 12/12 passing.

### Step 1.9: Run the entire parser suite and commit

- [ ] **Run all parser tests**

Run: `python3 -m pytest tests/test_reporting_coherence.py -v`
Expected: PASS, 39/39 passing (sum of all helpers above).

- [ ] **Commit Task 1**

```bash
git add corsair/analyzers/reporting.py tests/test_reporting_coherence.py
git commit -m "$(cat <<'EOF'
feat(reporting): add parser primitives + navigation discriminator

Seven pure-function helpers covering all twelve in-scope headers:
- _parse_reporting_endpoints (RFC 8941 dictionary keys)
- _parse_report_to (legacy V0 JSON, auto-wraps bare object, defaults missing
  group to "default")
- _extract_csp_report_to (CSP / CSP-RO directive)
- _extract_param_report_to (COOP / COOP-RO / COEP / COEP-RO / DIP semicolon
  parameter, both quoted and unquoted)
- _extract_nel_report_to (Network-Error-Logging JSON)
- _extract_integrity_endpoints (Integrity-Policy / IP-RO inner list)
- _is_navigation_response (Content-Type discriminator; missing → True)

All extracted names are lowercased on extraction. All malformed inputs return
empty/None rather than raising. 39 unit tests covering happy paths, malformed
input, case normalization, and edge cases per spec section 10.1.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Finding templates + builder

**Files:**
- Modify: `corsair/analyzers/reporting.py` (append templates and builder)
- Modify: `tests/test_reporting_coherence.py` (append classification tests)

### Step 2.1: Write failing tests for `_build_finding`

- [ ] **Append the failing tests**

Append to `tests/test_reporting_coherence.py`:

```python
# ---------------------------------------------------------------------------
# Finding templates + _build_finding
# ---------------------------------------------------------------------------

from corsair.analyzers.reporting import (
    _REPORT_001_TEMPLATE,
    _REPORT_002_TEMPLATE,
    _REPORT_004_TEMPLATE,
    _build_finding,
)
from corsair.models import HeaderCategory, Severity


class TestFindingTemplates:
    def test_report_001_is_low_severity(self):
        assert _REPORT_001_TEMPLATE.severity == Severity.LOW

    def test_report_002_is_medium_severity(self):
        assert _REPORT_002_TEMPLATE.severity == Severity.MEDIUM

    def test_report_004_is_high_severity(self):
        assert _REPORT_004_TEMPLATE.severity == Severity.HIGH

    def test_all_templates_use_reporting_category(self):
        for tpl in (_REPORT_001_TEMPLATE, _REPORT_002_TEMPLATE, _REPORT_004_TEMPLATE):
            assert tpl.category == HeaderCategory.REPORTING


class TestBuildFinding:
    def test_returns_deepcopy_not_template(self):
        f = _build_finding(_REPORT_002_TEMPLATE, "ghost", ["Content-Security-Policy"], cdn_detected=False)
        assert f is not _REPORT_002_TEMPLATE
        # Mutating the result must not pollute the template.
        f.title = "MUTATED"
        assert _REPORT_002_TEMPLATE.title != "MUTATED"

    def test_orphan_name_in_description(self):
        f = _build_finding(_REPORT_002_TEMPLATE, "ghost-endpoint", ["Content-Security-Policy"], cdn_detected=False)
        assert "ghost-endpoint" in f.description

    def test_affected_headers_in_header_field(self):
        f = _build_finding(
            _REPORT_002_TEMPLATE, "ghost",
            ["Content-Security-Policy", "Cross-Origin-Embedder-Policy"],
            cdn_detected=False,
        )
        assert "Content-Security-Policy" in f.header
        assert "Cross-Origin-Embedder-Policy" in f.header

    def test_current_value_includes_orphan_and_headers(self):
        f = _build_finding(
            _REPORT_002_TEMPLATE, "ghost",
            ["Content-Security-Policy"], cdn_detected=False,
        )
        assert "ghost" in f.current_value
        assert "Content-Security-Policy" in f.current_value

    def test_cdn_caveat_appended_when_detected(self):
        f = _build_finding(_REPORT_002_TEMPLATE, "ghost", ["Content-Security-Policy"], cdn_detected=True)
        assert "CDN" in f.description or "edge" in f.description

    def test_no_cdn_caveat_when_not_detected(self):
        f = _build_finding(_REPORT_002_TEMPLATE, "ghost", ["Content-Security-Policy"], cdn_detected=False)
        assert "CDN" not in f.description
```

- [ ] **Run tests to verify they fail**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestFindingTemplates tests/test_reporting_coherence.py::TestBuildFinding -v`
Expected: FAIL with `ImportError: cannot import name '_REPORT_001_TEMPLATE'`.

### Step 2.2: Implement templates and `_build_finding`

- [ ] **Append templates and builder**

Append to `corsair/analyzers/reporting.py`:

```python
# ---------------------------------------------------------------------------
# Compliance/CWE constants for finding templates
# ---------------------------------------------------------------------------

def _compliance(framework: str, req_id: str, req_name: str, status: str = "FAIL") -> ComplianceMapping:
    return ComplianceMapping(
        framework=framework,
        requirement_id=req_id,
        requirement_name=req_name,
        status=status,
    )


def _cwe(cwe_id: str, desc: str) -> CVECorrelation:
    return CVECorrelation(cve_id=cwe_id, cvss_score=0.0, description=desc)


_OWASP_A05 = _compliance("OWASP_TOP_10_2025", "A05", "Security Misconfiguration")
_OWASP_A09 = _compliance(
    "OWASP_TOP_10_2025", "A09", "Security Logging and Monitoring Failures"
)
_PCI_11_6_1 = _compliance(
    "PCI_DSS_4_0", "11.6.1", "Detect unauthorized changes to HTTP headers and payment-page content"
)
_CWE_778 = _cwe("CWE-778", "Insufficient Logging")
_CWE_693 = _cwe("CWE-693", "Protection Mechanism Failure")

_CDN_CAVEAT = (
    " If reporting endpoints are injected by a CDN/edge gateway, this finding "
    "may be a false positive on a direct-origin scan."
)


# ---------------------------------------------------------------------------
# Finding templates — populated with placeholders that _build_finding fills
# ---------------------------------------------------------------------------

_REPORT_001_TEMPLATE = Finding(
    header="Reporting-Endpoints",
    category=HeaderCategory.REPORTING,
    severity=Severity.LOW,
    title="Incomplete Migration to Modern Reporting API",
    description=(
        "The endpoint name '{name}' is referenced by {headers} and is defined "
        "in the legacy Report-To header but missing from the modern "
        "Reporting-Endpoints header. Chromium browsers fall back to the V0 "
        "cache for most policies, so reporting still functions on legacy "
        "browsers — but modern policies (e.g., Integrity-Policy) require the "
        "new header and will not work."
    ),
    current_value="Reference: {name} (in: {headers})",
    recommendation=(
        "Mirror the endpoint definition in the Reporting-Endpoints header "
        "using RFC 8941 Structured Fields syntax."
    ),
    example_value='Reporting-Endpoints: {name}="https://reports.example.com/{name}"',
    reference_url=REFERENCE_URL,
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_778],
)

_REPORT_002_TEMPLATE = Finding(
    header="Reporting-Endpoints",
    category=HeaderCategory.REPORTING,
    severity=Severity.MEDIUM,
    title="Orphaned Security Reporting Endpoint",
    description=(
        "The endpoint name '{name}' is referenced by {headers} but is not "
        "defined in either the modern Reporting-Endpoints header or the "
        "legacy Report-To header. The browser will silently discard every "
        "report for this name, leaving the site owner blind to security "
        "violations such as CSP breaches and cross-origin isolation failures."
    ),
    current_value="Reference: {name} (in: {headers})",
    recommendation=(
        "Add a Reporting-Endpoints header that defines the referenced name "
        "with a valid HTTPS URL."
    ),
    example_value='Reporting-Endpoints: {name}="https://reports.example.com/{name}"',
    reference_url=REFERENCE_URL,
    compliance_mappings=[_OWASP_A05, _OWASP_A09],
    cve_correlations=[_CWE_778],
)

_REPORT_004_TEMPLATE = Finding(
    header="Integrity-Policy",
    category=HeaderCategory.REPORTING,
    severity=Severity.HIGH,
    title="Integrity-Policy Monitoring Failure",
    description=(
        "The endpoint name '{name}' is referenced by {headers} (an "
        "Integrity-Policy or Integrity-Policy-Report-Only header) but is not "
        "defined in the Reporting-Endpoints header. Integrity-Policy does "
        "NOT fall back to legacy Report-To, so SRI violation reports are "
        "guaranteed to be silently discarded — a complete failure of the "
        "subresource integrity monitoring pipeline."
    ),
    current_value="Reference: {name} (in: {headers})",
    recommendation=(
        "Define the names listed in the Integrity-Policy endpoints=(...) "
        "parameter inside a Reporting-Endpoints header. Note that legacy "
        "Report-To definitions do not satisfy Integrity-Policy."
    ),
    example_value='Reporting-Endpoints: {name}="https://reports.example.com/integrity"',
    reference_url=REFERENCE_URL,
    compliance_mappings=[_OWASP_A05, _OWASP_A09, _PCI_11_6_1],
    cve_correlations=[_CWE_778, _CWE_693],
)


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------

def _build_finding(
    template: Finding,
    orphan_name: str,
    affected_headers: List[str],
    cdn_detected: bool,
) -> Finding:
    """Construct an emitted Finding from a template, injecting orphan name and
    affected reference headers. Appends the CDN caveat to the description if
    cdn_detected is True. Severity is taken from the template — callers handle
    severity overrides (placeholder downgrade) before calling _build_finding.
    """
    f = copy.deepcopy(template)
    headers_csv = ", ".join(affected_headers)
    f.header = headers_csv
    f.title = f.title  # title is generic by design; orphan name lives in description/current_value
    f.description = f.description.replace("{name}", orphan_name).replace("{headers}", headers_csv)
    f.current_value = f.current_value.replace("{name}", orphan_name).replace("{headers}", headers_csv)
    f.example_value = f.example_value.replace("{name}", orphan_name)
    if cdn_detected:
        f.description += _CDN_CAVEAT
    return f
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestFindingTemplates tests/test_reporting_coherence.py::TestBuildFinding -v`
Expected: PASS, 10/10 passing.

### Step 2.3: Run full suite and commit Task 2

- [ ] **Run all tests so far**

Run: `python3 -m pytest tests/test_reporting_coherence.py -v`
Expected: PASS, 49/49 passing.

- [ ] **Commit Task 2**

```bash
git add corsair/analyzers/reporting.py tests/test_reporting_coherence.py
git commit -m "$(cat <<'EOF'
feat(reporting): add finding templates and builder

Three Finding templates per spec section 5:
- _REPORT_001_TEMPLATE (LOW): incomplete migration — name in Report-To only
- _REPORT_002_TEMPLATE (MEDIUM): generic orphan — name undefined anywhere
- _REPORT_004_TEMPLATE (HIGH): Integrity-Policy orphan — IP doesn't fall back

Compliance mappings per spec section 9 (OWASP A05/A09, CWE-778/693, PCI 11.6.1
on REPORT-004). _build_finding deepcopies the template, injects the orphan
name and comma-joined affected headers via {name}/{headers} placeholders,
and appends the CDN caveat sentence when cdn_detected=True.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `ReportingCoherenceAnalyzer` class

**Files:**
- Modify: `corsair/analyzers/reporting.py` (append the class)
- Modify: `tests/test_reporting_coherence.py` (append classification + integration tests)

### Step 3.1: Write classification tests

- [ ] **Append the failing tests**

Append to `tests/test_reporting_coherence.py`:

```python
# ---------------------------------------------------------------------------
# ReportingCoherenceAnalyzer — classification (Layer 2 from spec)
# ---------------------------------------------------------------------------

from corsair.analyzers.reporting import ReportingCoherenceAnalyzer


def _make_analyzer(headers, url="https://example.com/"):
    return ReportingCoherenceAnalyzer(headers=headers, url=url)


def _ids(findings):
    """Return a sorted list of (severity, header) tuples for stable comparison."""
    return sorted([(f.severity.value, f.header) for f in findings])


class TestClassification:
    def test_ip_only_orphan_is_high(self):
        headers = {
            "content-type": "text/html",
            "integrity-policy": "endpoints=(missing-ip-ep)",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_ip_orphan_with_csp_referrer_collapses_to_single_high(self):
        headers = {
            "content-type": "text/html",
            "integrity-policy": "endpoints=(shared-orphan)",
            "content-security-policy": "default-src 'self'; report-to shared-orphan",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "Integrity-Policy" in findings[0].header
        assert "Content-Security-Policy" in findings[0].header

    def test_ip_orphan_with_legacy_only_definition_is_high(self):
        # IP does NOT fall back to Report-To, so legacy-only definition does
        # not rescue the IP reference.
        headers = {
            "content-type": "text/html",
            "report-to": '{"group": "legacy-only", "endpoints": [{"url": "https://r"}]}',
            "integrity-policy": "endpoints=(legacy-only)",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_csp_reference_to_legacy_only_is_low(self):
        # CSP CAN fall back to Report-To in Chromium, so this is a migration
        # gap, not a hard orphan.
        headers = {
            "content-type": "text/html",
            "report-to": '{"group": "legacy-grp", "endpoints": [{"url": "https://r"}]}',
            "content-security-policy": "default-src 'self'; report-to legacy-grp",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_csp_reference_to_undefined_name_is_medium(self):
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; report-to ghost",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_placeholder_in_report_only_downgraded_to_info(self):
        headers = {
            "content-type": "text/html",
            "content-security-policy-report-only": "default-src 'self'; report-to todo",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    def test_placeholder_in_enforcing_csp_stays_medium(self):
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; report-to todo",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_placeholder_in_integrity_policy_stays_high(self):
        headers = {
            "content-type": "text/html",
            "integrity-policy": "endpoints=(todo)",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_same_orphan_in_three_headers_collapses(self):
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; report-to ghost",
            "content-security-policy-report-only": "default-src 'self'; report-to ghost",
            "cross-origin-opener-policy": 'same-origin; report-to="ghost"',
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        h = findings[0].header
        assert "Content-Security-Policy" in h
        assert "Content-Security-Policy-Report-Only" in h
        assert "Cross-Origin-Opener-Policy" in h

    def test_two_distinct_orphans_emit_two_findings(self):
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; report-to ghost-a",
            "cross-origin-opener-policy": 'same-origin; report-to="ghost-b"',
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 2
        # Both MEDIUM, distinct names.
        names_in_descriptions = {f.description for f in findings}
        assert any("ghost-a" in d for d in names_in_descriptions)
        assert any("ghost-b" in d for d in names_in_descriptions)
```

- [ ] **Run tests to verify they fail**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestClassification -v`
Expected: FAIL with `ImportError: cannot import name 'ReportingCoherenceAnalyzer'`.

### Step 3.2: Implement the analyzer class

- [ ] **Append the class**

Append to `corsair/analyzers/reporting.py`:

```python
# ---------------------------------------------------------------------------
# Analyzer class
# ---------------------------------------------------------------------------

# Display-cased header names for the Finding.header field. Keep in sync with
# REFERENCE_HEADERS_* tuples above.
_DISPLAY_HEADER_NAMES: Dict[str, str] = {
    "content-security-policy": "Content-Security-Policy",
    "content-security-policy-report-only": "Content-Security-Policy-Report-Only",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-opener-policy-report-only": "Cross-Origin-Opener-Policy-Report-Only",
    "cross-origin-embedder-policy": "Cross-Origin-Embedder-Policy",
    "cross-origin-embedder-policy-report-only": "Cross-Origin-Embedder-Policy-Report-Only",
    "document-isolation-policy": "Document-Isolation-Policy",
    "nel": "NEL",
    "integrity-policy": "Integrity-Policy",
    "integrity-policy-report-only": "Integrity-Policy-Report-Only",
}

_REPORT_ONLY_HEADERS = frozenset({
    "content-security-policy-report-only",
    "cross-origin-opener-policy-report-only",
    "cross-origin-embedder-policy-report-only",
    "integrity-policy-report-only",
})


class ReportingCoherenceAnalyzer(BaseAnalyzer):
    """Cross-references reporting endpoint references against definitions.

    Restricts itself to navigation-style responses (HTML/XHTML/XML) to suppress
    SPA sub-resource false positives. Three findings per spec section 5:
    REPORT-001 (LOW migration), REPORT-002 (MEDIUM generic orphan), REPORT-004
    (HIGH Integrity-Policy orphan). One finding per orphan name; affected
    reference headers are listed in the header field and description.
    """

    HEADER_NAME = "Reporting-Endpoints"
    CATEGORY = HeaderCategory.REPORTING

    def analyze(self) -> List[Finding]:
        # Stage 1 — discriminator gate
        if not _is_navigation_response(self.headers):
            return []

        # Stage 2 — definitions
        modern_defs = _parse_reporting_endpoints(self._headers_lower.get("reporting-endpoints", ""))
        legacy_defs = _parse_report_to(self._headers_lower.get("report-to", ""))

        # Stage 3 — references → buckets
        ip_orphan_map, orphan_map, migration_map = self._collect_orphans(modern_defs, legacy_defs)

        if not (ip_orphan_map or orphan_map or migration_map):
            return []

        # Stage 4 — CDN detection
        cdn_detected = self._detect_cdn()

        # Stage 5 — finding emission
        return self._build_findings(ip_orphan_map, orphan_map, migration_map, cdn_detected)

    # ---- helpers -------------------------------------------------------

    def _collect_orphans(
        self, modern_defs: Set[str], legacy_defs: Set[str]
    ) -> tuple[Dict[str, List[str]], Dict[str, List[str]], Dict[str, List[str]]]:
        """Walk all reference headers and bucket each unresolved reference.

        Returns (ip_orphan_map, orphan_map, migration_map). Each dict maps
        orphan_name -> list of display-cased reference header names.
        """
        # Pass 1: collect every (name, header_lower) reference pair.
        refs: List[tuple[str, str]] = []  # (name, header_lower)

        for h in REFERENCE_HEADERS_CSP_STYLE:
            name = _extract_csp_report_to(self._headers_lower.get(h, ""))
            if name:
                refs.append((name, h))

        for h in REFERENCE_HEADERS_PARAM_STYLE:
            name = _extract_param_report_to(self._headers_lower.get(h, ""))
            if name:
                refs.append((name, h))

        for h in REFERENCE_HEADERS_NEL:
            name = _extract_nel_report_to(self._headers_lower.get(h, ""))
            if name:
                refs.append((name, h))

        for h in REFERENCE_HEADERS_INTEGRITY:
            for name in _extract_integrity_endpoints(self._headers_lower.get(h, "")):
                refs.append((name, h))

        # Pass 2: classify each name.
        # First, identify which names are referenced from any IP header AND not
        # in modern_defs — those are REPORT-004 candidates.
        ip_orphan_names: Set[str] = set()
        for name, h in refs:
            if h in REFERENCE_HEADERS_INTEGRITY and name not in modern_defs:
                ip_orphan_names.add(name)

        ip_orphan_map: Dict[str, List[str]] = {}
        orphan_map: Dict[str, List[str]] = {}
        migration_map: Dict[str, List[str]] = {}

        seen_per_name: Dict[str, Set[str]] = {}  # for dedup of (name, display_header)

        for name, h in refs:
            display = _DISPLAY_HEADER_NAMES.get(h, h)
            seen_headers = seen_per_name.setdefault(name, set())
            if display in seen_headers:
                continue
            seen_headers.add(display)

            if name in ip_orphan_names:
                ip_orphan_map.setdefault(name, []).append(display)
            elif name in modern_defs:
                continue  # resolved
            elif name in legacy_defs:
                migration_map.setdefault(name, []).append(display)
            else:
                orphan_map.setdefault(name, []).append(display)

        return ip_orphan_map, orphan_map, migration_map

    def _detect_cdn(self) -> bool:
        try:
            return bool(fingerprint_cdn(self.headers))
        except Exception as e:
            logger.debug(f"fingerprint_cdn raised: {e}")
            return False

    def _build_findings(
        self,
        ip_orphan_map: Dict[str, List[str]],
        orphan_map: Dict[str, List[str]],
        migration_map: Dict[str, List[str]],
        cdn_detected: bool,
    ) -> List[Finding]:
        out: List[Finding] = []

        for name, headers in ip_orphan_map.items():
            out.append(_build_finding(_REPORT_004_TEMPLATE, name, headers, cdn_detected))

        for name, headers in migration_map.items():
            out.append(_build_finding(_REPORT_001_TEMPLATE, name, headers, cdn_detected))

        for name, headers in orphan_map.items():
            f = _build_finding(_REPORT_002_TEMPLATE, name, headers, cdn_detected)
            # Placeholder downgrade: name is a known placeholder AND every
            # referencing header is a Report-Only variant -> INFO.
            if name in PLACEHOLDER_NAMES:
                referencing_lower = {h.lower() for h in headers}
                if referencing_lower.issubset(_REPORT_ONLY_HEADERS):
                    f.severity = Severity.INFO
            out.append(f)

        return out
```

- [ ] **Run classification tests to verify they pass**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestClassification -v`
Expected: PASS, 10/10 passing.

### Step 3.3: Write analyzer integration tests

- [ ] **Append the failing integration tests**

Append to `tests/test_reporting_coherence.py`:

```python
# ---------------------------------------------------------------------------
# Analyzer integration tests (Layer 3 from spec)
# ---------------------------------------------------------------------------

class TestAnalyzerIntegration:
    def test_healthy_site_no_findings(self):
        headers = {
            "content-type": "text/html",
            "reporting-endpoints": 'main="https://reports.example.com/main"',
            "content-security-policy": "default-src 'self'; report-to main",
        }
        findings = _make_analyzer(headers).analyze()
        assert findings == []

    def test_no_reporting_headers_no_findings(self):
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'",
        }
        findings = _make_analyzer(headers).analyze()
        assert findings == []

    def test_reporting_endpoints_defined_but_unreferenced_no_findings(self):
        headers = {
            "content-type": "text/html",
            "reporting-endpoints": 'main="https://r.example.com/r"',
        }
        findings = _make_analyzer(headers).analyze()
        assert findings == []

    def test_non_html_response_skipped_even_with_orphans(self):
        headers = {
            "content-type": "application/json",
            "content-security-policy": "default-src 'self'; report-to ghost",
        }
        findings = _make_analyzer(headers).analyze()
        assert findings == []

    def test_missing_content_type_runs_analyzer(self):
        headers = {
            "content-security-policy": "default-src 'self'; report-to ghost",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_walkthrough_example_emits_three_findings(self):
        # The §7 walkthrough from the spec.
        headers = {
            "content-type": "text/html; charset=utf-8",
            "reporting-endpoints": 'csp-endpoint="https://reports.example.com/csp"',
            "report-to": '{"group":"legacy-group","max_age":10886400,"endpoints":[{"url":"https://r.example.com"}]}',
            "content-security-policy": "default-src 'self'; report-to csp-endpoint",
            "content-security-policy-report-only": "default-src 'self'; report-to ghost-endpoint",
            "cross-origin-opener-policy": 'same-origin; report-to="legacy-group"',
            "cross-origin-embedder-policy": 'require-corp; report-to="ghost-endpoint"',
            "integrity-policy": "blocked-destinations=(script), endpoints=(missing-ip-endpoint)",
        }
        findings = _make_analyzer(headers).analyze()
        severities = sorted(f.severity for f in findings, key=lambda s: s.value)
        assert {f.severity for f in findings} == {Severity.HIGH, Severity.MEDIUM, Severity.LOW}
        assert len(findings) == 3
        # MEDIUM finding should list both CSP-RO and COEP.
        medium = next(f for f in findings if f.severity == Severity.MEDIUM)
        assert "Content-Security-Policy-Report-Only" in medium.header
        assert "Cross-Origin-Embedder-Policy" in medium.header

    def test_cdn_detected_appends_caveat(self, monkeypatch):
        from corsair.analyzers import reporting as mod
        monkeypatch.setattr(mod, "fingerprint_cdn", lambda _h: "cloudflare")
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; report-to ghost",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert "CDN" in findings[0].description or "edge" in findings[0].description

    def test_no_cdn_no_caveat(self, monkeypatch):
        from corsair.analyzers import reporting as mod
        monkeypatch.setattr(mod, "fingerprint_cdn", lambda _h: None)
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; report-to ghost",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert "CDN" not in findings[0].description

    def test_severity_unchanged_with_or_without_cdn(self, monkeypatch):
        from corsair.analyzers import reporting as mod
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; report-to ghost",
        }

        monkeypatch.setattr(mod, "fingerprint_cdn", lambda _h: None)
        sev_no = _make_analyzer(headers).analyze()[0].severity
        monkeypatch.setattr(mod, "fingerprint_cdn", lambda _h: "cloudflare")
        sev_yes = _make_analyzer(headers).analyze()[0].severity
        assert sev_no == sev_yes == Severity.MEDIUM

    def test_coop_ro_and_coep_ro_extracted(self):
        headers = {
            "content-type": "text/html",
            "cross-origin-opener-policy-report-only": 'same-origin; report-to="ghost-coop-ro"',
            "cross-origin-embedder-policy-report-only": 'require-corp; report-to="ghost-coep-ro"',
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 2
        names_in_descriptions = " ".join(f.description for f in findings)
        assert "ghost-coop-ro" in names_in_descriptions
        assert "ghost-coep-ro" in names_in_descriptions

    def test_malformed_report_to_does_not_crash(self):
        headers = {
            "content-type": "text/html",
            "report-to": "this is not valid json {{{",
            "content-security-policy": "default-src 'self'; report-to ghost",
        }
        # Should not raise; ghost remains an orphan.
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_malformed_reporting_endpoints_does_not_crash(self):
        headers = {
            "content-type": "text/html",
            "reporting-endpoints": "completely malformed structured field",
            "content-security-policy": "default-src 'self'; report-to ghost",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_fingerprint_cdn_raises_no_crash(self, monkeypatch):
        from corsair.analyzers import reporting as mod

        def boom(_h):
            raise RuntimeError("boom")

        monkeypatch.setattr(mod, "fingerprint_cdn", boom)
        headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; report-to ghost",
        }
        findings = _make_analyzer(headers).analyze()
        assert len(findings) == 1
        assert "CDN" not in findings[0].description
```

- [ ] **Run integration tests to verify they pass**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestAnalyzerIntegration -v`
Expected: PASS, 13/13 passing.

### Step 3.4: Run full file suite and commit Task 3

- [ ] **Run all reporting tests**

Run: `python3 -m pytest tests/test_reporting_coherence.py -v`
Expected: PASS, 72/72 passing (39 parsers + 10 templates+builder + 10 classification + 13 integration).

- [ ] **Commit Task 3**

```bash
git add corsair/analyzers/reporting.py tests/test_reporting_coherence.py
git commit -m "$(cat <<'EOF'
feat(reporting): add ReportingCoherenceAnalyzer class

5-stage analyze() implementation per spec section 6:
1. Discriminator gate (Content-Type allowlist) — short-circuits non-HTML
2. Definition pass — modern_defs + legacy_defs from Reporting-Endpoints + Report-To
3. Reference pass — walks 10 reference headers, buckets each unresolved name
   into ip_orphan_map (REPORT-004), orphan_map (REPORT-002), or
   migration_map (REPORT-001). IP-special-case absorbs cross-header
   references to the same name.
4. CDN detection — single fingerprint_cdn call, try/except guarded
5. Finding emission — one Finding per orphan name; placeholder downgrade
   to INFO for REPORT-002 when every referencing header is *-Report-Only

Classification + integration tests cover all severity branches, the
discriminator both directions, CDN caveat both directions, malformed
header inputs, and fingerprint_cdn failure handling.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Register in `ALL_ANALYZERS` + scanner-integration smoke

**Files:**
- Modify: `corsair/analyzers/__init__.py`
- Modify: `tests/test_reporting_coherence.py` (append scanner-integration smoke tests)

### Step 4.1: Write failing scanner-integration tests

- [ ] **Append the failing tests**

Append to `tests/test_reporting_coherence.py`:

```python
# ---------------------------------------------------------------------------
# Scanner-integration smoke (Layer 4 from spec)
# ---------------------------------------------------------------------------

from unittest.mock import patch

from corsair.analyzers import ALL_ANALYZERS, get_analyzer_names


class TestScannerIntegration:
    def test_analyzer_registered(self):
        assert "ReportingCoherenceAnalyzer" in get_analyzer_names()
        assert ReportingCoherenceAnalyzer in ALL_ANALYZERS

    def test_scanner_finds_orphan_in_csp(self):
        from corsair.scanner import HeadScanner

        # Mock httpx so the scan returns a deterministic header set with an
        # orphaned CSP report-to.
        scanner = HeadScanner(timeout=5)

        def fake_fetch(self, url):
            headers = {
                "content-type": "text/html",
                "content-security-policy": "default-src 'self'; report-to ghost-rt",
            }
            return (200, headers, url, None)

        with patch.object(HeadScanner, "_fetch_headers", fake_fetch):
            result = scanner.scan_target("https://example.com/")

        # Find the REPORT-002 finding.
        report_findings = [
            f for f in result.findings if f.category == HeaderCategory.REPORTING
        ]
        assert any(
            f.severity == Severity.MEDIUM and "ghost-rt" in f.description
            for f in report_findings
        )

    def test_scanner_clean_response_no_reporting_findings(self):
        from corsair.scanner import HeadScanner

        scanner = HeadScanner(timeout=5)

        def fake_fetch(self, url):
            headers = {
                "content-type": "text/html",
                "reporting-endpoints": 'main="https://reports.example.com/main"',
                "content-security-policy": "default-src 'self'; report-to main",
            }
            return (200, headers, url, None)

        with patch.object(HeadScanner, "_fetch_headers", fake_fetch):
            result = scanner.scan_target("https://example.com/")

        report_findings = [
            f for f in result.findings if f.category == HeaderCategory.REPORTING
        ]
        # No REPORT-* findings (the analyzer is silent on healthy sites).
        for f in report_findings:
            assert f.severity == Severity.PASS or "Reporting" not in f.title
```

- [ ] **Run tests to verify they fail**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestScannerIntegration -v`
Expected: FAIL — `ReportingCoherenceAnalyzer not in ALL_ANALYZERS`.

### Step 4.2: Register the analyzer

- [ ] **Modify `corsair/analyzers/__init__.py`**

Apply two edits:

**Edit A — add the import** (insert after the `cross_origin` import block, around line 36):

```python
from .cross_origin import (
    CrossOriginIsolationAnalyzer,
    OriginAgentClusterAnalyzer,
    DocumentPolicyAnalyzer,
)

# Reporting coherence (v0.5.4)
from .reporting import ReportingCoherenceAnalyzer
```

**Edit B — register in `ALL_ANALYZERS`** (insert after the `CookieAnalyzer` entry, before `AdditionalHeadersAnalyzer`):

```python
    # Cookie security
    CookieAnalyzer,
    # Reporting endpoint coherence (v0.5.4)
    ReportingCoherenceAnalyzer,
    # Additional headers (Server, X-Powered-By, etc.)
    AdditionalHeadersAnalyzer,
```

**Edit C — add to `__all__`**:

```python
    "CookieAnalyzer",
    "AdditionalHeadersAnalyzer",
    # Cross-origin isolation
    "CrossOriginIsolationAnalyzer",
    "OriginAgentClusterAnalyzer",
    "DocumentPolicyAnalyzer",
    # Reporting coherence
    "ReportingCoherenceAnalyzer",
    # Registry
    "ALL_ANALYZERS",
```

- [ ] **Run scanner-integration tests to verify they pass**

Run: `python3 -m pytest tests/test_reporting_coherence.py::TestScannerIntegration -v`
Expected: PASS, 3/3 passing.

### Step 4.3: Run the full test suite to catch regressions

- [ ] **Run all tests**

Run: `python3 -m pytest -v`
Expected: PASS — every previously-passing test still passes, 75 new tests added (72 from the reporting file + 3 scanner-integration). Numbers may vary if other tests change baseline counts; what matters: **zero failures, zero new errors**.

If the scanner-integration tests for cache/cors/fm regress because the new analyzer adds findings to fixture responses, update those fixtures to include `Content-Type: text/html` (so the discriminator runs) plus `Reporting-Endpoints` covering any references — or set non-HTML Content-Type to skip the analyzer entirely. Investigate before changing test logic.

- [ ] **Commit Task 4**

```bash
git add corsair/analyzers/__init__.py tests/test_reporting_coherence.py
git commit -m "$(cat <<'EOF'
feat(reporting): register ReportingCoherenceAnalyzer in ALL_ANALYZERS

Wires the new analyzer into the scanner pipeline. Runs in the standard
_analyze_headers() phase between CookieAnalyzer and AdditionalHeadersAnalyzer.
No scanner.py changes — the existing analyzer registry handles dispatch and
exception wrapping. Scanner-integration smoke tests confirm:
- Analyzer appears in get_analyzer_names()
- Scanner against a fixture with an orphaned CSP report-to emits a
  REPORT-002 MEDIUM finding
- Scanner against a clean fixture emits no REPORT-* findings

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: v0.5.4 release

**Files:**
- Modify: `corsair/__init__.py`
- Modify: `pyproject.toml`
- Modify: `README.md`

### Step 5.1: Bump version in `corsair/__init__.py`

- [ ] **Read the current version line**

Run: `grep '^__version__' corsair/__init__.py`
Expected: `__version__ = "0.5.3"`

- [ ] **Bump to 0.5.4**

Edit `corsair/__init__.py`:

```python
__version__ = "0.5.4"
```

(replace the `"0.5.3"` literal).

### Step 5.2: Bump version in `pyproject.toml`

- [ ] **Read the current version line**

Run: `grep '^version =' pyproject.toml`
Expected: `version = "0.5.3"`

- [ ] **Bump to 0.5.4**

Edit `pyproject.toml`:

```toml
version = "0.5.4"
```

### Step 5.3: Add v0.5.4 changelog entry to README

- [ ] **Locate the v0.5.3 changelog section**

Run: `grep -n '^## v0.5.3' README.md`
Expected: a single line number, e.g., `159:## v0.5.3 ...`

- [ ] **Insert v0.5.4 block immediately above the v0.5.3 section**

Edit `README.md` — insert above the `## v0.5.3` line:

```markdown
## v0.5.4 — Reporting-Endpoints Coherence Detection

**Released:** 2026-05-03

### New: Reporting-Endpoints Coherence Analyzer

Adds static-analysis detection of orphaned reporting endpoint references — names
referenced by policy headers (CSP, CSP-RO, COOP, COOP-RO, COEP, COEP-RO, DIP,
NEL, Integrity-Policy, Integrity-Policy-RO) but undefined in `Reporting-Endpoints`
or `Report-To`. Browsers silently discard reports for unresolved names, leaving
the site owner blind to security violations with no surface signal.

**Three findings:**

- **REPORT-001 (LOW)** — *Incomplete Migration to Modern Reporting API.* Name
  is defined in legacy `Report-To` but missing from modern `Reporting-Endpoints`.
  Chromium falls back to V0 for most policies — modern policies (Integrity-Policy)
  do not.
- **REPORT-002 (MEDIUM)** — *Orphaned Security Reporting Endpoint.* Name is
  referenced from a policy header but undefined anywhere. Browser silently
  discards every report.
- **REPORT-004 (HIGH)** — *Integrity-Policy Monitoring Failure.* `Integrity-Policy`
  references an undefined name. Special-cased because IP does **not** fall back
  to V0 `Report-To`, so the SRI monitoring pipeline is guaranteed to be broken.

**Implementation notes:**

- Pure static analysis. No new HTTP requests, no async, no new dependencies.
- Restricted to navigation-style responses (`text/html`, `application/xhtml+xml`,
  `application/xml`, `text/xml`) to suppress SPA sub-resource false positives.
- Appends a CDN caveat to findings when a CDN is fingerprinted on the response —
  reporting endpoints injected at the edge would not appear on a direct-origin scan.
- Placeholder names (`none`, `todo`, `dummy`, `test`, `placeholder`) referenced
  exclusively from `*-Report-Only` headers are downgraded to INFO.

```

(End the new block with one trailing blank line so the existing v0.5.3 section spacing is preserved.)

### Step 5.4: Verify and commit

- [ ] **Verify version bumps cohere**

Run: `python3 -c "import corsair; print(corsair.__version__)"`
Expected: `0.5.4`

Run: `grep '^version =' pyproject.toml`
Expected: `version = "0.5.4"`

- [ ] **Run the full test suite one final time**

Run: `python3 -m pytest -v`
Expected: PASS, no failures, no errors.

- [ ] **Commit the release**

```bash
git add corsair/__init__.py pyproject.toml README.md
git commit -m "$(cat <<'EOF'
release: v0.5.4 — Reporting-Endpoints Coherence Detection

Static analysis flagging orphaned reporting endpoint references across 10
policy headers (CSP/CSP-RO, COOP/COOP-RO, COEP/COEP-RO, DIP, NEL, IP/IP-RO)
against Reporting-Endpoints and Report-To definitions. Three severity tiers:
REPORT-001 (LOW migration gap), REPORT-002 (MEDIUM generic orphan),
REPORT-004 (HIGH Integrity-Policy orphan). Pure static analysis — no new
HTTP requests, no new dependencies.

Spec: docs/superpowers/specs/2026-05-03-reporting-endpoints-coherence-design.md
Plan: docs/superpowers/plans/2026-05-03-reporting-endpoints-coherence-plan.md

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Self-review checklist for the implementer

After all five tasks are committed, verify:

1. `python3 -m pytest -v` — full suite passes, zero failures, zero new errors.
2. `python3 -c "from corsair.analyzers import ReportingCoherenceAnalyzer; print('OK')"` — analyzer importable.
3. `python3 -c "from corsair.analyzers import ALL_ANALYZERS; print('ReportingCoherenceAnalyzer' in [c.__name__ for c in ALL_ANALYZERS])"` — registered.
4. `python3 -c "import corsair; print(corsair.__version__)"` — `0.5.4`.
5. `git log --oneline -6` — 5 atomic commits matching task structure plus any pre-existing.

After verification, the implementing controller invokes
`superpowers:finishing-a-development-branch` to merge or push the branch.
