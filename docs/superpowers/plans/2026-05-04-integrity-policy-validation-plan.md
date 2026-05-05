# Integrity-Policy Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Corsair v0.5.5 — a header-and-body-aware audit of `Integrity-Policy` and `Integrity-Policy-Report-Only` (RFC 9651 SF Dictionary, SRI §3.8). Five findings ship: IP-001 (header absent, LOW), IP-002 (Report-Only only, INFO), IP-003 (parse error / no destinations, LOW), IP-004 (`script` missing, LOW), IP-006 (enforcing IP + cross-origin scripts lacking `integrity`, HIGH). IP-005 is intentionally not added — REPORT-004 (v0.5.4) already owns orphaned `endpoints` references.

**Architecture:** New top-level subsystem `corsair/integrity_policy/` parallel to `corsair/cache/`, `corsair/cors/`, and `corsair/fetch_metadata/`. Five files: `__init__.py`, `parser.py`, `body.py`, `findings.py`, `auditor.py`. Two-stage flow: (1) static parse always runs and emits IP-001/002/003/004 or static PASS; (2) active body fetch runs only when `active=True` AND enforcing IP detected AND `script` in `blocked-destinations` AND HTML Content-Type — emits IP-006, IP-006 PASS, or IP-006 INCONCLUSIVE. New CLI flag `--ip-probe / --no-ip-probe` (default ON) plumbed through scanner.

**Tech Stack:** Python 3.9+, stdlib `re`, `copy`, `urllib.parse`; existing `httpx` (sync `httpx.Client.get` — no async needed for one body fetch); `pytest` and `pytest-httpx` (already test deps). No new external dependencies. `HeaderCategory.INTEGRITY` enum value will be added to `corsair/models.py` (does not yet exist).

**Spec:** `docs/superpowers/specs/2026-05-04-integrity-policy-validation-design.md`

---

## File Structure

| File | Action | Purpose |
|---|---|---|
| `corsair/models.py` | Modify | Add `HeaderCategory.INTEGRITY = "integrity"` enum value |
| `corsair/integrity_policy/__init__.py` | Create | Re-export `IntegrityPolicyAuditor` |
| `corsair/integrity_policy/parser.py` | Create | `_parse_integrity_policy`, `_is_html_response`, recognized-destinations constant |
| `corsair/integrity_policy/body.py` | Create | `_fetch_body` (sync httpx GET), `_extract_cross_origin_scripts`, `ONE_MEGABYTE` |
| `corsair/integrity_policy/findings.py` | Create | 5 templates + 3 PASS + 1 INCONCLUSIVE + `get_finding`, `build_ip_003_finding`, `build_ip_006_finding`, `build_ip_006_pass_finding`, `build_ip_006_inconclusive_finding` |
| `corsair/integrity_policy/auditor.py` | Create | `IntegrityPolicyAuditor` class; two-stage `audit()` |
| `tests/test_integrity_policy_parser.py` | Create | ~25 unit tests for parser + `_is_html_response` |
| `tests/test_integrity_policy_body.py` | Create | ~20 tests for `_fetch_body` (pytest-httpx mocks) + `_extract_cross_origin_scripts` |
| `tests/test_integrity_policy_auditor.py` | Create | ~25 auditor tests + 1 regression for v0.5.4 coexistence |
| `corsair/scanner.py` | Modify | Add `ip_probe` parameter; instantiate and call `IntegrityPolicyAuditor` after FM block |
| `corsair/cli.py` | Modify | Add `--ip-probe / --no-ip-probe` flag; plumb to `HeadScanner` |
| `corsair/__init__.py` | Modify | Bump `__version__` to `"0.5.5"` |
| `pyproject.toml` | Modify | Bump `version` to `"0.5.5"` |
| `README.md` | Modify | Add `### v0.5.5 — Integrity-Policy Validation` changelog entry |

**Tasks (6 total):**
1. `HeaderCategory.INTEGRITY` enum + `parser.py` (parse + HTML discriminator)
2. `body.py` (cross-origin script extraction + body fetch)
3. `findings.py` (5 finding templates + 3 PASS + 1 INCONCLUSIVE + builders)
4. `auditor.py` + `__init__.py` (two-stage `IntegrityPolicyAuditor`)
5. Scanner integration + CLI flag
6. v0.5.5 release commit (version bump + changelog)

---

## Task 1: Enum value + `parser.py`

**Files:**
- Modify: `corsair/models.py:35-53` (HeaderCategory enum)
- Create: `corsair/integrity_policy/parser.py`
- Create: `tests/test_integrity_policy_parser.py`

This task adds the enum value the design spec assumes exists, then implements the two pure-function parsers. No HTTP. No class instantiation. Strict TDD — every helper is test-first.

### Step 1.1: Add `HeaderCategory.INTEGRITY`

- [ ] **Inspect current `HeaderCategory` enum**

Run: `grep -n "HeaderCategory\|class HeaderCategory\|DEPRECATED" /Users/fevra/Apps/HeadScan/corsair/models.py | head -20`
Expected: Confirms enum exists at line 35 ending with `DEPRECATED = "deprecated"` around line 53.

- [ ] **Modify the enum to add INTEGRITY**

In `corsair/models.py`, locate the `HeaderCategory` enum (line 35-53) and add `INTEGRITY = "integrity"` after the `REPORTING` entry. The block becomes:

```python
class HeaderCategory(Enum):
    """
    Header categories for grouping and reporting.

    Organizes findings by security domain for easier analysis.
    """

    TRANSPORT = "transport"  # HSTS, upgrade-insecure-requests
    CONTENT = "content"  # CSP, X-Content-Type-Options
    FRAMING = "framing"  # X-Frame-Options, frame-ancestors
    ISOLATION = "isolation"  # COOP, COEP, CORP, Origin-Agent-Cluster
    PRIVACY = "privacy"  # Referrer-Policy, Client Hints
    PERMISSIONS = "permissions"  # Permissions-Policy (50+ features)
    CORS = "cors"  # CORS headers
    COOKIES = "cookies"  # Cookie security flags
    CACHING = "caching"  # Cache-Control security
    REPORTING = "reporting"  # NEL, Reporting-Endpoints, Report-To
    INTEGRITY = "integrity"  # Integrity-Policy, Integrity-Policy-Report-Only
    FINGERPRINT = "fingerprint"  # Server, X-Powered-By (info disclosure)
    DEPRECATED = "deprecated"  # HPKP, X-XSS-Protection, Expect-CT
```

- [ ] **Verify the enum value loads**

Run: `python3 -c "from corsair.models import HeaderCategory; print(HeaderCategory.INTEGRITY.value)"`
Expected: `integrity`

- [ ] **Run the existing test suite to confirm no regressions**

Run: `python3 -m pytest --ignore=tests/test_tls_auditor.py -q`
Expected: Same pass count as baseline (no new failures introduced by adding an enum value).

- [ ] **Commit**

```bash
git add corsair/models.py
git commit -m "$(cat <<'EOF'
feat(models): add HeaderCategory.INTEGRITY enum value

Prepares for v0.5.5 Integrity-Policy validation subsystem. New finding
templates IP-001/002/003/004/006 will categorize under INTEGRITY rather
than reusing CONTENT or REPORTING.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

### Step 1.2: Create `corsair/integrity_policy/` package directory

- [ ] **Create the package directory**

Run: `mkdir -p /Users/fevra/Apps/HeadScan/corsair/integrity_policy`

- [ ] **Create the empty `__init__.py` placeholder (will be filled in Task 4)**

Create `corsair/integrity_policy/__init__.py` containing exactly:

```python
"""Integrity-Policy validation subsystem (v0.5.5)."""
```

(Final exports added in Task 4 once the auditor exists.)

- [ ] **Verify package is importable**

Run: `python3 -c "import corsair.integrity_policy; print('OK')"`
Expected: `OK`

### Step 1.3: TDD `_parse_integrity_policy` — empty/whitespace inputs

- [ ] **Write the failing test file with the first three cases**

Create `tests/test_integrity_policy_parser.py`:

```python
"""Tests for corsair.integrity_policy.parser."""

import pytest

from corsair.integrity_policy.parser import (
    _is_html_response,
    _parse_integrity_policy,
)


# ---------------------------------------------------------------------------
# _parse_integrity_policy — empty / whitespace inputs
# ---------------------------------------------------------------------------

class TestParseEmptyInputs:
    def test_empty_string_returns_parse_error(self):
        result = _parse_integrity_policy("")
        assert result["parse_error"] is True
        assert result["blocked_destinations"] == []
        assert result["sources"] == ["inline"]
        assert result["endpoints"] == []

    def test_whitespace_only_returns_parse_error(self):
        result = _parse_integrity_policy("   ")
        assert result["parse_error"] is True
        assert result["blocked_destinations"] == []

    def test_garbage_input_returns_parse_error(self):
        result = _parse_integrity_policy("not_valid_sf!!!")
        assert result["parse_error"] is True
```

- [ ] **Run the tests to verify they fail with ImportError**

Run: `python3 -m pytest tests/test_integrity_policy_parser.py -v`
Expected: FAIL with `ImportError: cannot import name '_parse_integrity_policy'` (module does not exist yet).

- [ ] **Create `parser.py` with constants and a stub `_parse_integrity_policy`**

Create `corsair/integrity_policy/parser.py`:

```python
"""Parse Integrity-Policy / Integrity-Policy-Report-Only header values.

RFC 9651 Structured Fields Dictionary; SRI §3.8.
"""

import re
from typing import Dict, List


# Recognized destination tokens per SRI §3.8.
RECOGNIZED_DESTINATIONS = frozenset({"script", "style"})

# HTML-class Content-Type values that justify a body GET for IP-006.
HTML_CONTENT_TYPES = frozenset({
    "text/html",
    "application/xhtml+xml",
    "application/xml",
    "text/xml",
})

# Matches one SF dictionary member: <key>=(<inner-list>)
# Examples matched: 'blocked-destinations=(script style)', 'endpoints=(sri)'.
# Whitespace permitted around '=' and inside parens. Unknown SF dict keys are
# silently dropped in the consumer per RFC 9651 forward-compatibility rules.
_SF_DICT_MEMBER_RE = re.compile(
    r"(?:^|,)\s*([\w][\w\-]*)\s*=\s*\(([^)]*)\)",
    re.IGNORECASE,
)


def _parse_integrity_policy(value: str) -> Dict:
    """Parse an Integrity-Policy or IP-Report-Only header value.

    Returns a dict with keys:
      - blocked_destinations: list[str] — lowercased tokens (recognized or unknown)
      - sources: list[str] — lowercased tokens; defaults to ['inline'] per SRI §3.8
      - endpoints: list[str] — lowercased tokens
      - parse_error: bool — True if no SF dict members were found at all
    """
    parsed = {
        "blocked_destinations": [],
        "sources": ["inline"],  # SRI §3.8 default
        "endpoints": [],
        "parse_error": False,
    }
    if not value or not value.strip():
        parsed["parse_error"] = True
        return parsed

    members = list(_SF_DICT_MEMBER_RE.finditer(value))
    if not members:
        parsed["parse_error"] = True
        return parsed

    sources_seen = False
    for m in members:
        key = m.group(1).strip().lower()
        inner = m.group(2).strip()
        tokens = [t.strip().lower() for t in inner.split() if t.strip()]
        if key == "blocked-destinations":
            parsed["blocked_destinations"] = tokens
        elif key == "sources":
            parsed["sources"] = tokens
            sources_seen = True
        elif key == "endpoints":
            parsed["endpoints"] = tokens
        # Unknown dict keys silently dropped (RFC 9651 forward compat).

    if not sources_seen:
        parsed["sources"] = ["inline"]
    return parsed


def _is_html_response(headers: Dict[str, str]) -> bool:
    """Return True iff the Content-Type indicates an HTML-class document.

    Empty / missing Content-Type returns False — stricter than reporting.py
    because body fetching costs a round-trip; only do it when the server
    explicitly advertises HTML.
    """
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v or ""
            break
    if not ct:
        return False
    base = ct.split(";", 1)[0].strip().lower()
    return base in HTML_CONTENT_TYPES
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_parser.py::TestParseEmptyInputs -v`
Expected: PASS, 3/3 passing.

### Step 1.4: TDD valid-grammar parsing

- [ ] **Append valid-grammar tests**

Append to `tests/test_integrity_policy_parser.py`:

```python
# ---------------------------------------------------------------------------
# _parse_integrity_policy — valid grammars
# ---------------------------------------------------------------------------

class TestParseValidGrammars:
    def test_blocked_destinations_only(self):
        result = _parse_integrity_policy("blocked-destinations=(script)")
        assert result["parse_error"] is False
        assert result["blocked_destinations"] == ["script"]
        assert result["sources"] == ["inline"]
        assert result["endpoints"] == []

    def test_blocked_destinations_two_tokens(self):
        result = _parse_integrity_policy("blocked-destinations=(script style)")
        assert result["blocked_destinations"] == ["script", "style"]

    def test_blocked_destinations_with_endpoints(self):
        result = _parse_integrity_policy(
            "blocked-destinations=(script), endpoints=(sri)"
        )
        assert result["blocked_destinations"] == ["script"]
        assert result["endpoints"] == ["sri"]

    def test_explicit_sources_inline(self):
        result = _parse_integrity_policy(
            "blocked-destinations=(script), sources=(inline)"
        )
        assert result["sources"] == ["inline"]

    def test_all_three_keys_present(self):
        result = _parse_integrity_policy(
            "blocked-destinations=(script style), sources=(inline), endpoints=(sri main)"
        )
        assert result["blocked_destinations"] == ["script", "style"]
        assert result["sources"] == ["inline"]
        assert result["endpoints"] == ["sri", "main"]

    def test_multiple_endpoint_tokens(self):
        result = _parse_integrity_policy(
            "blocked-destinations=(script), endpoints=(ep1 ep2 ep3)"
        )
        assert result["endpoints"] == ["ep1", "ep2", "ep3"]

    def test_keys_in_any_order(self):
        result = _parse_integrity_policy(
            "endpoints=(sri), blocked-destinations=(script)"
        )
        assert result["blocked_destinations"] == ["script"]
        assert result["endpoints"] == ["sri"]

    def test_trailing_comma_does_not_break_parse(self):
        result = _parse_integrity_policy("blocked-destinations=(script),")
        assert result["parse_error"] is False
        assert result["blocked_destinations"] == ["script"]
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_parser.py::TestParseValidGrammars -v`
Expected: PASS, 8/8 passing.

### Step 1.5: TDD whitespace handling

- [ ] **Append whitespace tests**

Append to `tests/test_integrity_policy_parser.py`:

```python
# ---------------------------------------------------------------------------
# _parse_integrity_policy — whitespace tolerance
# ---------------------------------------------------------------------------

class TestParseWhitespace:
    def test_inner_whitespace_around_token(self):
        result = _parse_integrity_policy("blocked-destinations=( script )")
        assert result["blocked_destinations"] == ["script"]

    def test_whitespace_around_equals(self):
        result = _parse_integrity_policy("blocked-destinations =(script)")
        assert result["blocked_destinations"] == ["script"]

    def test_leading_trailing_whitespace_on_value(self):
        result = _parse_integrity_policy("   blocked-destinations=(script)   ")
        assert result["blocked_destinations"] == ["script"]
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_parser.py::TestParseWhitespace -v`
Expected: PASS, 3/3 passing. (The current regex already tolerates these — if any fail, refine the regex.)

### Step 1.6: TDD empty / missing destinations

- [ ] **Append empty-destinations tests**

Append to `tests/test_integrity_policy_parser.py`:

```python
# ---------------------------------------------------------------------------
# _parse_integrity_policy — empty / missing destinations
# ---------------------------------------------------------------------------

class TestParseEmptyDestinations:
    def test_empty_inner_list(self):
        result = _parse_integrity_policy("blocked-destinations=()")
        assert result["parse_error"] is False
        assert result["blocked_destinations"] == []

    def test_missing_blocked_destinations_key(self):
        # Only sources= present; no blocked-destinations.
        result = _parse_integrity_policy("sources=(inline)")
        assert result["parse_error"] is False
        assert result["blocked_destinations"] == []
        assert result["sources"] == ["inline"]
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_parser.py::TestParseEmptyDestinations -v`
Expected: PASS, 2/2 passing.

### Step 1.7: TDD unknown-token handling

- [ ] **Append unknown-token tests**

Append to `tests/test_integrity_policy_parser.py`:

```python
# ---------------------------------------------------------------------------
# _parse_integrity_policy — unknown tokens
# ---------------------------------------------------------------------------

class TestParseUnknownTokens:
    def test_all_unknown_tokens(self):
        # 'scripts' is plural, 'foo' is unknown — both retained as raw tokens.
        # Auditor decides what to do (this is a parse-only function).
        result = _parse_integrity_policy("blocked-destinations=(scripts foo)")
        assert result["parse_error"] is False
        assert result["blocked_destinations"] == ["scripts", "foo"]

    def test_recognized_plus_unknown_tokens(self):
        result = _parse_integrity_policy(
            "blocked-destinations=(script futureKind)"
        )
        assert result["parse_error"] is False
        assert "script" in result["blocked_destinations"]
        assert "futurekind" in result["blocked_destinations"]
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_parser.py::TestParseUnknownTokens -v`
Expected: PASS, 2/2 passing.

### Step 1.8: TDD malformed input

- [ ] **Append malformed-input tests**

Append to `tests/test_integrity_policy_parser.py`:

```python
# ---------------------------------------------------------------------------
# _parse_integrity_policy — malformed inputs
# ---------------------------------------------------------------------------

class TestParseMalformed:
    def test_unmatched_open_paren(self):
        # No closing paren means the regex finds zero members.
        result = _parse_integrity_policy("blocked-destinations=(script")
        assert result["parse_error"] is True

    def test_no_sf_dict_members_at_all(self):
        result = _parse_integrity_policy("totally_random_content_no_equals_no_parens")
        assert result["parse_error"] is True
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_parser.py::TestParseMalformed -v`
Expected: PASS, 2/2 passing.

### Step 1.9: TDD case normalization

- [ ] **Append case-normalization tests**

Append to `tests/test_integrity_policy_parser.py`:

```python
# ---------------------------------------------------------------------------
# _parse_integrity_policy — case normalization
# ---------------------------------------------------------------------------

class TestParseCaseNormalization:
    def test_uppercase_tokens_lowercased(self):
        result = _parse_integrity_policy("BLOCKED-DESTINATIONS=(SCRIPT)")
        assert result["blocked_destinations"] == ["script"]

    def test_mixed_case_keys_normalized(self):
        result = _parse_integrity_policy(
            "Blocked-Destinations=(Script), Endpoints=(SRI)"
        )
        assert result["blocked_destinations"] == ["script"]
        assert result["endpoints"] == ["sri"]
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_parser.py::TestParseCaseNormalization -v`
Expected: PASS, 2/2 passing.

### Step 1.10: TDD `sources` default

- [ ] **Append sources-default tests**

Append to `tests/test_integrity_policy_parser.py`:

```python
# ---------------------------------------------------------------------------
# _parse_integrity_policy — sources default
# ---------------------------------------------------------------------------

class TestSourcesDefault:
    def test_sources_omitted_defaults_to_inline(self):
        # SRI §3.8: missing 'sources' key implies sources=(inline).
        result = _parse_integrity_policy("blocked-destinations=(script)")
        assert result["sources"] == ["inline"]

    def test_sources_explicit_inline_returns_inline(self):
        result = _parse_integrity_policy(
            "blocked-destinations=(script), sources=(inline)"
        )
        assert result["sources"] == ["inline"]
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_parser.py::TestSourcesDefault -v`
Expected: PASS, 2/2 passing.

### Step 1.11: TDD `_is_html_response`

- [ ] **Append `_is_html_response` tests**

Append to `tests/test_integrity_policy_parser.py`:

```python
# ---------------------------------------------------------------------------
# _is_html_response
# ---------------------------------------------------------------------------

class TestIsHtmlResponse:
    def test_text_html(self):
        assert _is_html_response({"Content-Type": "text/html"}) is True

    def test_xhtml_xml(self):
        assert _is_html_response({"Content-Type": "application/xhtml+xml"}) is True

    def test_application_xml(self):
        assert _is_html_response({"Content-Type": "application/xml"}) is True

    def test_text_xml(self):
        assert _is_html_response({"Content-Type": "text/xml"}) is True

    def test_text_html_with_charset(self):
        assert _is_html_response({"Content-Type": "text/html; charset=utf-8"}) is True

    def test_application_json_returns_false(self):
        assert _is_html_response({"Content-Type": "application/json"}) is False

    def test_missing_content_type_returns_false(self):
        assert _is_html_response({}) is False

    def test_empty_content_type_returns_false(self):
        assert _is_html_response({"Content-Type": ""}) is False

    def test_lowercase_header_key(self):
        # httpx normalizes to lowercase, but be defensive.
        assert _is_html_response({"content-type": "text/html"}) is True
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_parser.py::TestIsHtmlResponse -v`
Expected: PASS, 9/9 passing.

### Step 1.12: Run the full parser test file

- [ ] **Confirm the full file passes**

Run: `python3 -m pytest tests/test_integrity_policy_parser.py -v`
Expected: PASS, ~33 tests (3 + 8 + 3 + 2 + 2 + 2 + 2 + 2 + 9). Adjust the spec target of "~25" — 33 covers more whitespace and HTML-CT cases than originally projected, which is fine and improves coverage.

### Step 1.13: Commit Task 1

- [ ] **Stage and commit**

```bash
git add corsair/integrity_policy/__init__.py corsair/integrity_policy/parser.py tests/test_integrity_policy_parser.py
git commit -m "$(cat <<'EOF'
feat(integrity-policy): add parser and HTML response discriminator

Pure-function header-value parser for Integrity-Policy and
Integrity-Policy-Report-Only (RFC 9651 SF Dictionary; SRI §3.8). Returns a
dict with blocked_destinations, sources (default ['inline']), endpoints,
and parse_error. Tolerates whitespace and case; silently drops unknown
SF dict keys per RFC 9651 forward-compatibility rules.

_is_html_response() discriminates HTML-class Content-Types so the auditor
only spends a body GET when the server explicitly advertises HTML.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: `body.py` — body fetch + cross-origin script extraction

**Files:**
- Create: `corsair/integrity_policy/body.py`
- Create: `tests/test_integrity_policy_body.py`

This task implements the Stage-2 helpers: a sync `httpx.Client.get` body fetch (capped at 1 MB) and a regex-based cross-origin script extractor. No class plumbing yet.

### Step 2.1: TDD `_extract_cross_origin_scripts` — basic cross-origin detection

- [ ] **Write the failing test file with the first set of cases**

Create `tests/test_integrity_policy_body.py`:

```python
"""Tests for corsair.integrity_policy.body."""

import pytest

from corsair.integrity_policy.body import (
    ONE_MEGABYTE,
    _extract_cross_origin_scripts,
    _fetch_body,
)


# ---------------------------------------------------------------------------
# _extract_cross_origin_scripts — basic cross-origin detection
# ---------------------------------------------------------------------------

DOC_URL = "https://www.example.com/"


class TestExtractBasicCrossOrigin:
    def test_different_host_flagged(self):
        body = '<script src="https://cdn.example.com/x.js"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == [
            "https://cdn.example.com/x.js"
        ]

    def test_different_port_flagged(self):
        body = '<script src="https://www.example.com:8080/x.js"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == [
            "https://www.example.com:8080/x.js"
        ]

    def test_different_scheme_flagged(self):
        body = '<script src="http://www.example.com/x.js"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == [
            "http://www.example.com/x.js"
        ]

    def test_mixed_case_host_flagged(self):
        # Hostname compared case-insensitively per URL standard.
        body = '<script src="https://CDN.Example.com/x.js"></script>'
        result = _extract_cross_origin_scripts(body, DOC_URL)
        assert len(result) == 1

    def test_ipv4_vs_hostname(self):
        body = '<script src="https://93.184.216.34/x.js"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == [
            "https://93.184.216.34/x.js"
        ]
```

- [ ] **Run tests to verify they fail**

Run: `python3 -m pytest tests/test_integrity_policy_body.py::TestExtractBasicCrossOrigin -v`
Expected: FAIL with `ImportError: cannot import name '_extract_cross_origin_scripts'`.

- [ ] **Create `body.py` with `_extract_cross_origin_scripts` and `ONE_MEGABYTE`**

Create `corsair/integrity_policy/body.py`:

```python
"""Body fetch + cross-origin script extraction for Integrity-Policy IP-006.

Sync httpx GET capped at 1 MB; regex-based <script> tag scan against an
exact (scheme, host, port) origin tuple.
"""

import logging
import re
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

import httpx


logger = logging.getLogger(__name__)


ONE_MEGABYTE = 1024 * 1024  # body cap


# Default ports per scheme — applied when port is omitted.
_DEFAULT_PORTS = {"http": 80, "https": 443}


# Match opening <script ...> tag (NOT closing </script>). DOTALL so multi-line
# tags match. Capture inner attributes as group 1.
_SCRIPT_TAG_RE = re.compile(
    r"<script\b([^>]*?)>",
    re.IGNORECASE | re.DOTALL,
)

# Attribute extractors. Independent regexes — order-agnostic within the tag.
_SRC_ATTR_RE = re.compile(
    r"""\bsrc\s*=\s*(?P<q>["'])(?P<val>.*?)(?P=q)""",
    re.IGNORECASE | re.DOTALL,
)
_INTEGRITY_ATTR_RE = re.compile(
    r"""\bintegrity\s*=\s*(?P<q>["'])(?P<val>.*?)(?P=q)""",
    re.IGNORECASE | re.DOTALL,
)


def _origin_tuple(url: str) -> Optional[Tuple[str, str, int]]:
    """Return (scheme, host, port) tuple for the URL, or None on failure."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        return None
    port = parts.port if parts.port is not None else _DEFAULT_PORTS.get(scheme, 0)
    return (scheme, host, port)


def _resolve_src(src: str, doc_url: str) -> Optional[str]:
    """Resolve src against doc_url. Skip data:, javascript:, blob:, empty."""
    if not src:
        return None
    s = src.strip()
    if not s:
        return None
    lower = s.lower()
    if lower.startswith(("data:", "javascript:", "blob:", "about:", "mailto:")):
        return None
    # Protocol-relative: //host/path -> resolve scheme from doc_url.
    if s.startswith("//"):
        doc_origin = _origin_tuple(doc_url)
        if doc_origin is None:
            return None
        return f"{doc_origin[0]}:{s}"
    # Absolute URL: keep as-is.
    if "://" in s:
        return s
    # Relative URL: same-origin by definition; caller treats None as same-origin.
    return None


def _extract_cross_origin_scripts(body: str, doc_url: str) -> List[str]:
    """Return cross-origin script src URLs that lack an integrity attribute.

    Cross-origin = different (scheme, host, port) from doc_url. Subdomains are
    cross-origin (exact tuple match, not eTLD+1).

    False positives accepted: HTML-comment-wrapped scripts and <noscript>
    subtree scripts are matched by the regex. Documented in the IP-006 finding.
    """
    if not body:
        return []
    doc_origin = _origin_tuple(doc_url)
    if doc_origin is None:
        return []

    flagged: List[str] = []
    for tag_match in _SCRIPT_TAG_RE.finditer(body):
        attrs = tag_match.group(1)
        src_match = _SRC_ATTR_RE.search(attrs)
        if src_match is None:
            continue
        raw_src = src_match.group("val")
        resolved = _resolve_src(raw_src, doc_url)
        if resolved is None:
            continue
        script_origin = _origin_tuple(resolved)
        if script_origin is None or script_origin == doc_origin:
            continue
        # Cross-origin script. Flag if no integrity attribute.
        if _INTEGRITY_ATTR_RE.search(attrs) is None:
            flagged.append(resolved)
    return flagged


def _fetch_body(
    url: str, timeout: int, user_agent: str
) -> Tuple[str, Optional[str]]:
    """GET url with the supplied User-Agent. Return (body_text, error_or_None).

    Honors timeout. Caps body at 1 MB (truncates the rest). Treats non-2xx
    as a soft failure: returns ("", "HTTP <status>"). Network exceptions
    return ("", "<exception class>: <message>").
    """
    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            verify=True,
        ) as client:
            response = client.get(
                url,
                headers={"User-Agent": user_agent, "Accept": "text/html, */*"},
            )
    except httpx.TimeoutException:
        return ("", "Request timeout")
    except httpx.ConnectError as e:
        return ("", f"Connection error: {e}")
    except httpx.TooManyRedirects:
        return ("", "Too many redirects")
    except Exception as e:  # broad: TLS handshake, brotli decode, etc.
        return ("", f"{type(e).__name__}: {e}")

    if not (200 <= response.status_code < 300):
        return ("", f"HTTP {response.status_code}")

    raw = response.content or b""
    truncated = raw[:ONE_MEGABYTE]
    try:
        body_text = truncated.decode(response.encoding or "utf-8", errors="replace")
    except (LookupError, TypeError):
        body_text = truncated.decode("utf-8", errors="replace")
    return (body_text, None)
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_body.py::TestExtractBasicCrossOrigin -v`
Expected: PASS, 5/5 passing.

### Step 2.2: TDD same-origin skip cases

- [ ] **Append same-origin tests**

Append to `tests/test_integrity_policy_body.py`:

```python
# ---------------------------------------------------------------------------
# _extract_cross_origin_scripts — same-origin skip
# ---------------------------------------------------------------------------

class TestExtractSameOriginSkip:
    def test_exact_match_url_skipped(self):
        body = '<script src="https://www.example.com/x.js"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_root_relative_skipped(self):
        body = '<script src="/js/app.js"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_pure_relative_skipped(self):
        body = '<script src="js/app.js"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_explicit_default_port_treated_same_origin(self):
        # https://x:443/ == https://x/
        body = '<script src="https://www.example.com:443/x.js"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_body.py::TestExtractSameOriginSkip -v`
Expected: PASS, 4/4 passing.

### Step 2.3: TDD protocol-relative URLs

- [ ] **Append protocol-relative tests**

Append to `tests/test_integrity_policy_body.py`:

```python
# ---------------------------------------------------------------------------
# _extract_cross_origin_scripts — protocol-relative URLs
# ---------------------------------------------------------------------------

class TestExtractProtocolRelative:
    def test_protocol_relative_resolves_to_https_when_doc_https(self):
        body = '<script src="//cdn.com/x.js"></script>'
        result = _extract_cross_origin_scripts(body, DOC_URL)
        assert result == ["https://cdn.com/x.js"]

    def test_protocol_relative_resolves_to_http_when_doc_http(self):
        body = '<script src="//cdn.com/x.js"></script>'
        result = _extract_cross_origin_scripts(body, "http://www.example.com/")
        assert result == ["http://cdn.com/x.js"]
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_body.py::TestExtractProtocolRelative -v`
Expected: PASS, 2/2 passing.

### Step 2.4: TDD integrity-attribute presence

- [ ] **Append integrity-present tests**

Append to `tests/test_integrity_policy_body.py`:

```python
# ---------------------------------------------------------------------------
# _extract_cross_origin_scripts — integrity attribute present
# ---------------------------------------------------------------------------

class TestExtractIntegrityPresent:
    def test_integrity_after_src(self):
        body = (
            '<script src="https://cdn.com/x.js" '
            'integrity="sha384-abc" crossorigin="anonymous"></script>'
        )
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_integrity_before_src(self):
        body = (
            '<script integrity="sha384-abc" '
            'src="https://cdn.com/x.js" crossorigin="anonymous"></script>'
        )
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_integrity_with_whitespace_around_equals(self):
        body = '<script src="https://cdn.com/x.js" integrity = "sha384-abc"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_multiline_tag_with_integrity(self):
        body = (
            "<script\n"
            '  src="https://cdn.com/x.js"\n'
            '  integrity="sha384-abc"\n'
            "></script>"
        )
        assert _extract_cross_origin_scripts(body, DOC_URL) == []
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_body.py::TestExtractIntegrityPresent -v`
Expected: PASS, 4/4 passing.

### Step 2.5: TDD multiple-script bodies

- [ ] **Append multiple-script tests**

Append to `tests/test_integrity_policy_body.py`:

```python
# ---------------------------------------------------------------------------
# _extract_cross_origin_scripts — multiple scripts in body
# ---------------------------------------------------------------------------

class TestExtractMultipleScripts:
    def test_mixed_covered_and_uncovered(self):
        body = (
            '<script src="https://cdn1.com/a.js" integrity="sha384-aaa"></script>'
            '<script src="https://cdn2.com/b.js"></script>'
            '<script src="/local.js"></script>'
            '<script src="https://cdn3.com/c.js"></script>'
        )
        result = _extract_cross_origin_scripts(body, DOC_URL)
        assert result == ["https://cdn2.com/b.js", "https://cdn3.com/c.js"]

    def test_all_covered_returns_empty(self):
        body = (
            '<script src="https://cdn1.com/a.js" integrity="sha384-aaa"></script>'
            '<script src="https://cdn2.com/b.js" integrity="sha384-bbb"></script>'
        )
        assert _extract_cross_origin_scripts(body, DOC_URL) == []
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_body.py::TestExtractMultipleScripts -v`
Expected: PASS, 2/2 passing.

### Step 2.6: TDD non-fetch URL schemes

- [ ] **Append URL-scheme-skip tests**

Append to `tests/test_integrity_policy_body.py`:

```python
# ---------------------------------------------------------------------------
# _extract_cross_origin_scripts — non-fetch schemes
# ---------------------------------------------------------------------------

class TestExtractSpecialSchemes:
    def test_data_url_skipped(self):
        body = '<script src="data:text/javascript,alert(1)"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_javascript_url_skipped(self):
        body = '<script src="javascript:void(0)"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_blob_url_skipped(self):
        body = '<script src="blob:https://www.example.com/abc"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_empty_src_skipped(self):
        body = '<script src=""></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_body.py::TestExtractSpecialSchemes -v`
Expected: PASS, 4/4 passing.

### Step 2.7: TDD edge bodies (no scripts, comments, noscript)

- [ ] **Append edge-body tests**

Append to `tests/test_integrity_policy_body.py`:

```python
# ---------------------------------------------------------------------------
# _extract_cross_origin_scripts — edge bodies
# ---------------------------------------------------------------------------

class TestExtractEdgeBodies:
    def test_empty_body_returns_empty(self):
        assert _extract_cross_origin_scripts("", DOC_URL) == []

    def test_body_with_no_script_tags(self):
        body = "<html><head><title>x</title></head><body><p>hi</p></body></html>"
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_html_comment_documented_false_positive(self):
        # Documented limitation per spec §5.4: regex still matches scripts
        # inside HTML comments. Lock this behavior into the test suite so
        # any future change is intentional.
        body = '<!-- <script src="https://cdn.com/x.js"></script> -->'
        result = _extract_cross_origin_scripts(body, DOC_URL)
        assert result == ["https://cdn.com/x.js"]

    def test_noscript_subtree_documented_false_positive(self):
        body = (
            "<noscript>"
            '<script src="https://cdn.com/x.js"></script>'
            "</noscript>"
        )
        result = _extract_cross_origin_scripts(body, DOC_URL)
        assert result == ["https://cdn.com/x.js"]

    def test_inline_script_with_no_src_skipped(self):
        body = "<script>alert(1)</script>"
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_self_closing_xhtml_script_matched(self):
        body = '<script src="https://cdn.com/x.js"/>'
        result = _extract_cross_origin_scripts(body, DOC_URL)
        assert result == ["https://cdn.com/x.js"]
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_body.py::TestExtractEdgeBodies -v`
Expected: PASS, 6/6 passing.

### Step 2.8: TDD `_fetch_body` — happy path with pytest-httpx

- [ ] **Append fetch-body 200-OK test**

Append to `tests/test_integrity_policy_body.py`:

```python
# ---------------------------------------------------------------------------
# _fetch_body — pytest-httpx mocked HTTP
# ---------------------------------------------------------------------------

class TestFetchBody:
    def test_200_ok_returns_body_no_error(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text="<html><body>hi</body></html>",
            headers={"Content-Type": "text/html"},
        )
        body, error = _fetch_body("https://example.com/", 10, "TestUA/1.0")
        assert error is None
        assert "hi" in body
```

- [ ] **Run test to verify it passes**

Run: `python3 -m pytest tests/test_integrity_policy_body.py::TestFetchBody::test_200_ok_returns_body_no_error -v`
Expected: PASS, 1/1.

### Step 2.9: TDD `_fetch_body` — non-2xx soft failures

- [ ] **Append non-2xx tests**

Append inside `class TestFetchBody`:

```python
    def test_404_returns_soft_failure(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=404,
            text="not found",
        )
        body, error = _fetch_body("https://example.com/", 10, "TestUA/1.0")
        assert body == ""
        assert error == "HTTP 404"

    def test_500_returns_soft_failure(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=500,
            text="server error",
        )
        body, error = _fetch_body("https://example.com/", 10, "TestUA/1.0")
        assert body == ""
        assert error == "HTTP 500"
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_body.py::TestFetchBody -v`
Expected: PASS, 3/3 (200, 404, 500).

### Step 2.10: TDD `_fetch_body` — timeout

- [ ] **Append timeout test**

Append inside `class TestFetchBody`:

```python
    def test_timeout_returns_request_timeout(self, httpx_mock):
        import httpx as _httpx
        httpx_mock.add_exception(_httpx.ReadTimeout("read timeout"))
        body, error = _fetch_body("https://example.com/", 1, "TestUA/1.0")
        assert body == ""
        assert error == "Request timeout"
```

- [ ] **Run test to verify it passes**

Run: `python3 -m pytest tests/test_integrity_policy_body.py::TestFetchBody::test_timeout_returns_request_timeout -v`
Expected: PASS, 1/1.

### Step 2.11: TDD `_fetch_body` — body cap at 1 MB

- [ ] **Append body-cap test**

Append inside `class TestFetchBody`:

```python
    def test_body_truncated_at_one_megabyte(self, httpx_mock):
        big = "A" * (ONE_MEGABYTE + 1024)  # 1 MB + 1 KB
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text=big,
            headers={"Content-Type": "text/html"},
        )
        body, error = _fetch_body("https://example.com/", 10, "TestUA/1.0")
        assert error is None
        assert len(body) == ONE_MEGABYTE
```

- [ ] **Run test to verify it passes**

Run: `python3 -m pytest tests/test_integrity_policy_body.py::TestFetchBody::test_body_truncated_at_one_megabyte -v`
Expected: PASS, 1/1.

### Step 2.12: Run the full body test file

- [ ] **Confirm full file passes**

Run: `python3 -m pytest tests/test_integrity_policy_body.py -v`
Expected: PASS, ~28 tests across all classes.

### Step 2.13: Commit Task 2

- [ ] **Stage and commit**

```bash
git add corsair/integrity_policy/body.py tests/test_integrity_policy_body.py
git commit -m "$(cat <<'EOF'
feat(integrity-policy): add body fetch and cross-origin script extraction

_fetch_body() does a sync httpx GET capped at 1 MB. Soft-fails non-2xx
to ('', 'HTTP <status>'). Network exceptions return ('', '<class>: <msg>').

_extract_cross_origin_scripts() compares (scheme, host, port) tuples
exactly — subdomains are cross-origin. Resolves protocol-relative URLs
against the document scheme. Skips data:, javascript:, blob:.

Documented false positives in HTML comments and <noscript> subtree are
locked into the test suite so any future change is intentional.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `findings.py` — templates and builders

**Files:**
- Create: `corsair/integrity_policy/findings.py`

This task implements the five finding templates (IP-001/002/003/004/006), three PASS variants (static PASS, IP-006 PASS), one INCONCLUSIVE variant, and the public builders. Mirrors `corsair/fetch_metadata/findings.py` structure: DRY `_compliance` and `_cwe` constructors, module-level constants, `get_finding(id)` returning `copy.deepcopy(template)`, and per-finding builders that substitute runtime context.

### Step 3.1: Create `findings.py` skeleton with DRY helpers and constants

- [ ] **Write the file skeleton**

Create `corsair/integrity_policy/findings.py`:

```python
"""Integrity-Policy finding templates, registry, and builders.

Mirrors corsair/fetch_metadata/findings.py. Public API:
  - get_finding(finding_id) -> Finding | None  (deepcopy of static template)
  - build_ip_003_finding(parsed_value, raw_value)
  - build_ip_006_finding(scripts, truncated)
  - build_ip_006_pass_finding(truncated)
  - build_ip_006_inconclusive_finding(error_reason)
"""

import copy
from typing import List, Optional

from ..models import (
    ComplianceMapping,
    CVECorrelation,
    Finding,
    HeaderCategory,
    Severity,
)


# ---------------------------------------------------------------------------
# DRY helpers
# ---------------------------------------------------------------------------

def _compliance(
    framework: str, req_id: str, req_name: str, status: str = "FAIL"
) -> ComplianceMapping:
    return ComplianceMapping(
        framework=framework,
        requirement_id=req_id,
        requirement_name=req_name,
        status=status,
    )


def _cwe(cwe_id: str, desc: str) -> CVECorrelation:
    return CVECorrelation(cve_id=cwe_id, cvss_score=0.0, description=desc)


# ---------------------------------------------------------------------------
# Compliance / CWE constants
# ---------------------------------------------------------------------------

_OWASP_A08 = _compliance(
    "OWASP_TOP_10_2021", "A08", "Software and Data Integrity Failures"
)
_NIST_SI_7 = _compliance(
    "NIST_SP_800_53", "SI-7", "Software, Firmware, and Information Integrity"
)
_PCI_6_4_3 = _compliance(
    "PCI_DSS_4_0", "6.4.3", "Manage all payment page scripts loaded in the browser"
)
_CWE_353 = _cwe("CWE-353", "Missing Support for Integrity Check")
_CWE_494 = _cwe("CWE-494", "Download of Code Without Integrity Check")
_CWE_829 = _cwe(
    "CWE-829", "Inclusion of Functionality from Untrusted Control Sphere"
)

_REFERENCE_URL = (
    "https://w3c.github.io/webappsec-subresource-integrity/"
    "#integrity-policy-section"
)
```

- [ ] **Verify the skeleton imports cleanly**

Run: `python3 -c "from corsair.integrity_policy import findings; print('OK')"`
Expected: `OK`

### Step 3.2: Add IP-001 template + `get_finding` registry

- [ ] **Append the IP-001 template and the registry function**

Append to `corsair/integrity_policy/findings.py`:

```python
# ---------------------------------------------------------------------------
# IP-001: Integrity-Policy header absent
# ---------------------------------------------------------------------------

_IP_001_TEMPLATE = Finding(
    header="Integrity-Policy",
    category=HeaderCategory.INTEGRITY,
    severity=Severity.LOW,
    title="Integrity-Policy header absent",
    description=(
        "Neither Integrity-Policy nor Integrity-Policy-Report-Only is set. The "
        "browser will not enforce any baseline requirement that subresources "
        "carry an integrity attribute, so a compromised CDN or third-party host "
        "can serve modified script/style without detection. Even sites that "
        "currently set integrity= on every <script> tag benefit from defining "
        "Integrity-Policy as a policy gate, because policy survives template "
        "regressions and partial deployments."
    ),
    current_value=None,
    recommended_value=(
        "Integrity-Policy: blocked-destinations=(script), endpoints=(default)"
    ),
    impact=(
        "Compromised third-party scripts can execute without browser intervention."
    ),
    recommendation=(
        "Define an Integrity-Policy header in Report-Only mode first to "
        "discover scripts lacking integrity, then upgrade to enforcing once "
        "all in-scope scripts carry sha384 integrity attributes."
    ),
    score_deduction=3,
    cve_correlations=[_CWE_353, _CWE_494],
    compliance_mappings=[_OWASP_A08, _NIST_SI_7, _PCI_6_4_3],
    reference_url=_REFERENCE_URL,
)


# ---------------------------------------------------------------------------
# Registry: static templates accessible via get_finding(finding_id)
# ---------------------------------------------------------------------------

_REGISTRY = {
    "IP-001": _IP_001_TEMPLATE,
}


def get_finding(finding_id: str) -> Optional[Finding]:
    """Return a deepcopy of the static template for a finding ID."""
    template = _REGISTRY.get(finding_id)
    if template is None:
        return None
    return copy.deepcopy(template)
```

- [ ] **Verify it loads and IP-001 has correct shape**

Run:
```bash
python3 -c "
from corsair.integrity_policy.findings import get_finding
from corsair.models import Severity, HeaderCategory
f = get_finding('IP-001')
assert f is not None
assert f.severity == Severity.LOW
assert f.category == HeaderCategory.INTEGRITY
assert f.score_deduction == 3
print('OK')
"
```
Expected: `OK`

### Step 3.3: Add IP-002 template (Report-Only present, enforcing absent)

- [ ] **Append IP-002 template and register**

Append to `corsair/integrity_policy/findings.py`:

```python
# ---------------------------------------------------------------------------
# IP-002: Integrity-Policy-Report-Only set without enforcing Integrity-Policy
# ---------------------------------------------------------------------------

_IP_002_TEMPLATE = Finding(
    header="Integrity-Policy-Report-Only",
    category=HeaderCategory.INTEGRITY,
    severity=Severity.INFO,
    title="Integrity-Policy in Report-Only mode without enforcing counterpart",
    description=(
        "Integrity-Policy-Report-Only is set but Integrity-Policy is not. "
        "Report-Only is a discovery aid: violations are reported via the "
        "Reporting API but the browser does not block any requests. Sites "
        "that have completed integrity rollout should promote to enforcing "
        "Integrity-Policy."
    ),
    current_value=None,
    recommended_value=(
        "Integrity-Policy: blocked-destinations=(script), endpoints=(default)"
    ),
    impact=(
        "Discovery posture only; no protection against compromised subresources."
    ),
    recommendation=(
        "Once Reporting API confirms zero violations under Report-Only, "
        "duplicate the directive into the enforcing Integrity-Policy header."
    ),
    score_deduction=0,
    cve_correlations=[_CWE_353],
    compliance_mappings=[_OWASP_A08],
    reference_url=_REFERENCE_URL,
)

_REGISTRY["IP-002"] = _IP_002_TEMPLATE
```

- [ ] **Verify IP-002 has correct shape**

Run:
```bash
python3 -c "
from corsair.integrity_policy.findings import get_finding
from corsair.models import Severity
f = get_finding('IP-002')
assert f.severity == Severity.INFO
assert f.score_deduction == 0
print('OK')
"
```
Expected: `OK`

### Step 3.4: Add IP-003 template + `build_ip_003_finding`

- [ ] **Append IP-003 template and builder**

Append to `corsair/integrity_policy/findings.py`:

```python
# ---------------------------------------------------------------------------
# IP-003: Integrity-Policy parse error / no recognized destinations
# ---------------------------------------------------------------------------

_IP_003_TEMPLATE = Finding(
    header="Integrity-Policy",
    category=HeaderCategory.INTEGRITY,
    severity=Severity.LOW,
    title="Integrity-Policy header has no recognized destinations",
    description=(
        "Integrity-Policy is set but cannot be parsed as an RFC 9651 "
        "Structured Field Dictionary, or contains no recognized destination "
        "tokens. Browsers treat unparseable Integrity-Policy values as "
        "absent, so this site has the same effective protection as if no "
        "Integrity-Policy header were sent."
    ),
    current_value=None,
    recommended_value=(
        "Integrity-Policy: blocked-destinations=(script), endpoints=(default)"
    ),
    impact=(
        "Header is sent but ignored by the browser; no integrity enforcement."
    ),
    recommendation=(
        "Use the SF Dictionary syntax: blocked-destinations=(script), "
        "sources=(inline), endpoints=(name). Recognized destination tokens "
        "today are 'script' and 'style'."
    ),
    score_deduction=2,
    cve_correlations=[_CWE_353],
    compliance_mappings=[_OWASP_A08],
    reference_url=_REFERENCE_URL,
)

_REGISTRY["IP-003"] = _IP_003_TEMPLATE


def build_ip_003_finding(raw_value: str) -> Finding:
    """Build IP-003 with the raw header value embedded for diagnostic context."""
    finding = copy.deepcopy(_IP_003_TEMPLATE)
    finding.current_value = raw_value
    finding.description = (
        finding.description
        + f"\n\nRaw header value (verbatim): {raw_value!r}"
    )
    return finding
```

- [ ] **Verify the builder substitutes raw_value**

Run:
```bash
python3 -c "
from corsair.integrity_policy.findings import build_ip_003_finding
f = build_ip_003_finding('blocked-destinations=()')
assert f.current_value == 'blocked-destinations=()'
assert 'blocked-destinations=()' in f.description
print('OK')
"
```
Expected: `OK`

### Step 3.5: Add IP-004 template (script missing from destinations)

- [ ] **Append IP-004 template and register**

Append to `corsair/integrity_policy/findings.py`:

```python
# ---------------------------------------------------------------------------
# IP-004: Integrity-Policy lacks 'script' in blocked-destinations
# ---------------------------------------------------------------------------

_IP_004_TEMPLATE = Finding(
    header="Integrity-Policy",
    category=HeaderCategory.INTEGRITY,
    severity=Severity.LOW,
    title="Integrity-Policy does not block script destinations",
    description=(
        "Integrity-Policy is set but 'script' is not in blocked-destinations. "
        "Scripts are the highest-value target for subresource integrity "
        "enforcement because they execute arbitrary code. A policy that "
        "blocks only 'style' (or any other destination) misses the most "
        "impactful protection class."
    ),
    current_value=None,
    recommended_value=(
        "Integrity-Policy: blocked-destinations=(script), endpoints=(default)"
    ),
    impact=(
        "Subresource integrity enforcement applied to non-script destinations only."
    ),
    recommendation=(
        "Add 'script' to blocked-destinations. Style enforcement can coexist: "
        "blocked-destinations=(script style)."
    ),
    score_deduction=3,
    cve_correlations=[_CWE_353, _CWE_829],
    compliance_mappings=[_OWASP_A08, _PCI_6_4_3],
    reference_url=_REFERENCE_URL,
)

_REGISTRY["IP-004"] = _IP_004_TEMPLATE
```

- [ ] **Verify IP-004 has correct shape**

Run:
```bash
python3 -c "
from corsair.integrity_policy.findings import get_finding
from corsair.models import Severity
f = get_finding('IP-004')
assert f.severity == Severity.LOW
assert f.score_deduction == 3
print('OK')
"
```
Expected: `OK`

### Step 3.6: Add IP-006 template + builders (HIGH, with PASS + INCONCLUSIVE variants)

- [ ] **Append IP-006 template, PASS, INCONCLUSIVE, builders, and static PASS**

Append to `corsair/integrity_policy/findings.py`:

```python
# ---------------------------------------------------------------------------
# IP-006: enforcing Integrity-Policy + cross-origin script lacking integrity
# ---------------------------------------------------------------------------

_IP_006_TEMPLATE = Finding(
    header="Integrity-Policy",
    category=HeaderCategory.INTEGRITY,
    severity=Severity.HIGH,
    title="Enforcing Integrity-Policy + scripts lacking integrity attribute",
    description=(
        "Integrity-Policy is enforcing 'script' blocking, but the document "
        "body contains one or more cross-origin <script> tags without an "
        "integrity attribute. In Chrome 138+, Firefox 145+, and Safari 26+, "
        "these scripts will be blocked by the browser, breaking page "
        "functionality. This is the page-breaking enforcement scenario.\n\n"
        "Note: scripts injected dynamically via JavaScript are not visible to "
        "this scan; only scripts present in the initial server response are "
        "examined. False positives in HTML comments and <noscript> subtrees "
        "are documented in the Corsair v0.5.5 spec — verify in browser "
        "console before remediating."
    ),
    current_value=None,
    recommended_value=None,
    impact=(
        "Browser will block listed scripts; pages that depend on them will fail."
    ),
    recommendation=(
        "Add integrity attributes to each cross-origin <script>:\n"
        "  cat script.js | openssl dgst -sha384 -binary | openssl base64 -A\n"
        "Embed: <script src=\"...\" integrity=\"sha384-<hash>\" "
        "crossorigin=\"anonymous\"></script>\n\n"
        "Fallback: demote to Integrity-Policy-Report-Only until the rollout "
        "completes, monitor reports, then re-enforce."
    ),
    score_deduction=10,
    cve_correlations=[_CWE_353, _CWE_494, _CWE_829],
    compliance_mappings=[_OWASP_A08, _NIST_SI_7, _PCI_6_4_3],
    reference_url=_REFERENCE_URL,
)


_IP_006_PASS_TEMPLATE = Finding(
    header="Integrity-Policy",
    category=HeaderCategory.INTEGRITY,
    severity=Severity.PASS,
    title="Integrity-Policy enforcing — all examined scripts have integrity",
    description=(
        "Integrity-Policy is enforcing 'script' blocking and every cross-origin "
        "<script> tag in the response body carries an integrity attribute. "
        "This PASS does not guarantee coverage of authenticated routes or "
        "dynamically-injected scripts."
    ),
    current_value=None,
    recommended_value=None,
    impact="Subresource integrity enforced as configured.",
    recommendation="Continue monitoring via the configured reporting endpoint.",
    score_deduction=0,
    cve_correlations=[],
    compliance_mappings=[],
    reference_url=_REFERENCE_URL,
)


_IP_006_INCONCLUSIVE_TEMPLATE = Finding(
    header="Integrity-Policy",
    category=HeaderCategory.INTEGRITY,
    severity=Severity.INFO,
    title="Integrity-Policy enforcement check inconclusive",
    description=(
        "Integrity-Policy is enforcing 'script' blocking, but the document "
        "body could not be retrieved to verify whether scripts carry "
        "integrity attributes. Manual verification recommended."
    ),
    current_value=None,
    recommended_value=None,
    impact="Audit gap: scripts lacking integrity may be present.",
    recommendation=(
        "Re-run the scan when the target is reachable, or verify in browser."
    ),
    score_deduction=0,
    cve_correlations=[],
    compliance_mappings=[],
    reference_url=_REFERENCE_URL,
)


_IP_STATIC_PASS_TEMPLATE = Finding(
    header="Integrity-Policy",
    category=HeaderCategory.INTEGRITY,
    severity=Severity.PASS,
    title="Integrity-Policy header configured with script enforcement",
    description=(
        "Integrity-Policy is set with 'script' in blocked-destinations. "
        "Static configuration check passed."
    ),
    current_value=None,
    recommended_value=None,
    impact="Header configured to enforce script subresource integrity.",
    recommendation="No change required.",
    score_deduction=0,
    cve_correlations=[],
    compliance_mappings=[],
    reference_url=_REFERENCE_URL,
)


def build_ip_006_finding(scripts: List[str], truncated: bool = False) -> Finding:
    """IP-006 with the offending script list + optional truncation note."""
    finding = copy.deepcopy(_IP_006_TEMPLATE)
    count = len(scripts)
    listed = "\n".join(f"- {s}" for s in scripts)
    finding.current_value = (
        f"{count} cross-origin script(s) lacking integrity:\n{listed}"
    )
    if truncated:
        finding.description = (
            finding.description
            + "\n\nNote: response body was truncated at 1 MB; some scripts "
            "may not have been examined."
        )
    return finding


def build_ip_006_pass_finding(truncated: bool = False) -> Finding:
    finding = copy.deepcopy(_IP_006_PASS_TEMPLATE)
    if truncated:
        finding.description = (
            finding.description
            + "\n\nNote: response body was truncated at 1 MB; PASS reflects "
            "only the examined prefix."
        )
    return finding


def build_ip_006_inconclusive_finding(error_reason: str) -> Finding:
    finding = copy.deepcopy(_IP_006_INCONCLUSIVE_TEMPLATE)
    finding.current_value = error_reason
    finding.description = (
        finding.description + f"\n\nBody fetch failed: {error_reason}"
    )
    return finding


def build_ip_static_pass_finding() -> Finding:
    return copy.deepcopy(_IP_STATIC_PASS_TEMPLATE)
```

- [ ] **Verify all templates and builders work**

Run:
```bash
python3 -c "
from corsair.integrity_policy.findings import (
    get_finding,
    build_ip_003_finding,
    build_ip_006_finding,
    build_ip_006_pass_finding,
    build_ip_006_inconclusive_finding,
    build_ip_static_pass_finding,
)
from corsair.models import Severity, HeaderCategory

for fid in ('IP-001', 'IP-002', 'IP-003', 'IP-004'):
    f = get_finding(fid)
    assert f is not None, fid
    assert f.category == HeaderCategory.INTEGRITY

f6 = build_ip_006_finding(['https://cdn.com/x.js'], truncated=True)
assert f6.severity == Severity.HIGH
assert 'truncated' in f6.description
assert 'cdn.com/x.js' in f6.current_value

f6p = build_ip_006_pass_finding()
assert f6p.severity == Severity.PASS

f6i = build_ip_006_inconclusive_finding('Request timeout')
assert f6i.severity == Severity.INFO
assert 'Request timeout' in f6i.description

f3 = build_ip_003_finding('garbage')
assert 'garbage' in f3.description

fs = build_ip_static_pass_finding()
assert fs.severity == Severity.PASS

print('OK')
"
```
Expected: `OK`

### Step 3.7: Commit Task 3

- [ ] **Stage and commit**

```bash
git add corsair/integrity_policy/findings.py
git commit -m "$(cat <<'EOF'
feat(integrity-policy): add finding templates and builders

Five Finding templates (IP-001/002/003/004/006), three PASS variants
(static, IP-006), and one INCONCLUSIVE variant. Public API:
  get_finding(finding_id) -> Finding | None  (deepcopy of template)
  build_ip_003_finding(raw_value)
  build_ip_006_finding(scripts, truncated)
  build_ip_006_pass_finding(truncated)
  build_ip_006_inconclusive_finding(error_reason)
  build_ip_static_pass_finding()

Severity assignments per spec §3.3:
  IP-001 LOW (3pt), IP-002 INFO (0pt), IP-003 LOW (2pt),
  IP-004 LOW (3pt), IP-006 HIGH (10pt).
All categorized as HeaderCategory.INTEGRITY.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `auditor.py` — `IntegrityPolicyAuditor` class

**Files:**
- Create: `corsair/integrity_policy/auditor.py`
- Modify: `corsair/integrity_policy/__init__.py` (add export)
- Create: `tests/test_integrity_policy_auditor.py`

This task implements the orchestrator. It dispatches the static-path checks (always run) and gates the active body-fetch path on four conditions: `active=True`, parse succeeded, `script` in blocked-destinations, HTML response Content-Type.

### Step 4.1: TDD auditor — IP-001 (both headers absent)

- [ ] **Write the failing test file with the first auditor test**

Create `tests/test_integrity_policy_auditor.py`:

```python
"""Tests for corsair.integrity_policy.auditor.IntegrityPolicyAuditor."""

import pytest

from corsair.integrity_policy.auditor import IntegrityPolicyAuditor
from corsair.models import Severity


# ---------------------------------------------------------------------------
# Static path: one finding per primary scenario
# ---------------------------------------------------------------------------

class TestStaticPathFindingsByScenario:
    def test_ip_001_when_both_headers_absent(self):
        auditor = IntegrityPolicyAuditor(timeout=10, active=False)
        findings = auditor.audit("https://example.com/", {})
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.LOW
        assert "absent" in f.title.lower()
```

- [ ] **Run test to verify it fails**

Run: `python3 -m pytest tests/test_integrity_policy_auditor.py -v`
Expected: FAIL with `ImportError: cannot import name 'IntegrityPolicyAuditor'`.

- [ ] **Create the auditor with minimal IP-001 path**

Create `corsair/integrity_policy/auditor.py`:

```python
"""IntegrityPolicyAuditor — two-stage Integrity-Policy validation.

Stage 1 (static, always runs): parse Integrity-Policy and Integrity-Policy-
Report-Only headers and emit IP-001/002/003/004 or static PASS.

Stage 2 (active, gated): when active=True AND enforcing IP detected AND
'script' in blocked-destinations AND HTML Content-Type, GET the document
body and check cross-origin <script> tags for integrity attributes.
Emits IP-006, IP-006 PASS, or IP-006 INCONCLUSIVE.
"""

import logging
from typing import Dict, List, Mapping, Optional, Tuple

from ..models import Finding
from .body import ONE_MEGABYTE, _extract_cross_origin_scripts, _fetch_body
from .findings import (
    build_ip_003_finding,
    build_ip_006_finding,
    build_ip_006_inconclusive_finding,
    build_ip_006_pass_finding,
    build_ip_static_pass_finding,
    get_finding,
)
from .parser import _is_html_response, _parse_integrity_policy


logger = logging.getLogger(__name__)


_RECOGNIZED_DESTINATIONS = frozenset({"script", "style"})


class IntegrityPolicyAuditor:
    def __init__(
        self,
        timeout: int = 10,
        active: bool = True,
        user_agent: str = "HeadScan/1.0 (Security Header Analyzer)",
    ):
        self.timeout = timeout
        self.active = active
        self.user_agent = user_agent

    def audit(self, url: str, headers: Mapping[str, str]) -> List[Finding]:
        try:
            return self._audit_inner(url, headers)
        except Exception as e:
            logger.error(f"Integrity-Policy audit failed for {url}: {e}")
            # Surface the gap rather than swallow it.
            inconclusive = build_ip_006_inconclusive_finding(
                f"Auditor exception: {type(e).__name__}: {e}"
            )
            inconclusive.title = "Integrity-Policy analysis failed"
            return [inconclusive]

    def _audit_inner(
        self, url: str, headers: Mapping[str, str]
    ) -> List[Finding]:
        ip_value = self._get_header(headers, "integrity-policy")
        ip_ro_value = self._get_header(headers, "integrity-policy-report-only")
        static_findings, parsed = self._static_audit(ip_value, ip_ro_value)
        return static_findings  # Stage 2 wired in later steps

    @staticmethod
    def _get_header(headers: Mapping[str, str], name: str) -> Optional[str]:
        for k, v in headers.items():
            if k.lower() == name:
                return v
        return None

    def _static_audit(
        self, ip_value: Optional[str], ip_ro_value: Optional[str]
    ) -> Tuple[List[Finding], Optional[Dict]]:
        # Both headers absent -> IP-001
        if not ip_value and not ip_ro_value:
            return ([get_finding("IP-001")], None)
        # IP absent, IP-RO present -> IP-002
        if not ip_value and ip_ro_value:
            return ([get_finding("IP-002")], None)
        # IP present (with or without IP-RO): parse and dispatch
        parsed = _parse_integrity_policy(ip_value or "")
        if parsed["parse_error"]:
            return ([build_ip_003_finding(ip_value or "")], parsed)
        recognized = [
            t for t in parsed["blocked_destinations"]
            if t in _RECOGNIZED_DESTINATIONS
        ]
        if not recognized:
            return ([build_ip_003_finding(ip_value or "")], parsed)
        if "script" not in parsed["blocked_destinations"]:
            return ([get_finding("IP-004")], parsed)
        # Healthy static config
        return ([build_ip_static_pass_finding()], parsed)
```

- [ ] **Run the test to verify it passes**

Run: `python3 -m pytest tests/test_integrity_policy_auditor.py::TestStaticPathFindingsByScenario::test_ip_001_when_both_headers_absent -v`
Expected: PASS, 1/1.

### Step 4.2: TDD auditor — IP-002 path

- [ ] **Append IP-002 test**

Append inside `class TestStaticPathFindingsByScenario`:

```python
    def test_ip_002_when_only_report_only_present(self):
        auditor = IntegrityPolicyAuditor(timeout=10, active=False)
        headers = {"Integrity-Policy-Report-Only": "blocked-destinations=(script)"}
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "Report-Only" in findings[0].title
```

- [ ] **Run test to verify it passes**

Run: `python3 -m pytest tests/test_integrity_policy_auditor.py::TestStaticPathFindingsByScenario::test_ip_002_when_only_report_only_present -v`
Expected: PASS, 1/1.

### Step 4.3: TDD auditor — IP-003 paths (3 sub-cases)

- [ ] **Append IP-003 sub-case tests**

Append inside `class TestStaticPathFindingsByScenario`:

```python
    def test_ip_003_on_empty_inner_list(self):
        auditor = IntegrityPolicyAuditor(timeout=10, active=False)
        headers = {"Integrity-Policy": "blocked-destinations=()"}
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "no recognized destinations" in findings[0].title.lower()

    def test_ip_003_on_unparseable_value(self):
        auditor = IntegrityPolicyAuditor(timeout=10, active=False)
        headers = {"Integrity-Policy": "garbage_value!!"}
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "garbage_value!!" in findings[0].current_value

    def test_ip_003_on_all_unknown_tokens(self):
        auditor = IntegrityPolicyAuditor(timeout=10, active=False)
        headers = {"Integrity-Policy": "blocked-destinations=(scripts foo)"}
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_auditor.py -k "ip_003" -v`
Expected: PASS, 3/3.

### Step 4.4: TDD auditor — IP-004 path

- [ ] **Append IP-004 test**

Append inside `class TestStaticPathFindingsByScenario`:

```python
    def test_ip_004_when_script_missing(self):
        auditor = IntegrityPolicyAuditor(timeout=10, active=False)
        headers = {"Integrity-Policy": "blocked-destinations=(style)"}
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "does not block script" in findings[0].title.lower()
```

- [ ] **Run test to verify it passes**

Run: `python3 -m pytest tests/test_integrity_policy_auditor.py::TestStaticPathFindingsByScenario::test_ip_004_when_script_missing -v`
Expected: PASS, 1/1.

### Step 4.5: TDD auditor — static PASS with `--no-ip-probe`

- [ ] **Append static-PASS test**

Append inside `class TestStaticPathFindingsByScenario`:

```python
    def test_static_pass_when_active_false(self):
        auditor = IntegrityPolicyAuditor(timeout=10, active=False)
        headers = {"Integrity-Policy": "blocked-destinations=(script)"}
        findings = auditor.audit("https://example.com/", headers)
        # Stage 2 skipped: only the static PASS finding.
        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS
```

- [ ] **Run test to verify it passes**

Run: `python3 -m pytest tests/test_integrity_policy_auditor.py::TestStaticPathFindingsByScenario::test_static_pass_when_active_false -v`
Expected: PASS, 1/1.

### Step 4.6: Wire Stage 2 into the auditor

- [ ] **Modify `_audit_inner` to dispatch Stage 2**

In `corsair/integrity_policy/auditor.py`, replace the existing `_audit_inner` with:

```python
    def _audit_inner(
        self, url: str, headers: Mapping[str, str]
    ) -> List[Finding]:
        ip_value = self._get_header(headers, "integrity-policy")
        ip_ro_value = self._get_header(headers, "integrity-policy-report-only")
        static_findings, parsed = self._static_audit(ip_value, ip_ro_value)
        findings: List[Finding] = list(static_findings)

        # Stage 2 gate: must be active AND parse succeeded AND script blocked
        # AND HTML response.
        if not self.active:
            return findings
        if parsed is None or parsed.get("parse_error"):
            return findings
        if "script" not in parsed.get("blocked_destinations", []):
            return findings
        if not _is_html_response(dict(headers)):
            return findings

        # Stage 2: body fetch + IP-006 dispatch
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

- [ ] **Verify existing static tests still pass**

Run: `python3 -m pytest tests/test_integrity_policy_auditor.py -v`
Expected: PASS, all 7 existing tests still pass.

### Step 4.7: TDD auditor — IP-006 fires on cross-origin script

- [ ] **Append IP-006 test using pytest-httpx**

Append to `tests/test_integrity_policy_auditor.py`:

```python
# ---------------------------------------------------------------------------
# Stage 2 active path
# ---------------------------------------------------------------------------

class TestStage2ActivePath:
    def test_ip_006_fires_on_cross_origin_script_no_integrity(self, httpx_mock):
        body = (
            '<html><body>'
            '<script src="https://cdn.example.net/tag.js"></script>'
            '</body></html>'
        )
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text=body,
            headers={"Content-Type": "text/html"},
        )
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(script)",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 2  # static PASS + IP-006
        ip6 = next(f for f in findings if f.severity == Severity.HIGH)
        assert "cdn.example.net" in ip6.current_value
```

- [ ] **Run test to verify it passes**

Run: `python3 -m pytest tests/test_integrity_policy_auditor.py::TestStage2ActivePath::test_ip_006_fires_on_cross_origin_script_no_integrity -v`
Expected: PASS, 1/1.

### Step 4.8: TDD auditor — IP-006 PASS path

- [ ] **Append IP-006 PASS test**

Append inside `class TestStage2ActivePath`:

```python
    def test_ip_006_pass_when_all_scripts_have_integrity(self, httpx_mock):
        body = (
            '<html><body>'
            '<script src="https://cdn.example.net/tag.js" '
            'integrity="sha384-abc" crossorigin="anonymous"></script>'
            '</body></html>'
        )
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text=body,
            headers={"Content-Type": "text/html"},
        )
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(script)",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        # static PASS + IP-006 PASS
        assert len(findings) == 2
        assert all(f.severity == Severity.PASS for f in findings)
```

- [ ] **Run test to verify it passes**

Run: `python3 -m pytest tests/test_integrity_policy_auditor.py::TestStage2ActivePath::test_ip_006_pass_when_all_scripts_have_integrity -v`
Expected: PASS, 1/1.

### Step 4.9: TDD auditor — IP-006 INCONCLUSIVE on body fetch failure

- [ ] **Append INCONCLUSIVE tests**

Append inside `class TestStage2ActivePath`:

```python
    def test_ip_006_inconclusive_on_timeout(self, httpx_mock):
        import httpx as _httpx
        httpx_mock.add_exception(_httpx.ReadTimeout("read timeout"))
        auditor = IntegrityPolicyAuditor(timeout=1, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(script)",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        # static PASS + IP-006 INCONCLUSIVE
        assert len(findings) == 2
        inc = next(f for f in findings if f.severity == Severity.INFO)
        assert "Request timeout" in inc.current_value

    def test_ip_006_inconclusive_on_500(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=500,
            text="server error",
        )
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(script)",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        inc = next(f for f in findings if f.severity == Severity.INFO)
        assert "HTTP 500" in inc.current_value

    def test_ip_006_inconclusive_on_connect_error(self, httpx_mock):
        import httpx as _httpx
        httpx_mock.add_exception(_httpx.ConnectError("dns failure"))
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(script)",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        inc = next(f for f in findings if f.severity == Severity.INFO)
        assert "Connection error" in inc.current_value
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_auditor.py::TestStage2ActivePath -k inconclusive -v`
Expected: PASS, 3/3.

### Step 4.10: TDD Stage 2 gate skips

- [ ] **Append Stage-2 gate-skip tests**

Append to `tests/test_integrity_policy_auditor.py`:

```python
# ---------------------------------------------------------------------------
# Stage 2 gate skips — five exit conditions
# ---------------------------------------------------------------------------

class TestStage2GateSkips:
    def test_active_false_skips_body_fetch(self, httpx_mock):
        # No httpx_mock.add_response — if Stage 2 ran, the test would fail.
        auditor = IntegrityPolicyAuditor(timeout=10, active=False)
        headers = {
            "Integrity-Policy": "blocked-destinations=(script)",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1  # static PASS only

    def test_parse_error_skips_body_fetch(self, httpx_mock):
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "garbage!!",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1  # IP-003 only

    def test_script_missing_skips_body_fetch(self, httpx_mock):
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(style)",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1  # IP-004 only

    def test_non_html_content_type_skips_body_fetch(self, httpx_mock):
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(script)",
            "Content-Type": "application/json",
        }
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1  # static PASS only

    def test_missing_content_type_skips_body_fetch(self, httpx_mock):
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {"Integrity-Policy": "blocked-destinations=(script)"}
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1  # static PASS only
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_auditor.py::TestStage2GateSkips -v`
Expected: PASS, 5/5. (`pytest-httpx` will raise if the auditor unexpectedly issues a request — perfect for verifying Stage 2 was skipped.)

### Step 4.11: TDD combined / interaction cases

- [ ] **Append combined-case tests**

Append to `tests/test_integrity_policy_auditor.py`:

```python
# ---------------------------------------------------------------------------
# Combined / interaction cases
# ---------------------------------------------------------------------------

class TestCombinedCases:
    def test_both_headers_present_no_ip_002(self, httpx_mock):
        body = "<html><body>no scripts</body></html>"
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text=body,
            headers={"Content-Type": "text/html"},
        )
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(script)",
            "Integrity-Policy-Report-Only": "blocked-destinations=(script)",
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        # Static PASS (no IP-002) + IP-006 PASS (no scripts).
        assert all(f.severity == Severity.PASS for f in findings)
        assert not any("Report-Only" in f.title for f in findings)

    def test_ip_004_skips_body_fetch_no_ip_006(self, httpx_mock):
        # No httpx_mock response — body fetch would fail the test.
        auditor = IntegrityPolicyAuditor(timeout=10, active=True)
        headers = {
            "Integrity-Policy": "blocked-destinations=(style)",  # no script
            "Content-Type": "text/html",
        }
        findings = auditor.audit("https://example.com/", headers)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW  # IP-004 only
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_auditor.py::TestCombinedCases -v`
Expected: PASS, 2/2.

### Step 4.12: TDD compliance/CWE/reference shape locked into tests

- [ ] **Append metadata-shape tests**

Append to `tests/test_integrity_policy_auditor.py`:

```python
# ---------------------------------------------------------------------------
# Compliance / CWE / reference shape — lock into the test suite
# ---------------------------------------------------------------------------

from corsair.integrity_policy.findings import (
    build_ip_003_finding,
    build_ip_006_finding,
    get_finding,
)
from corsair.models import HeaderCategory


class TestFindingMetadataShape:
    def test_each_finding_categorized_as_integrity(self):
        for fid in ("IP-001", "IP-002", "IP-003", "IP-004"):
            f = get_finding(fid)
            assert f.category == HeaderCategory.INTEGRITY, fid
        f6 = build_ip_006_finding(["https://cdn.com/x.js"])
        assert f6.category == HeaderCategory.INTEGRITY

    def test_ip_001_compliance_includes_owasp_a08_and_pci(self):
        f = get_finding("IP-001")
        framework_ids = {(c.framework, c.requirement_id) for c in f.compliance_mappings}
        assert ("OWASP_TOP_10_2021", "A08") in framework_ids
        assert ("PCI_DSS_4_0", "6.4.3") in framework_ids
        assert ("NIST_SP_800_53", "SI-7") in framework_ids

    def test_reference_url_present_and_https(self):
        for fid in ("IP-001", "IP-002", "IP-003", "IP-004"):
            f = get_finding(fid)
            assert f.reference_url is not None
            assert f.reference_url.startswith("https://"), fid
        f6 = build_ip_006_finding([])
        assert f6.reference_url.startswith("https://")
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_integrity_policy_auditor.py::TestFindingMetadataShape -v`
Expected: PASS, 3/3.

### Step 4.13: Update `__init__.py` to export the auditor

- [ ] **Replace `corsair/integrity_policy/__init__.py`**

Overwrite with:

```python
"""Integrity-Policy validation subsystem (v0.5.5)."""

from .auditor import IntegrityPolicyAuditor

__all__ = ["IntegrityPolicyAuditor"]
```

- [ ] **Verify the public import works**

Run: `python3 -c "from corsair.integrity_policy import IntegrityPolicyAuditor; print('OK')"`
Expected: `OK`

### Step 4.14: Run the full auditor test file

- [ ] **Confirm full file passes**

Run: `python3 -m pytest tests/test_integrity_policy_auditor.py -v`
Expected: PASS, ~22 tests across all classes (7 + 5 + 5 + 2 + 3 = 22). Target met.

### Step 4.15: Commit Task 4

- [ ] **Stage and commit**

```bash
git add corsair/integrity_policy/auditor.py corsair/integrity_policy/__init__.py tests/test_integrity_policy_auditor.py
git commit -m "$(cat <<'EOF'
feat(integrity-policy): add IntegrityPolicyAuditor with two-stage flow

Stage 1 (always runs): static parse → IP-001/002/003/004 or static PASS.
Stage 2 (gated): active body fetch when active=True AND parse OK AND
'script' in blocked-destinations AND HTML Content-Type. Emits IP-006,
IP-006 PASS, or IP-006 INCONCLUSIVE.

Auditor never raises out: top-level try/except converts unexpected
exceptions into a single INFO finding so audit gaps stay visible.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Scanner integration + CLI flag

**Files:**
- Modify: `corsair/scanner.py:25-229` (HeadScanner class)
- Modify: `corsair/cli.py:174` (add new option) and `cli.py:197-244` (plumb through)

This task wires the auditor into the pipeline and exposes the CLI flag, then tests both via a scanner-integration smoke test and the v0.5.4 coexistence regression.

### Step 5.1: TDD scanner integration smoke test

- [ ] **Append the smoke test to the auditor test file**

Append to `tests/test_integrity_policy_auditor.py`:

```python
# ---------------------------------------------------------------------------
# Scanner integration smoke test
# ---------------------------------------------------------------------------

from unittest.mock import patch


class TestScannerIntegration:
    def test_ip_006_emitted_via_full_pipeline(self, httpx_mock):
        from corsair.scanner import HeadScanner

        body = (
            '<html><body>'
            '<script src="https://cdn.example.net/tag.js"></script>'
            '</body></html>'
        )
        # Mock Stage 2 body fetch.
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text=body,
            headers={"Content-Type": "text/html"},
        )

        # Mock the initial HeadScanner._fetch_headers to return enforcing IP +
        # HTML Content-Type (avoids a real first request and a second body GET).
        ip_headers = {
            "Integrity-Policy": "blocked-destinations=(script)",
            "Content-Type": "text/html",
        }
        with patch.object(
            HeadScanner,
            "_fetch_headers",
            return_value=(200, ip_headers, "https://example.com/", None),
        ):
            scanner = HeadScanner(
                timeout=10,
                cache_probe=False,
                cors_probe=False,
                fm_probe=False,
                ip_probe=True,
            )
            result = scanner.scan_target("https://example.com/")

        ip6_findings = [
            f for f in result.findings
            if f.title.startswith("Enforcing Integrity-Policy")
        ]
        assert len(ip6_findings) == 1
```

- [ ] **Run test to verify it fails**

Run: `python3 -m pytest tests/test_integrity_policy_auditor.py::TestScannerIntegration -v`
Expected: FAIL with `TypeError: HeadScanner.__init__() got an unexpected keyword argument 'ip_probe'`.

### Step 5.2: Add `ip_probe` to `HeadScanner.__init__`

- [ ] **Modify `corsair/scanner.py`**

In `HeadScanner.__init__` (around lines 28-58), add `ip_probe: bool = True` to the signature and store it as `self.ip_probe = ip_probe`. The relevant changes (showing context):

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
        ip_probe: bool = True,
    ):
        ...
        self.fm_probe = fm_probe
        self.ip_probe = ip_probe
```

Also extend the docstring's `Args:` block with one line for `ip_probe`.

- [ ] **Add the IntegrityPolicyAuditor block in `scan_target` after Fetch Metadata**

In `corsair/scanner.py`, after the existing Fetch Metadata block (around line 207), insert:

```python
        # Integrity-Policy validation
        try:
            from .integrity_policy import IntegrityPolicyAuditor
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

(Local import keeps the new dep loaded only when scan_target runs, matching the FetchMetadataAuditor pattern.)

- [ ] **Run the smoke test to verify it passes**

Run: `python3 -m pytest tests/test_integrity_policy_auditor.py::TestScannerIntegration -v`
Expected: PASS, 1/1.

### Step 5.3: Add `--ip-probe / --no-ip-probe` to CLI

- [ ] **Add the click option**

In `corsair/cli.py` after line 174 (the `--fm-probe` option), insert:

```python
@click.option("--ip-probe/--no-ip-probe", default=True, help="Run Integrity-Policy validation")
```

- [ ] **Add the parameter to the `scan` function signature**

In `corsair/cli.py` around line 199 (after `fm_probe: bool,`), add:

```python
    fm_probe: bool,
    ip_probe: bool,
    cors_evil_origin: str,
```

- [ ] **Plumb `ip_probe` to the `HeadScanner(...)` instantiation**

Around line 244 in `corsair/cli.py`, update the constructor call:

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
        ip_probe=ip_probe,
    )
```

- [ ] **Verify CLI shows the new flag**

Run: `corsair scan --help | grep -E "ip-probe|fm-probe"`
Expected output includes:
```
--ip-probe / --no-ip-probe      Run Integrity-Policy validation
--fm-probe / --no-fm-probe      Run Fetch Metadata enforcement probing
```

### Step 5.4: Regression test for v0.5.4 coexistence with REPORT-004

- [ ] **Append the regression test**

Append to `tests/test_integrity_policy_auditor.py`:

```python
# ---------------------------------------------------------------------------
# Regression: REPORT-004 (v0.5.4) still fires on the same fixture
# ---------------------------------------------------------------------------

class TestV054Coexistence:
    def test_report_004_still_fires_when_ip_endpoints_orphaned(self):
        """When Integrity-Policy references an undefined endpoint, REPORT-004
        from corsair/analyzers/reporting.py must still fire even though the
        new IntegrityPolicyAuditor also runs on the same headers. The two
        subsystems address different misconfigurations; they must not collide.
        """
        from corsair.analyzers.reporting import ReportingCoherenceAnalyzer

        headers = {
            # Integrity-Policy references 'missing-endpoint' but no Reporting-
            # Endpoints header defines it. v0.5.4 REPORT-004 owns this.
            "Integrity-Policy": (
                "blocked-destinations=(script), endpoints=(missing-endpoint)"
            ),
            "Content-Type": "text/html",
        }
        analyzer = ReportingCoherenceAnalyzer(headers, "https://example.com/")
        report_findings = analyzer.analyze()
        report_004 = [
            f for f in report_findings
            if f.title.startswith("Integrity-Policy")
            and "endpoint" in f.title.lower()
        ]
        assert len(report_004) >= 1, (
            "REPORT-004 must still fire on orphaned endpoints; the new "
            "IntegrityPolicyAuditor does not own this misconfiguration."
        )

        # And the new auditor (with active=False so we don't hit the network)
        # contributes its own static finding without erasing REPORT-004.
        ip_auditor = IntegrityPolicyAuditor(timeout=10, active=False)
        ip_findings = ip_auditor.audit("https://example.com/", headers)
        # Static path: 'script' present in blocked-destinations -> static PASS.
        assert any(f.severity == Severity.PASS for f in ip_findings)
```

- [ ] **Run the regression test to verify it passes**

Run: `python3 -m pytest tests/test_integrity_policy_auditor.py::TestV054Coexistence -v`
Expected: PASS, 1/1.

### Step 5.5: Run the full test suite

- [ ] **Run the full test suite to confirm zero new failures**

Run: `python3 -m pytest --ignore=tests/test_tls_auditor.py -q`
Expected: All tests pass except the 3 pre-existing TLS BadSSL failures (which are excluded). New test count: ~70+ for IP subsystem.

### Step 5.6: Commit Task 5

- [ ] **Stage and commit**

```bash
git add corsair/scanner.py corsair/cli.py tests/test_integrity_policy_auditor.py
git commit -m "$(cat <<'EOF'
feat(integrity-policy): wire IntegrityPolicyAuditor into scanner and CLI

HeadScanner gains an ip_probe parameter (default True) and instantiates
IntegrityPolicyAuditor after the Fetch Metadata block, with try/except
matching the established auditor-block pattern.

CLI gains --ip-probe / --no-ip-probe (default ON) plumbed through the
scan command parameters.

Regression test asserts REPORT-004 (v0.5.4) still fires on orphaned
Integrity-Policy endpoints; the new auditor does not erase or duplicate
the cross-header reporting coherence subsystem.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: v0.5.5 release

**Files:**
- Modify: `corsair/__init__.py:27` (`__version__`)
- Modify: `pyproject.toml:7` (`version`)
- Modify: `README.md` (insert `### v0.5.5` block above `### v0.5.4`)

This task ships the version bump and the changelog entry. No new code or tests.

### Step 6.1: Bump `corsair/__init__.py`

- [ ] **Update `__version__`**

In `corsair/__init__.py`, change line 27:

```python
__version__ = "0.5.5"
```

- [ ] **Verify the import shows the new version**

Run: `python3 -c "import corsair; print(corsair.__version__)"`
Expected: `0.5.5`

### Step 6.2: Bump `pyproject.toml`

- [ ] **Update `version`**

In `pyproject.toml`, change line 7:

```toml
version = "0.5.5"
```

### Step 6.3: Add v0.5.5 changelog entry to README

- [ ] **Insert above the v0.5.4 entry**

In `README.md`, locate `### v0.5.4 — Reporting-Endpoints Coherence Detection` (line ~159) and insert above it:

```markdown
### v0.5.5 — Integrity-Policy Validation (2026-05-04)

**Headline:** First public scanner with body-aware Integrity-Policy enforcement detection (IP-006).

**New subsystem:** `corsair/integrity_policy/`
- `parser.py` — RFC 9651 SF Dictionary parser for Integrity-Policy / Integrity-Policy-Report-Only; HTML Content-Type discriminator.
- `body.py` — Sync httpx GET (capped at 1 MB) + cross-origin <script> extraction (exact scheme/host/port match).
- `findings.py` — 5 finding templates + 3 PASS variants + 1 INCONCLUSIVE.
- `auditor.py` — `IntegrityPolicyAuditor` two-stage flow: static parse always runs, body fetch gated on enforcing+script+HTML.

**Findings:**
- IP-001 (LOW, 3pt) — Integrity-Policy and Integrity-Policy-Report-Only both absent.
- IP-002 (INFO, 0pt) — Report-Only set without enforcing counterpart.
- IP-003 (LOW, 2pt) — Header set but unparseable or no recognized destinations.
- IP-004 (LOW, 3pt) — `script` missing from `blocked-destinations`.
- IP-006 (HIGH, 10pt) — Enforcing IP + cross-origin scripts lacking `integrity` (page-breaking).

**CLI:** New flag `--ip-probe / --no-ip-probe` (default ON).

**Compliance:** OWASP A08, NIST SI-7, PCI-DSS 6.4.3; CWE-353/494/829.

**Tests:** ~70 new tests across `tests/test_integrity_policy_*.py` plus 1 v0.5.4 coexistence regression for REPORT-004.

**Models:** `HeaderCategory.INTEGRITY` enum value added.

```

- [ ] **Verify the README changes look right**

Run: `grep -n "v0.5.5\|v0.5.4" /Users/fevra/Apps/HeadScan/README.md | head -5`
Expected: Line with `### v0.5.5 — Integrity-Policy Validation (2026-05-04)` precedes `### v0.5.4 — Reporting-Endpoints Coherence Detection`.

### Step 6.4: Run the full test suite once more before the release commit

- [ ] **Final test run**

Run: `python3 -m pytest --ignore=tests/test_tls_auditor.py -q`
Expected: All tests pass. Confirm new test count vs. v0.5.4 baseline shows ~70+ added tests.

### Step 6.5: Commit the release

- [ ] **Stage and commit**

```bash
git add corsair/__init__.py pyproject.toml README.md
git commit -m "$(cat <<'EOF'
release: v0.5.5 — Integrity-Policy Validation

First public scanner with body-aware Integrity-Policy enforcement
detection (IP-006). New corsair/integrity_policy/ subsystem ships
five findings (IP-001/002/003/004/006), a new --ip-probe / --no-ip-probe
CLI flag (default ON), and ~70 unit tests.

Cutting-edge positioning: IP-006 detects the page-breaking enforcement
scenario (enforcing Integrity-Policy + cross-origin <script> tags
lacking integrity attribute). No other public scanner — humble,
drHEADer, Mozilla Observatory, Snyk — implements this check at time
of release.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

### Step 6.6: Hand off to the development-finishing skill

- [ ] **Announce and invoke the finishing-a-development-branch skill**

Per superpowers:subagent-driven-development Step 7: after all tasks complete, run the final code reviewer subagent across the full implementation, then announce:

> "I'm using the finishing-a-development-branch skill to complete this work."

Follow that skill to verify tests, present the four standard options (merge locally / create PR / keep as-is / discard), and execute the chosen path.

---

## Acceptance criteria checklist

Map of spec §10 acceptance criteria → tasks that satisfy each:

| # | Criterion | Satisfied by |
|---|---|---|
| 1 | `from corsair.integrity_policy import IntegrityPolicyAuditor` works | Task 4 (Step 4.13) |
| 2 | `audit(url, headers)` returns `list[Finding]` for every §6.3 scenario | Tasks 4 (all auditor scenarios) + Task 5 (smoke + regression) |
| 3 | `corsair --help` shows `--ip-probe / --no-ip-probe` | Task 5 (Step 5.3) |
| 4 | `pytest tests/test_integrity_policy_*.py` passes (~70 tests) | Tasks 1, 2, 4 |
| 5 | Full suite minus TLS shows zero new failures vs v0.5.4 | Tasks 5.5 + 6.4 |
| 6 | Auditor wired into `HeadScanner.scan_target()` after FM block | Task 5 (Step 5.2) |
| 7 | v0.5.5 release artifacts updated | Task 6 (Steps 6.1-6.3) |
| 8 | REPORT-004 still fires on regression fixture | Task 5 (Step 5.4) |
