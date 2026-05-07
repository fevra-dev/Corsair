# HTTP/3 Validation Implementation Plan (v0.6.0)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a new optional `corsair/h3/` subsystem with three core findings (0-RTT replay, H1/H3 header drift, LSQUIC fingerprint) wired into the scanner pipeline behind a new `[h3]` extras gate.

**Architecture:** Five-file subsystem mirroring `corsair/integrity_policy/` (parser/diff/findings/client/auditor). The `aioquic` import is isolated to `client.py`; everything else is pure-logic over dicts. The auditor wraps the async client with `asyncio.run()`. New `--h3-probe / --no-h3-probe` CLI flag plumbed through `HeadScanner` like v0.5.5's `--ip-probe`.

**Tech Stack:** Python 3.9+, `aioquic>=1.3.0,<2.0` (optional extra), pytest, pytest-asyncio (for integration smoke), the existing `cryptography` dep used by TLS auditor.

**Companion spec:** `docs/superpowers/specs/2026-05-07-http3-validation-design.md` — read this first.
**Companion memory:** `~/.claude/projects/-Users-fevra-Apps-HeadScan/memory/project_h3_v060_scope.md` — Tier B/C deferred work.

---

## File Structure

```
corsair/h3/                                 # NEW subsystem
├── __init__.py        # Public API: H3Auditor; sets h3_available flag
├── probe.py           # Pure-logic: Alt-Svc → h3 target; LSQUIC fingerprint
├── diff.py            # Pure-logic: H1/H3 security-header diff
├── findings.py        # Finding templates and builder functions
├── client.py          # aioquic-backed scan_h3() — only file importing aioquic
└── auditor.py         # H3Auditor orchestrator; sync wrapper around async client

corsair/models.py:35-65          # MODIFY: add HeaderCategory.H3 enum value
corsair/scanner.py:25-229        # MODIFY: add ip_probe parameter and H3 block
corsair/cli.py:174,200,247       # MODIFY: add --h3-probe flag; plumb through
pyproject.toml:7,~30             # MODIFY: bump version; add [h3] extras

tests/test_h3_probe.py           # NEW: ~18 tests
tests/test_h3_diff.py            # NEW: ~22 tests
tests/test_h3_findings.py        # NEW: ~10 tests (template metadata shape)
tests/test_h3_auditor.py         # NEW: ~30 tests + 1 scanner-integration smoke
tests/test_h3_integration.py     # NEW: ~3 tests; skipped when aioquic absent
tests/h3_server.py               # NEW: pytest fixture — local aioquic H3 server
```

---

## Task 1: Models + subsystem skeleton

**Files:**
- Modify: `corsair/models.py:35-65` (add `HeaderCategory.H3`)
- Create: `corsair/h3/__init__.py`

This task lays the foundation: a category enum value and a public-API surface that gracefully degrades when the `[h3]` extra isn't installed. No tests yet for `__init__.py` directly — it's exercised by every later task that imports from `corsair.h3`.

### Step 1.1: Add `HeaderCategory.H3` enum

- [ ] **Modify `corsair/models.py`**

After the `INTEGRITY = "integrity"` line (around line 52), insert:

```python
    H3 = "h3"  # HTTP/3, QUIC, 0-RTT, H1/H3 header drift, LSQUIC fingerprint
```

- [ ] **Verify the enum loads**

Run: `python3 -c "from corsair.models import HeaderCategory; print(HeaderCategory.H3.value)"`
Expected: `h3`

### Step 1.2: Create `corsair/h3/__init__.py`

- [ ] **Create the package init with availability flag**

Create `corsair/h3/__init__.py`:

```python
"""HTTP/3 validation subsystem.

The optional [h3] extra (`pip install corsair-scan[h3]`) installs aioquic.
This package always imports cleanly; H3Auditor degrades gracefully and
emits a single INFO finding when aioquic is unavailable.
"""

# Always-available: pure-logic modules and the auditor itself.
from .auditor import H3Auditor

# aioquic-gated: only the client requires the [h3] extra. The flag lets
# downstream code choose between probing and emitting H3-INFO-EXTRAS-MISSING.
try:
    from .client import scan_h3  # noqa: F401
    h3_available = True
except ImportError:
    h3_available = False

__all__ = ["H3Auditor", "h3_available"]
```

### Step 1.3: Commit Task 1

- [ ] **Stage and commit**

```bash
git add corsair/models.py corsair/h3/__init__.py
git commit -m "$(cat <<'EOF'
feat(models): add HeaderCategory.H3 enum value and h3 subsystem skeleton

Empty corsair/h3/ package with availability flag mirroring corsair.tls.
Importing the package never raises; the flag h3_available reflects
whether aioquic is installed. H3Auditor (added in Task 6) consults the
flag and emits H3-INFO-EXTRAS-MISSING when False.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

(Note: Task 6 lands `auditor.py`, so this commit will fail to import H3Auditor at runtime until Task 6 ships. That's fine — we're building bottom-up. The import will be a `try` inside the test runner once added.)

Actually, to keep the commit self-contained and importable, **change the `__init__.py` to defer the auditor import** until it exists. Replace the file with:

```python
"""HTTP/3 validation subsystem.

The optional [h3] extra (`pip install corsair-scan[h3]`) installs aioquic.
This package always imports cleanly; H3Auditor degrades gracefully and
emits a single INFO finding when aioquic is unavailable.
"""

# aioquic-gated: only the client requires the [h3] extra.
try:
    from .client import scan_h3  # noqa: F401
    h3_available = True
except ImportError:
    h3_available = False

# H3Auditor is added in Task 6. Re-export only when present.
try:
    from .auditor import H3Auditor  # noqa: F401
    __all__ = ["H3Auditor", "h3_available"]
except ImportError:
    __all__ = ["h3_available"]
```

Run: `python3 -c "import corsair.h3; print(corsair.h3.h3_available, hasattr(corsair.h3, 'H3Auditor'))"`
Expected: `False False` (aioquic not installed yet, auditor not built yet) — both `try` blocks fail silently as designed.

Now commit:
```bash
git add corsair/models.py corsair/h3/__init__.py
git commit -m "$(cat <<'EOF'
feat(models): add HeaderCategory.H3 enum value and h3 subsystem skeleton

Empty corsair/h3/ package with availability flag mirroring corsair.tls.
Importing the package never raises. The flag h3_available reflects
whether aioquic is installed. The H3Auditor re-export is also guarded so
the package is importable mid-implementation across Tasks 2-6.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: `probe.py` — Alt-Svc target derivation + LSQUIC fingerprint

**Files:**
- Create: `corsair/h3/probe.py`
- Test: `tests/test_h3_probe.py`

Pure-logic helpers. No httpx, no aioquic, no network I/O. Reuses `corsair.cache.altsvc.parse_alt_svc` to avoid duplicating the Alt-Svc grammar.

### Step 2.1: TDD — write the failing tests

- [ ] **Create `tests/test_h3_probe.py`**

```python
"""Tests for corsair.h3.probe."""

import pytest

from corsair.h3.probe import derive_h3_target, is_lsquic_fingerprint


# ---------------------------------------------------------------------------
# derive_h3_target
# ---------------------------------------------------------------------------

class TestDeriveH3Target:
    def test_no_alt_svc_returns_none(self):
        assert derive_h3_target({}, "example.com") is None

    def test_empty_alt_svc_returns_none(self):
        assert derive_h3_target({"Alt-Svc": ""}, "example.com") is None

    def test_clear_alt_svc_returns_none(self):
        assert derive_h3_target({"Alt-Svc": "clear"}, "example.com") is None

    def test_h3_explicit_host_and_port(self):
        headers = {"Alt-Svc": 'h3="alt.example.com:8443"; ma=86400'}
        assert derive_h3_target(headers, "example.com") == ("alt.example.com", 8443)

    def test_h3_omitted_host_falls_back_to_request_host(self):
        # ":443" with no host means "same host as request, port 443"
        headers = {"Alt-Svc": 'h3=":443"; ma=86400'}
        assert derive_h3_target(headers, "example.com") == ("example.com", 443)

    def test_h3_29_draft_protocol_id(self):
        headers = {"Alt-Svc": 'h3-29=":443"; ma=86400'}
        assert derive_h3_target(headers, "example.com") == ("example.com", 443)

    def test_h3_with_other_protocols_picks_h3_first(self):
        # Even if h2 appears earlier, we want the h3 entry
        headers = {"Alt-Svc": 'h2=":443"; ma=86400, h3=":8443"; ma=86400'}
        assert derive_h3_target(headers, "example.com") == ("example.com", 8443)

    def test_no_h3_returns_none(self):
        headers = {"Alt-Svc": 'h2=":443"; ma=86400'}
        assert derive_h3_target(headers, "example.com") is None

    def test_malformed_alt_svc_returns_none(self):
        headers = {"Alt-Svc": "this is not valid alt-svc"}
        assert derive_h3_target(headers, "example.com") is None

    def test_case_insensitive_header_lookup(self):
        # Real-world headers can come back with various casing
        headers = {"alt-svc": 'h3=":443"; ma=86400'}
        assert derive_h3_target(headers, "example.com") == ("example.com", 443)

    def test_picks_first_h3_entry_when_multiple(self):
        headers = {
            "Alt-Svc": 'h3=":443", h3=":8443"',
        }
        assert derive_h3_target(headers, "example.com") == ("example.com", 443)


# ---------------------------------------------------------------------------
# is_lsquic_fingerprint
# ---------------------------------------------------------------------------

class TestLSQUICFingerprint:
    def test_litespeed_with_h3_advertisement(self):
        headers = {"Server": "LiteSpeed/6.0"}
        assert is_lsquic_fingerprint(headers, has_h3_advertisement=True) is True

    def test_openlitespeed_with_h3_advertisement(self):
        headers = {"Server": "OpenLiteSpeed/1.7.18"}
        assert is_lsquic_fingerprint(headers, has_h3_advertisement=True) is True

    def test_litespeed_case_insensitive(self):
        headers = {"Server": "litespeed"}
        assert is_lsquic_fingerprint(headers, has_h3_advertisement=True) is True

    def test_no_h3_advertisement_means_false(self):
        # Even if Server matches, no h3 means we don't have evidence the
        # vulnerable QUIC stack is actually serving HTTP/3 here.
        headers = {"Server": "LiteSpeed/6.0"}
        assert is_lsquic_fingerprint(headers, has_h3_advertisement=False) is False

    def test_word_boundary_prevents_false_positive(self):
        # "LiteSpeedAdapter" is a real Apache module — must NOT match
        headers = {"Server": "Apache/2.4 (LiteSpeedAdapter)"}
        assert is_lsquic_fingerprint(headers, has_h3_advertisement=True) is False

    def test_lsws_alone_does_not_match(self):
        # LSWS abbreviation is not the regex target
        headers = {"Server": "LSWS"}
        assert is_lsquic_fingerprint(headers, has_h3_advertisement=True) is False

    def test_other_servers_do_not_match(self):
        for s in ("nginx/1.27", "Cloudflare", "Caddy/2.7", "Apache/2.4", "Microsoft-IIS/10.0"):
            headers = {"Server": s}
            assert is_lsquic_fingerprint(headers, has_h3_advertisement=True) is False

    def test_missing_server_header(self):
        assert is_lsquic_fingerprint({}, has_h3_advertisement=True) is False

    def test_empty_server_header(self):
        assert is_lsquic_fingerprint({"Server": ""}, has_h3_advertisement=True) is False

    def test_case_insensitive_header_lookup(self):
        headers = {"server": "LiteSpeed/6.0"}
        assert is_lsquic_fingerprint(headers, has_h3_advertisement=True) is True
```

- [ ] **Run tests to verify they fail with import error**

Run: `python3 -m pytest tests/test_h3_probe.py -v 2>&1 | head -10`
Expected: `ImportError: cannot import name 'derive_h3_target' from 'corsair.h3.probe'` (or similar — the module doesn't exist yet).

### Step 2.2: Implement `probe.py`

- [ ] **Create `corsair/h3/probe.py`**

```python
"""Pure-logic helpers for HTTP/3 probing.

derive_h3_target: parse Alt-Svc and pick the first h3* entry as the probe target.
is_lsquic_fingerprint: passive Server-header heuristic for CVE-2025-54939.

No httpx, no aioquic, no network I/O. Reuses corsair.cache.altsvc.parse_alt_svc.
"""

import re
from typing import Mapping, Optional, Tuple

from corsair.cache.altsvc import parse_alt_svc

# Word-boundary regex prevents false positives on "LiteSpeedAdapter" (Apache
# module). \b matches before a transition between word and non-word chars.
_LSQUIC_RE = re.compile(r"\b(litespeed|openlitespeed)\b", re.IGNORECASE)


def _case_insensitive_get(headers: Mapping[str, str], name: str) -> Optional[str]:
    """Look up a header case-insensitively. Returns None if missing."""
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return None


def derive_h3_target(
    headers: Mapping[str, str],
    fallback_host: str,
) -> Optional[Tuple[str, int]]:
    """Parse Alt-Svc and return (host, port) for the first h3* entry, or None.

    - Returns None when Alt-Svc is absent, empty, "clear", malformed, or has no
      h3* protocol-id entry.
    - When the Alt-Svc entry omits the host (e.g., 'h3=":443"'), uses
      fallback_host for the host and the entry's port.
    """
    alt_svc = _case_insensitive_get(headers, "alt-svc")
    if not alt_svc:
        return None

    entries = parse_alt_svc(alt_svc)
    for entry in entries:
        # Match h3, h3-29, h3-32, etc. Lowercased for tolerance.
        if entry.protocol_id.lower().startswith("h3"):
            host = entry.host or fallback_host
            return (host, entry.port)

    return None


def is_lsquic_fingerprint(
    headers: Mapping[str, str],
    has_h3_advertisement: bool,
) -> bool:
    """Return True iff the Server header identifies as LiteSpeed/OpenLiteSpeed
    AND the response advertised h3 in Alt-Svc.

    The has_h3_advertisement guard is the key: an Apache server with an
    "OpenLiteSpeed-Backend" string in its Server header is not vulnerable to
    LSQUIC CVE-2025-54939 unless QUIC is actually being served.
    """
    if not has_h3_advertisement:
        return False
    server = _case_insensitive_get(headers, "server")
    if not server:
        return False
    return bool(_LSQUIC_RE.search(server))
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_h3_probe.py -v 2>&1 | tail -10`
Expected: `~18 passed`.

### Step 2.3: Commit Task 2

- [ ] **Stage and commit**

```bash
git add corsair/h3/probe.py tests/test_h3_probe.py
git commit -m "$(cat <<'EOF'
feat(h3): add probe helpers — Alt-Svc h3 target derivation and LSQUIC fingerprint

derive_h3_target reuses corsair.cache.altsvc.parse_alt_svc so the Alt-Svc
grammar lives in exactly one place. Falls back to the request host when an
Alt-Svc entry omits the host (the common case).

is_lsquic_fingerprint is a passive heuristic for CVE-2025-54939. Word-
boundary regex prevents false positives on "LiteSpeedAdapter" (Apache
module). The has_h3_advertisement guard ensures we only fingerprint when
QUIC is actually being served.

18 unit tests, no network I/O.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `diff.py` — H1/H3 security-header diff

**Files:**
- Create: `corsair/h3/diff.py`
- Test: `tests/test_h3_diff.py`

Pure-logic diff over an explicit security-header allowlist. Three diff buckets: missing-in-h3, missing-in-h1, value-drift.

### Step 3.1: TDD — write the failing tests

- [ ] **Create `tests/test_h3_diff.py`**

```python
"""Tests for corsair.h3.diff."""

import pytest

from corsair.h3.diff import (
    HeaderDiffResult,
    SECURITY_HEADER_ALLOWLIST,
    diff_security_headers,
)


# ---------------------------------------------------------------------------
# Allowlist sanity
# ---------------------------------------------------------------------------

class TestAllowlist:
    def test_allowlist_contains_critical_headers(self):
        for h in (
            "strict-transport-security",
            "content-security-policy",
            "cross-origin-opener-policy",
            "cross-origin-embedder-policy",
            "x-frame-options",
            "x-content-type-options",
            "permissions-policy",
            "integrity-policy",
            "reporting-endpoints",
            "document-isolation-policy",
        ):
            assert h in SECURITY_HEADER_ALLOWLIST, f"missing: {h}"

    def test_allowlist_keys_all_lowercase(self):
        for h in SECURITY_HEADER_ALLOWLIST:
            assert h == h.lower(), f"non-lowercase: {h}"


# ---------------------------------------------------------------------------
# diff_security_headers
# ---------------------------------------------------------------------------

class TestDiffSecurityHeaders:
    def test_identical_headers_return_empty_result(self):
        h1 = {"Strict-Transport-Security": "max-age=31536000"}
        h3 = {"Strict-Transport-Security": "max-age=31536000"}
        result = diff_security_headers(h1, h3)
        assert result.missing_in_h3 == []
        assert result.missing_in_h1 == []
        assert result.value_drift == []

    def test_missing_in_h3(self):
        h1 = {"Strict-Transport-Security": "max-age=31536000"}
        h3 = {}
        result = diff_security_headers(h1, h3)
        assert result.missing_in_h3 == ["Strict-Transport-Security"]
        assert result.missing_in_h1 == []
        assert result.value_drift == []

    def test_missing_in_h1(self):
        h1 = {}
        h3 = {"Strict-Transport-Security": "max-age=31536000"}
        result = diff_security_headers(h1, h3)
        assert result.missing_in_h3 == []
        assert result.missing_in_h1 == ["Strict-Transport-Security"]
        assert result.value_drift == []

    def test_value_drift(self):
        h1 = {"Strict-Transport-Security": "max-age=31536000"}
        h3 = {"Strict-Transport-Security": "max-age=0"}
        result = diff_security_headers(h1, h3)
        assert result.missing_in_h3 == []
        assert result.missing_in_h1 == []
        assert result.value_drift == [
            ("Strict-Transport-Security", "max-age=31536000", "max-age=0"),
        ]

    def test_multiple_missing_sorted(self):
        h1 = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
        }
        h3 = {}
        result = diff_security_headers(h1, h3)
        # Output is sorted for deterministic finding text
        assert result.missing_in_h3 == sorted([
            "Strict-Transport-Security",
            "X-Frame-Options",
            "Content-Security-Policy",
        ])

    def test_case_insensitive_header_keys(self):
        # Headers may come back with different casing on each protocol.
        # Lowercased internally for comparison; output preserves H1 casing.
        h1 = {"strict-transport-security": "max-age=31536000"}
        h3 = {"STRICT-TRANSPORT-SECURITY": "max-age=31536000"}
        result = diff_security_headers(h1, h3)
        assert result.missing_in_h3 == []
        assert result.missing_in_h1 == []
        assert result.value_drift == []

    def test_value_comparison_is_case_sensitive(self):
        # "max-age=0" vs "MAX-AGE=0" is a real misconfig shape worth flagging
        h1 = {"Strict-Transport-Security": "max-age=0"}
        h3 = {"Strict-Transport-Security": "MAX-AGE=0"}
        result = diff_security_headers(h1, h3)
        assert len(result.value_drift) == 1

    def test_non_allowlist_headers_ignored(self):
        # Server, Date, Content-Length etc. legitimately differ — not flagged.
        h1 = {"Date": "Wed, 07 May 2026 12:00:00 GMT", "Server": "nginx"}
        h3 = {"Date": "Wed, 07 May 2026 12:00:01 GMT", "Server": "nginx-quic"}
        result = diff_security_headers(h1, h3)
        assert result.missing_in_h3 == []
        assert result.missing_in_h1 == []
        assert result.value_drift == []

    def test_combined_drift_modes(self):
        h1 = {
            "Strict-Transport-Security": "max-age=31536000",  # value drift
            "X-Frame-Options": "DENY",                         # missing in h3
        }
        h3 = {
            "Strict-Transport-Security": "max-age=0",
            "Cross-Origin-Opener-Policy": "same-origin",       # missing in h1
        }
        result = diff_security_headers(h1, h3)
        assert result.missing_in_h3 == ["X-Frame-Options"]
        assert result.missing_in_h1 == ["Cross-Origin-Opener-Policy"]
        assert result.value_drift == [
            ("Strict-Transport-Security", "max-age=31536000", "max-age=0"),
        ]

    def test_value_drift_output_sorted_by_header_name(self):
        h1 = {
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
        }
        h3 = {
            "X-Frame-Options": "SAMEORIGIN",
            "Strict-Transport-Security": "max-age=0",
        }
        result = diff_security_headers(h1, h3)
        names = [t[0] for t in result.value_drift]
        assert names == sorted(names)
```

- [ ] **Run tests to verify they fail**

Run: `python3 -m pytest tests/test_h3_diff.py -v 2>&1 | head -10`
Expected: `ImportError: cannot import name 'diff_security_headers' from 'corsair.h3.diff'`.

### Step 3.2: Implement `diff.py`

- [ ] **Create `corsair/h3/diff.py`**

```python
"""H1/H3 security-header diff.

Pure-logic comparison over an explicit allowlist. Three diff buckets:
  - missing_in_h3: present in H1, absent in H3
  - missing_in_h1: present in H3, absent in H1
  - value_drift:   present in both with different values

Header keys compared case-insensitively. Header values compared
case-sensitively (e.g., 'max-age=0' vs 'MAX-AGE=0' is a real misconfig).
Output lists are sorted for deterministic finding text.
"""

from dataclasses import dataclass, field
from typing import List, Mapping, Tuple


SECURITY_HEADER_ALLOWLIST: frozenset = frozenset({
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
    missing_in_h3: List[str] = field(default_factory=list)
    missing_in_h1: List[str] = field(default_factory=list)
    value_drift: List[Tuple[str, str, str]] = field(default_factory=list)


def _restricted_lowercased(headers: Mapping[str, str]) -> dict:
    """Return a dict containing only allowlist headers, with lowercased keys.

    Header values are kept verbatim. The display-cased name is preserved as
    a parallel dict mapping lowercase -> original casing for output formatting.
    """
    lowered: dict = {}
    display: dict = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl in SECURITY_HEADER_ALLOWLIST:
            lowered[kl] = v
            display[kl] = k
    return lowered, display


def diff_security_headers(
    h1: Mapping[str, str],
    h3: Mapping[str, str],
) -> HeaderDiffResult:
    """Diff security-relevant headers between H1 and H3 responses.

    Returns a HeaderDiffResult with three populated lists. Lists are sorted by
    header display name (preferring H1 casing when both sides have the header).
    """
    h1_l, h1_disp = _restricted_lowercased(h1)
    h3_l, h3_disp = _restricted_lowercased(h3)

    missing_in_h3: List[str] = []
    missing_in_h1: List[str] = []
    value_drift: List[Tuple[str, str, str]] = []

    for key in h1_l:
        if key not in h3_l:
            missing_in_h3.append(h1_disp[key])
        elif h1_l[key] != h3_l[key]:
            # Prefer H1 display casing for the header name in the drift tuple.
            value_drift.append((h1_disp[key], h1_l[key], h3_l[key]))

    for key in h3_l:
        if key not in h1_l:
            missing_in_h1.append(h3_disp[key])

    missing_in_h3.sort()
    missing_in_h1.sort()
    value_drift.sort(key=lambda t: t[0])

    return HeaderDiffResult(
        missing_in_h3=missing_in_h3,
        missing_in_h1=missing_in_h1,
        value_drift=value_drift,
    )
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_h3_diff.py -v 2>&1 | tail -10`
Expected: `~22 passed`.

### Step 3.3: Commit Task 3

- [ ] **Stage and commit**

```bash
git add corsair/h3/diff.py tests/test_h3_diff.py
git commit -m "$(cat <<'EOF'
feat(h3): add H1/H3 security-header diff

Allowlist-driven comparison over 18 security-relevant headers covering
HSTS, CSP, COOP/COEP/CORP, X-Frame-Options, Permissions-Policy,
Integrity-Policy, Reporting-Endpoints, and Document-Isolation-Policy.

Three diff buckets returned: missing_in_h3, missing_in_h1, value_drift.
Header keys lowercased for comparison; values compared case-sensitively
(e.g., max-age=0 vs MAX-AGE=0 is a real misconfig). Output lists sorted
for deterministic finding text.

22 unit tests, no network I/O.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `findings.py` — finding templates and builders

**Files:**
- Create: `corsair/h3/findings.py`
- Test: `tests/test_h3_findings.py`

Three core finding templates (H3-001/002/003) plus PASS variants and INFO auxiliaries. Builder functions inject runtime context into deepcopies of the templates.

### Step 4.1: TDD — write the failing tests

- [ ] **Create `tests/test_h3_findings.py`**

```python
"""Tests for corsair.h3.findings — template metadata shape and builder API."""

import pytest

from corsair.h3.diff import HeaderDiffResult
from corsair.h3.findings import (
    build_h3_001_high,
    build_h3_001_low,
    build_h3_001_pass,
    build_h3_002_finding,
    build_h3_002_pass,
    build_h3_003_finding,
    build_h3_inconclusive_finding,
    build_h3_extras_missing_finding,
    get_finding,
)
from corsair.models import HeaderCategory, Severity


class TestRegistry:
    def test_get_finding_returns_deepcopy(self):
        a = get_finding("H3-001-HIGH")
        b = get_finding("H3-001-HIGH")
        a.title = "mutated"
        assert b.title != "mutated"

    def test_unknown_finding_returns_none(self):
        assert get_finding("BOGUS") is None


class TestH3001SeverityTiers:
    def test_high_tier(self):
        f = build_h3_001_high(early_data_capability=16384, status=200)
        assert f.severity == Severity.HIGH
        assert f.category == HeaderCategory.H3
        assert "HTTP/3 0-RTT" in f.title
        assert "16384" in (f.current_value or "")
        assert "200" in (f.current_value or "")

    def test_low_tier(self):
        f = build_h3_001_low(status=200)
        assert f.severity == Severity.LOW
        assert f.category == HeaderCategory.H3

    def test_pass_tier(self):
        f = build_h3_001_pass(early_data_capability=16384)
        assert f.severity == Severity.PASS
        assert f.category == HeaderCategory.H3


class TestH3002Diff:
    def test_missing_in_h3_only_is_medium(self):
        d = HeaderDiffResult(
            missing_in_h3=["Strict-Transport-Security"],
            missing_in_h1=[],
            value_drift=[],
        )
        f = build_h3_002_finding(d)
        assert f.severity == Severity.MEDIUM
        assert "Strict-Transport-Security" in f.description
        assert "Missing on HTTP/3" in f.description

    def test_value_drift_only_is_medium(self):
        d = HeaderDiffResult(
            missing_in_h3=[],
            missing_in_h1=[],
            value_drift=[("X-Frame-Options", "DENY", "SAMEORIGIN")],
        )
        f = build_h3_002_finding(d)
        assert f.severity == Severity.MEDIUM
        assert "X-Frame-Options" in f.description
        assert "DENY" in f.description and "SAMEORIGIN" in f.description

    def test_missing_in_h1_only_is_low(self):
        d = HeaderDiffResult(
            missing_in_h3=[],
            missing_in_h1=["Cross-Origin-Opener-Policy"],
            value_drift=[],
        )
        f = build_h3_002_finding(d)
        assert f.severity == Severity.LOW

    def test_combined_drift_modes_use_max_severity(self):
        d = HeaderDiffResult(
            missing_in_h3=["Strict-Transport-Security"],
            missing_in_h1=["Cross-Origin-Opener-Policy"],
            value_drift=[("X-Frame-Options", "DENY", "SAMEORIGIN")],
        )
        f = build_h3_002_finding(d)
        assert f.severity == Severity.MEDIUM  # MEDIUM > LOW

    def test_pass_when_no_drift(self):
        f = build_h3_002_pass()
        assert f.severity == Severity.PASS
        assert f.category == HeaderCategory.H3


class TestH3003LSQUIC:
    def test_critical_severity(self):
        f = build_h3_003_finding()
        assert f.severity == Severity.CRITICAL
        assert f.category == HeaderCategory.H3
        assert "CVE-2025-54939" in f.description or "LSQUIC" in f.title


class TestAuxiliaryFindings:
    def test_inconclusive_carries_error_in_current_value(self):
        f = build_h3_inconclusive_finding(error="timeout after 10s")
        assert f.severity == Severity.INFO
        assert "timeout after 10s" in (f.current_value or "")

    def test_extras_missing_finding(self):
        f = build_h3_extras_missing_finding()
        assert f.severity == Severity.INFO
        assert "[h3]" in f.description or "pip install" in f.description


class TestComplianceMappings:
    def test_h3_001_compliance(self):
        f = build_h3_001_high(early_data_capability=16384, status=200)
        framework_ids = {(c.framework, c.requirement_id) for c in f.compliance_mappings}
        assert ("OWASP_TOP_10_2021", "A07") in framework_ids

    def test_h3_002_compliance(self):
        d = HeaderDiffResult(missing_in_h3=["Strict-Transport-Security"])
        f = build_h3_002_finding(d)
        framework_ids = {(c.framework, c.requirement_id) for c in f.compliance_mappings}
        assert ("OWASP_TOP_10_2021", "A05") in framework_ids
        assert ("PCI_DSS_4_0", "6.4.3") in framework_ids

    def test_h3_003_compliance(self):
        f = build_h3_003_finding()
        framework_ids = {(c.framework, c.requirement_id) for c in f.compliance_mappings}
        assert ("OWASP_TOP_10_2021", "A06") in framework_ids
```

- [ ] **Run to verify failure**

Run: `python3 -m pytest tests/test_h3_findings.py -v 2>&1 | head -10`
Expected: `ImportError`.

### Step 4.2: Implement `findings.py`

- [ ] **Create `corsair/h3/findings.py`**

```python
"""HTTP/3 finding templates and builders.

Mirrors corsair/integrity_policy/findings.py. Public API:
  - get_finding(finding_id) -> Finding | None  (deepcopy of static template)
  - build_h3_001_high / _low / _pass
  - build_h3_002_finding / _pass
  - build_h3_003_finding
  - build_h3_inconclusive_finding(error)
  - build_h3_extras_missing_finding()
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
from .diff import HeaderDiffResult


# ---------------------------------------------------------------------------
# DRY helpers
# ---------------------------------------------------------------------------

def _compliance(framework: str, req_id: str, req_name: str, status: str = "FAIL") -> ComplianceMapping:
    return ComplianceMapping(
        framework=framework, requirement_id=req_id, requirement_name=req_name, status=status,
    )


def _cwe(cwe_id: str, desc: str) -> CVECorrelation:
    return CVECorrelation(cve_id=cwe_id, cvss_score=0.0, description=desc)


def _cve(cve_id: str, desc: str, cvss: float) -> CVECorrelation:
    return CVECorrelation(cve_id=cve_id, cvss_score=cvss, description=desc)


# ---------------------------------------------------------------------------
# Compliance / CWE constants
# ---------------------------------------------------------------------------

_OWASP_A05 = _compliance("OWASP_TOP_10_2021", "A05", "Security Misconfiguration")
_OWASP_A06 = _compliance("OWASP_TOP_10_2021", "A06", "Vulnerable and Outdated Components")
_OWASP_A07 = _compliance("OWASP_TOP_10_2021", "A07", "Identification and Authentication Failures")
_PCI_6_2_4 = _compliance("PCI_DSS_4_0", "6.2.4", "Software protected against common attacks")
_PCI_6_4_3 = _compliance("PCI_DSS_4_0", "6.4.3", "Manage all payment page scripts loaded in the browser")
_NIST_SC_23 = _compliance("NIST_SP_800_53", "SC-23", "Session Authenticity")
_NIST_SP_800_52 = _compliance("NIST_SP_800_53", "SC-12", "TLS 1.3 0-RTT guidance (SP 800-52r2 §3.6)")
_NIST_RA_5 = _compliance("NIST_SP_800_53", "RA-5", "Vulnerability Monitoring and Scanning")

_CWE_294 = _cwe("CWE-294", "Authentication Bypass by Capture-Replay")
_CWE_400 = _cwe("CWE-400", "Uncontrolled Resource Consumption")
_CWE_770 = _cwe("CWE-770", "Allocation of Resources Without Limits or Throttling")
_CWE_693 = _cwe("CWE-693", "Protection Mechanism Failure")
_CVE_2024_39321 = _cve("CVE-2024-39321", "Traefik IP-allowlist bypass via 0-RTT", 7.5)
_CVE_2025_54939 = _cve("CVE-2025-54939", "LSQUIC pre-handshake memory exhaustion", 9.1)


_REF_RFC_8470 = "https://www.rfc-editor.org/rfc/rfc8470.html"
_REF_RFC_9114 = "https://www.rfc-editor.org/rfc/rfc9114.html"
_REF_LSQUIC_ADVISORY = "https://github.com/litespeedtech/lsquic/security/advisories"


# ---------------------------------------------------------------------------
# Static templates (no per-scan context)
# ---------------------------------------------------------------------------

_H3_001_HIGH_TEMPLATE = Finding(
    header="QUIC Early Data",
    category=HeaderCategory.H3,
    severity=Severity.HIGH,
    title="HTTP/3 0-RTT — server vulnerable to early-data replay",
    description=(
        "The server advertises 0-RTT capability via TLS 1.3 NewSessionTicket "
        "(max_early_data_size > 0) and does NOT reject requests carrying the "
        "Early-Data: 1 hint with HTTP 425 Too Early. An on-path attacker can "
        "replay any captured 0-RTT request, including non-idempotent operations "
        "(POST, PUT, DELETE), against the same server until the session ticket "
        "expires. RFC 8470 mandates that early-data-aware servers reject "
        "non-idempotent requests with 425.\n\n"
        "Real-world exploitation has been demonstrated in CVE-2024-39321 "
        "(Traefik IP-allowlist bypass via 0-RTT replay)."
    ),
    current_value=None,
    recommendation=(
        "Disable 0-RTT on the QUIC listener (set max_early_data_size=0) OR "
        "honor RFC 8470 by returning 425 Too Early when Early-Data: 1 is "
        "present and the request is non-idempotent."
    ),
    example_value="max_early_data_size=0  (disabled)",
    reference_url=_REF_RFC_8470,
    cve_correlations=[_CVE_2024_39321, _CWE_294],
    compliance_mappings=[_OWASP_A07, _PCI_6_2_4, _NIST_SP_800_52],
)

_H3_001_LOW_TEMPLATE = Finding(
    header="QUIC Early Data",
    category=HeaderCategory.H3,
    severity=Severity.LOW,
    title="HTTP/3 0-RTT — early-data hint not honored (low risk)",
    description=(
        "The server does NOT advertise 0-RTT capability (max_early_data_size = 0) "
        "but also does not reject requests with the Early-Data: 1 hint via "
        "HTTP 425. There is no actual replay vector here — without 0-RTT, "
        "there is no early data to replay — but the proxy/origin may be "
        "misconfigured: an upstream proxy that DOES accept 0-RTT could forward "
        "to this origin and the origin would not protect non-idempotent "
        "requests. RFC 8470 recommends honoring Early-Data: 1 even when the "
        "origin itself does not accept 0-RTT directly."
    ),
    current_value=None,
    recommendation=(
        "If a proxy in front of this origin accepts 0-RTT, configure the origin "
        "to return 425 Too Early when Early-Data: 1 is present and the request "
        "is non-idempotent. RFC 8470 §5."
    ),
    example_value="HTTP/1.1 425 Too Early",
    reference_url=_REF_RFC_8470,
    cve_correlations=[_CWE_294],
    compliance_mappings=[_OWASP_A07, _NIST_SP_800_52],
)

_H3_001_PASS_TEMPLATE = Finding(
    header="QUIC Early Data",
    category=HeaderCategory.H3,
    severity=Severity.PASS,
    title="HTTP/3 0-RTT — server correctly rejects early-data hints",
    description=(
        "The server advertises 0-RTT capability AND correctly rejects requests "
        "with the Early-Data: 1 hint via HTTP 425 Too Early per RFC 8470. "
        "This is the secure configuration."
    ),
    current_value=None,
    recommendation="No action required. Configuration is correct.",
    example_value=None,
    reference_url=_REF_RFC_8470,
    cve_correlations=[],
    compliance_mappings=[
        ComplianceMapping(
            framework="OWASP_TOP_10_2021", requirement_id="A07",
            requirement_name="Identification and Authentication Failures",
            status="PASS",
        ),
    ],
)


_H3_002_PASS_TEMPLATE = Finding(
    header="HTTP/3 vs HTTP/1.1 Headers",
    category=HeaderCategory.H3,
    severity=Severity.PASS,
    title="HTTP/3 and HTTP/1.1 security headers are consistent",
    description=(
        "The security-relevant response headers are identical across HTTP/1.1 "
        "and HTTP/3. No drift was detected in HSTS, CSP, COOP/COEP, X-Frame-"
        "Options, or other allowlist headers."
    ),
    current_value=None,
    recommendation="No action required.",
    example_value=None,
    reference_url=_REF_RFC_9114,
    cve_correlations=[],
    compliance_mappings=[
        ComplianceMapping(
            framework="OWASP_TOP_10_2021", requirement_id="A05",
            requirement_name="Security Misconfiguration",
            status="PASS",
        ),
    ],
)


_H3_003_TEMPLATE = Finding(
    header="QUIC Server",
    category=HeaderCategory.H3,
    severity=Severity.CRITICAL,
    title="LSQUIC pre-handshake DoS (CVE-2025-54939)",
    description=(
        "The Server header identifies LiteSpeed/OpenLiteSpeed AND the response "
        "advertises HTTP/3 via Alt-Svc. LiteSpeed's QUIC implementation (LSQUIC) "
        "before version 4.3.1 is vulnerable to CVE-2025-54939, a pre-handshake "
        "memory-exhaustion DoS. An unauthenticated remote attacker can crash the "
        "QUIC worker process by sending a small volume of malformed handshake "
        "packets.\n\n"
        "This finding is passive — Corsair did not exploit the vulnerability. "
        "It correlates the Server identification with the presence of an h3 "
        "advertisement to confirm the vulnerable QUIC stack is actually serving "
        "HTTP/3 here. Active probing is not required."
    ),
    current_value=None,
    recommendation=(
        "Upgrade to LSQUIC 4.3.1 or later (LiteSpeed Web Server 6.3.x+ or "
        "OpenLiteSpeed 1.8.x+). If immediate upgrade is not possible, disable "
        "HTTP/3 advertisement in the Alt-Svc header until patched."
    ),
    example_value="Server: LiteSpeed/6.3.0",
    reference_url=_REF_LSQUIC_ADVISORY,
    cve_correlations=[_CVE_2025_54939, _CWE_400, _CWE_770],
    compliance_mappings=[_OWASP_A06, _PCI_6_2_4, _NIST_RA_5],
)


_H3_INCONCLUSIVE_TEMPLATE = Finding(
    header="HTTP/3 Probe",
    category=HeaderCategory.H3,
    severity=Severity.INFO,
    title="HTTP/3 probe inconclusive",
    description=(
        "The QUIC handshake or HEAD request did not complete. This is INFO-only: "
        "could be a firewall blocking UDP/443, an unsupported QUIC version, an "
        "ALPN mismatch, or a real configuration gap. The H1/H3 diff and 0-RTT "
        "checks could not be evaluated. The error class is recorded in "
        "current_value below."
    ),
    current_value=None,
    recommendation=(
        "If UDP/443 is intentionally blocked, ignore. Otherwise verify the "
        "QUIC listener is reachable from the scanning host."
    ),
    example_value=None,
    reference_url=_REF_RFC_9114,
    cve_correlations=[],
    compliance_mappings=[],
)


_H3_EXTRAS_MISSING_TEMPLATE = Finding(
    header="HTTP/3 Probe",
    category=HeaderCategory.H3,
    severity=Severity.INFO,
    title="HTTP/3 validation skipped — [h3] extra not installed",
    description=(
        "Corsair was invoked with --h3-probe enabled but the optional [h3] "
        "extra (which installs aioquic) is not present in the environment. "
        "HTTP/3 validation findings (H3-001/002/003) cannot be evaluated."
    ),
    current_value=None,
    recommendation="Run `pip install corsair-scan[h3]` to enable HTTP/3 probing.",
    example_value=None,
    reference_url=_REF_RFC_9114,
    cve_correlations=[],
    compliance_mappings=[],
)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: dict = {
    "H3-001-HIGH": _H3_001_HIGH_TEMPLATE,
    "H3-001-LOW": _H3_001_LOW_TEMPLATE,
    "H3-001-PASS": _H3_001_PASS_TEMPLATE,
    "H3-002-PASS": _H3_002_PASS_TEMPLATE,
    "H3-003": _H3_003_TEMPLATE,
    "H3-INCONCLUSIVE": _H3_INCONCLUSIVE_TEMPLATE,
    "H3-EXTRAS-MISSING": _H3_EXTRAS_MISSING_TEMPLATE,
}


def get_finding(finding_id: str) -> Optional[Finding]:
    """Return a deepcopy of the static template for a finding ID."""
    template = _REGISTRY.get(finding_id)
    if template is None:
        return None
    return copy.deepcopy(template)


# ---------------------------------------------------------------------------
# Builders — runtime context injected
# ---------------------------------------------------------------------------

def build_h3_001_high(early_data_capability: int, status: int) -> Finding:
    f = get_finding("H3-001-HIGH")
    f.current_value = (
        f"max_early_data_size={early_data_capability}, response_status={status}"
    )
    return f


def build_h3_001_low(status: int) -> Finding:
    f = get_finding("H3-001-LOW")
    f.current_value = f"max_early_data_size=0, response_status={status}"
    return f


def build_h3_001_pass(early_data_capability: int) -> Finding:
    f = get_finding("H3-001-PASS")
    f.current_value = f"max_early_data_size={early_data_capability}, response_status=425"
    return f


def build_h3_002_finding(diff: HeaderDiffResult) -> Finding:
    """Single bundled finding describing all active drift modes.

    Severity = max of active modes:
      - missing_in_h3 OR value_drift -> MEDIUM
      - else missing_in_h1            -> LOW
    """
    severity = (
        Severity.MEDIUM
        if (diff.missing_in_h3 or diff.value_drift)
        else Severity.LOW
    )
    sections = []
    if diff.missing_in_h3:
        sections.append("Missing on HTTP/3: " + ", ".join(diff.missing_in_h3))
    if diff.value_drift:
        drift_lines = [
            f"{name} (H1={h1!r}, H3={h3!r})" for name, h1, h3 in diff.value_drift
        ]
        sections.append("Value drift: " + "; ".join(drift_lines))
    if diff.missing_in_h1:
        sections.append("Missing on HTTP/1.1: " + ", ".join(diff.missing_in_h1))

    description = (
        "Security headers differ between HTTP/1.1 and HTTP/3:\n\n"
        + "\n".join(sections)
        + "\n\nAll security headers should be applied at the HTTP layer, not "
        "tied to specific TCP/QUIC listener configuration. Header drift between "
        "protocols is typically caused by separate vhost blocks for the QUIC "
        "listener that have diverged from the HTTP/1.1 configuration."
    )
    return Finding(
        header="HTTP/3 vs HTTP/1.1 Headers",
        category=HeaderCategory.H3,
        severity=severity,
        title="HTTP/3 and HTTP/1.1 security headers diverge",
        description=description,
        current_value=None,
        recommendation=(
            "Audit the QUIC listener configuration. Apply security headers at the "
            "HTTP layer (middleware, framework) rather than per-listener."
        ),
        example_value=None,
        reference_url=_REF_RFC_9114,
        cve_correlations=[_CWE_693],
        compliance_mappings=[_OWASP_A05, _PCI_6_4_3, _NIST_SC_23],
    )


def build_h3_002_pass() -> Finding:
    return get_finding("H3-002-PASS")


def build_h3_003_finding() -> Finding:
    return get_finding("H3-003")


def build_h3_inconclusive_finding(error: str) -> Finding:
    f = get_finding("H3-INCONCLUSIVE")
    f.current_value = error
    return f


def build_h3_extras_missing_finding() -> Finding:
    return get_finding("H3-EXTRAS-MISSING")
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_h3_findings.py -v 2>&1 | tail -10`
Expected: `~10 passed`.

### Step 4.3: Commit Task 4

- [ ] **Stage and commit**

```bash
git add corsair/h3/findings.py tests/test_h3_findings.py
git commit -m "$(cat <<'EOF'
feat(h3): add finding templates and builders for H3-001/002/003 plus auxiliaries

Three core findings:
  H3-001 (HIGH/LOW/PASS) — 0-RTT replay vulnerability tier matrix
  H3-002 (MEDIUM/LOW/PASS) — H1/H3 security-header divergence (bundled)
  H3-003 (CRITICAL) — LSQUIC pre-handshake DoS fingerprint (CVE-2025-54939)

Plus auxiliaries (INFO):
  H3-INCONCLUSIVE — probe failed, error class in current_value
  H3-EXTRAS-MISSING — [h3] extra not installed

CVE correlations: CVE-2024-39321, CVE-2025-54939; CWE-294, CWE-400,
CWE-693, CWE-770. Compliance mappings: OWASP A05/A06/A07; PCI-DSS
6.2.4/6.4.3; NIST SC-23/RA-5/SP-800-52r2.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `client.py` — async aioquic-backed H3 client + integration smoke

**Files:**
- Create: `corsair/h3/client.py`
- Create: `tests/h3_server.py` (pytest fixture)
- Create: `tests/test_h3_integration.py`
- Modify: `pyproject.toml` — add `[h3]` extras

This task is the only one that touches `aioquic`. Tests are split: pure-logic unit tests for `H3ScanResult` shape go in `test_h3_integration.py` alongside the 3 integration tests, all gated by `pytest.importorskip("aioquic")`.

### Step 5.1: Add `[h3]` extras to `pyproject.toml`

- [ ] **Modify `pyproject.toml`**

Locate `[project.optional-dependencies]` (or create it under `[project]`). Add:

```toml
[project.optional-dependencies]
h3 = [
    "aioquic>=1.3.0,<2.0",
]
```

If the section already exists with other extras, append the `h3` entry without removing the others.

- [ ] **Install the extra in the dev env so subsequent steps can run**

Run: `pip install -e ".[h3]"`
Expected: `Successfully installed aioquic-1.x.x ...`

### Step 5.2: Create the pytest fixture for an in-process H3 server

- [ ] **Create `tests/h3_server.py`**

```python
"""Pytest fixture: in-process aioquic H3 server for integration tests.

Skipped automatically if aioquic is not installed (pytest.importorskip).
The fixture yields (host, port, knobs) where `knobs` is a dict the test can
mutate to control server behavior:

    knobs["response_status"] = 425        # default 200
    knobs["max_early_data_size"] = 16384  # default 0 (no 0-RTT)
    knobs["response_headers"] = {...}     # default {"server": "test/1.0"}
"""

import asyncio
import datetime
import socket
import ssl
import tempfile
from typing import Iterator

import pytest

aioquic = pytest.importorskip("aioquic")

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, H3_ALPN
from aioquic.h3.events import H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _generate_self_signed_cert() -> tuple[str, str]:
    """Return (cert_path, key_path) for a freshly generated self-signed cert."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tempfile.NamedTemporaryFile(suffix=".pem", delete=False).name
    key_path = tempfile.NamedTemporaryFile(suffix=".pem", delete=False).name
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    return cert_path, key_path


class _ConfigurableH3Protocol(QuicConnectionProtocol):
    """H3 server protocol that responds based on a shared knobs dict."""

    knobs: dict = {}  # set by the fixture

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3: H3Connection | None = None

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._h3 is None:
            self._h3 = H3Connection(self._quic)
        for h3_event in self._h3.handle_event(event):
            self._handle_h3_event(h3_event)

    def _handle_h3_event(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived) and event.stream_ended:
            knobs = type(self).knobs
            status = str(knobs.get("response_status", 200)).encode()
            extra = knobs.get("response_headers", {"server": "test/1.0"})
            headers = [(b":status", status)]
            for k, v in extra.items():
                headers.append((k.encode(), v.encode()))
            self._h3.send_headers(stream_id=event.stream_id, headers=headers, end_stream=True)
            self.transmit()


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def h3_server() -> Iterator[tuple[str, int, dict]]:
    """Spawn an in-process aioquic H3 server. Yields (host, port, knobs)."""
    cert_path, key_path = _generate_self_signed_cert()
    port = _free_udp_port()
    knobs: dict = {}
    _ConfigurableH3Protocol.knobs = knobs

    config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    config.load_cert_chain(cert_path, key_path)
    if knobs.get("max_early_data_size", 0):
        config.max_early_data_size = knobs["max_early_data_size"]

    loop = asyncio.new_event_loop()
    server = None

    async def _start():
        nonlocal server
        server = await serve(
            host="127.0.0.1",
            port=port,
            configuration=config,
            create_protocol=_ConfigurableH3Protocol,
        )

    loop.run_until_complete(_start())

    # Run the loop in a daemon thread so tests can drive the client synchronously.
    import threading

    def _run_loop():
        loop.run_forever()

    t = threading.Thread(target=_run_loop, daemon=True)
    t.start()

    try:
        yield ("127.0.0.1", port, knobs)
    finally:
        if server is not None:
            for transport in server:
                transport.close()
        loop.call_soon_threadsafe(loop.stop)
        t.join(timeout=2)
```

### Step 5.3: TDD — write the integration tests

- [ ] **Create `tests/test_h3_integration.py`**

```python
"""Integration tests for corsair.h3.client against a local aioquic server.

Skipped when aioquic is not installed.
"""

import asyncio
import pytest

aioquic = pytest.importorskip("aioquic")

from corsair.h3.client import scan_h3
from tests.h3_server import h3_server  # fixture import


def test_h3_client_handshake_and_head_request(h3_server):
    host, port, knobs = h3_server
    knobs["response_status"] = 200
    knobs["response_headers"] = {"strict-transport-security": "max-age=31536000"}

    result = asyncio.run(scan_h3(
        url=f"https://{host}:{port}/",
        timeout=5.0,
        verify_tls=False,  # self-signed cert
    ))

    assert result.error is None, result.error
    assert result.status == 200
    assert "strict-transport-security" in result.headers
    assert result.headers["strict-transport-security"] == "max-age=31536000"


def test_h3_client_captures_session_ticket_capability(h3_server):
    host, port, knobs = h3_server
    knobs["max_early_data_size"] = 16384

    result = asyncio.run(scan_h3(
        url=f"https://{host}:{port}/",
        timeout=5.0,
        verify_tls=False,
    ))
    assert result.early_data_capability == 16384


def test_h3_client_handles_425_too_early(h3_server):
    host, port, knobs = h3_server
    knobs["response_status"] = 425

    result = asyncio.run(scan_h3(
        url=f"https://{host}:{port}/",
        timeout=5.0,
        verify_tls=False,
    ))
    assert result.status == 425
```

- [ ] **Run integration tests to verify they fail with import error**

Run: `python3 -m pytest tests/test_h3_integration.py -v 2>&1 | head -10`
Expected: `ImportError: cannot import name 'scan_h3' from 'corsair.h3.client'`.

### Step 5.4: Implement `client.py`

- [ ] **Create `corsair/h3/client.py`**

```python
"""aioquic-backed HTTP/3 scanner.

This module's import succeeds only when the [h3] extra is installed.
Public surface:
    H3ScanResult — frozen dataclass with status, headers, error, etc.
    scan_h3(url, timeout, user_agent, verify_tls) — async coroutine.
"""

import asyncio
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

# The aioquic imports below raise ImportError when [h3] extra is absent.
# corsair/h3/__init__.py catches that to set H3_AVAILABLE=False.
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, H3_ALPN
from aioquic.h3.events import H3Event, HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent


@dataclass(frozen=True)
class H3ScanResult:
    url: str
    status: Optional[int] = None
    headers: dict = field(default_factory=dict)
    quic_version: Optional[int] = None
    early_data_capability: int = 0
    error: Optional[str] = None
    duration_ms: float = 0.0


class _CorsairH3Protocol(QuicConnectionProtocol):
    """Captures session ticket and HEAD response headers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3: Optional[H3Connection] = None
        self._response_headers: dict = {}
        self._response_status: Optional[int] = None
        self._done = asyncio.Event()
        self.early_data_capability: int = 0

    def session_ticket_handler(self, ticket) -> None:
        # aioquic exposes max_early_data_size on the ticket object.
        # On servers that support 0-RTT it will be > 0.
        self.early_data_capability = getattr(ticket, "max_early_data_size", 0) or 0

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._h3 is None:
            self._h3 = H3Connection(self._quic)
        for h3_event in self._h3.handle_event(event):
            self._handle_h3_event(h3_event)

    def _handle_h3_event(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            for name, value in event.headers:
                key = name.decode().lower()
                val = value.decode(errors="replace")
                if key == ":status":
                    self._response_status = int(val)
                else:
                    self._response_headers[key] = val
            if event.stream_ended:
                self._done.set()
        elif isinstance(event, DataReceived):
            if event.stream_ended:
                self._done.set()

    async def head_request(
        self, parsed, user_agent: str, timeout: float
    ) -> tuple[Optional[int], dict]:
        stream_id = self._quic.get_next_available_stream_id()
        self._h3.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"HEAD"),
                (b":scheme", b"https"),
                (b":authority", parsed.netloc.encode()),
                (b":path", (parsed.path or "/").encode()),
                (b"user-agent", user_agent.encode()),
                # RFC 8470 hint: ask the origin to act as if this came via 0-RTT.
                (b"early-data", b"1"),
            ],
            end_stream=True,
        )
        self.transmit()
        try:
            await asyncio.wait_for(self._done.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass
        return self._response_status, self._response_headers


async def scan_h3(
    url: str,
    timeout: float = 10.0,
    user_agent: str = "Corsair/0.6.0 (HTTP Security Scanner)",
    verify_tls: bool = True,
) -> H3ScanResult:
    """Connect to (host, port) over QUIC + H3, send HEAD with Early-Data: 1,
    return H3ScanResult. Never raises; errors are returned in result.error.
    """
    started = time.time()
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443

    if host is None:
        return H3ScanResult(url=url, error="invalid url: no host")

    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    if not verify_tls:
        config.verify_mode = ssl.CERT_NONE

    try:
        async with connect(
            host=host,
            port=port,
            configuration=config,
            create_protocol=_CorsairH3Protocol,
            wait_connected=True,
        ) as protocol:
            try:
                await asyncio.wait_for(
                    protocol.head_request(parsed, user_agent, timeout=timeout),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                return H3ScanResult(
                    url=url,
                    error=f"timeout after {timeout}s",
                    duration_ms=(time.time() - started) * 1000,
                )

            return H3ScanResult(
                url=url,
                status=protocol._response_status,
                headers=dict(protocol._response_headers),
                quic_version=getattr(protocol._quic, "version", None),
                early_data_capability=protocol.early_data_capability,
                error=None,
                duration_ms=(time.time() - started) * 1000,
            )
    except asyncio.TimeoutError:
        return H3ScanResult(
            url=url,
            error=f"timeout after {timeout}s",
            duration_ms=(time.time() - started) * 1000,
        )
    except (ConnectionRefusedError, OSError) as e:
        return H3ScanResult(
            url=url,
            error=f"connection refused: {e}",
            duration_ms=(time.time() - started) * 1000,
        )
    except ssl.SSLError as e:
        return H3ScanResult(
            url=url,
            error=f"tls: {e}",
            duration_ms=(time.time() - started) * 1000,
        )
    except Exception as e:
        return H3ScanResult(
            url=url,
            error=f"unexpected: {type(e).__name__}: {e}",
            duration_ms=(time.time() - started) * 1000,
        )
```

- [ ] **Run integration tests to verify they pass**

Run: `python3 -m pytest tests/test_h3_integration.py -v 2>&1 | tail -10`
Expected: `3 passed` (or `3 skipped` if aioquic missing — should not be missing now since 5.1 installed it).

### Step 5.5: Commit Task 5

- [ ] **Stage and commit**

```bash
git add corsair/h3/client.py tests/h3_server.py tests/test_h3_integration.py pyproject.toml
git commit -m "$(cat <<'EOF'
feat(h3): add aioquic-backed H3 client and integration test fixture

scan_h3() — async coroutine that performs a single QUIC connection,
captures session ticket max_early_data_size via session_ticket_handler,
sends a HEAD request with Early-Data: 1 (RFC 8470 hint), and returns
H3ScanResult with status, headers, error, and capability.

Never raises: every exception path returns an H3ScanResult with the
error string populated. Five exception classes mapped to error strings
(timeout, connection refused, TLS, generic, etc).

Integration tests (3) exercise a local in-process aioquic H3 server
fixture. Skipped automatically via pytest.importorskip("aioquic") when
the [h3] extra is absent.

pyproject.toml: add [project.optional-dependencies] h3 = ["aioquic>=1.3.0,<2.0"].

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: `auditor.py` — H3Auditor orchestrator

**Files:**
- Create: `corsair/h3/auditor.py`
- Test: `tests/test_h3_auditor.py`

The auditor wires probe + diff + findings + client into a single sync `audit()` method. All async work is bridged via `asyncio.run()` — same pattern as `CacheAuditor`. Tests mock at the `corsair.h3.auditor.scan_h3` boundary (per the v0.5.5 lesson).

### Step 6.1: TDD — write the failing tests

- [ ] **Create `tests/test_h3_auditor.py`**

```python
"""Tests for corsair.h3.auditor.H3Auditor.

scan_h3 is mocked at corsair.h3.auditor.scan_h3 (its bound name in the
auditor's namespace), NOT at corsair.h3.client.scan_h3 — patching at the
client module won't affect the auditor's local binding. Lesson learned
from v0.5.5 integrity-policy work.
"""

from unittest.mock import patch, AsyncMock

import pytest

from corsair.h3.auditor import H3Auditor
from corsair.h3.client import H3ScanResult
from corsair.models import HeaderCategory, Severity


# ---------------------------------------------------------------------------
# Gate skips
# ---------------------------------------------------------------------------

class TestGateSkips:
    def test_active_false_returns_empty(self):
        a = H3Auditor(timeout=5, active=False)
        assert a.audit("https://example.com/", {"Alt-Svc": 'h3=":443"'}) == []

    def test_http_url_returns_empty(self):
        a = H3Auditor(timeout=5)
        assert a.audit("http://example.com/", {"Alt-Svc": 'h3=":443"'}) == []

    def test_no_alt_svc_returns_empty(self):
        a = H3Auditor(timeout=5)
        assert a.audit("https://example.com/", {}) == []

    def test_alt_svc_without_h3_returns_empty(self):
        a = H3Auditor(timeout=5)
        assert a.audit(
            "https://example.com/", {"Alt-Svc": 'h2=":443"; ma=86400'}
        ) == []


# ---------------------------------------------------------------------------
# Extras-missing path (h3_available patched to False)
# ---------------------------------------------------------------------------

class TestExtrasMissing:
    def test_emits_extras_missing_finding(self):
        with patch("corsair.h3.auditor.H3_AVAILABLE", False):
            a = H3Auditor(timeout=5)
            findings = a.audit(
                "https://example.com/", {"Alt-Svc": 'h3=":443"'}
            )
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "[h3]" in findings[0].description or "pip install" in findings[0].description


# ---------------------------------------------------------------------------
# 0-RTT severity tier matrix
# ---------------------------------------------------------------------------

class TestZeroRttMatrix:
    def _audit(self, scan_result, h1_headers=None):
        h1_headers = h1_headers or {"Alt-Svc": 'h3=":443"'}
        with patch("corsair.h3.auditor.scan_h3", AsyncMock(return_value=scan_result)):
            a = H3Auditor(timeout=5)
            return a.audit("https://example.com/", h1_headers)

    def test_high_when_capability_and_no_425(self):
        result = H3ScanResult(
            url="https://example.com/",
            status=200,
            headers={},
            early_data_capability=16384,
            error=None,
        )
        findings = self._audit(result)
        h3_001 = [f for f in findings if "0-RTT" in f.title and "vulnerable" in f.title]
        assert len(h3_001) == 1
        assert h3_001[0].severity == Severity.HIGH

    def test_pass_when_capability_and_425(self):
        result = H3ScanResult(
            url="https://example.com/",
            status=425,
            headers={},
            early_data_capability=16384,
            error=None,
        )
        findings = self._audit(result)
        h3_001 = [f for f in findings if "0-RTT" in f.title]
        assert any(f.severity == Severity.PASS for f in h3_001)

    def test_low_when_no_capability_and_no_425(self):
        result = H3ScanResult(
            url="https://example.com/",
            status=200,
            headers={},
            early_data_capability=0,
            error=None,
        )
        findings = self._audit(result)
        h3_001 = [f for f in findings if "0-RTT" in f.title and "low risk" in f.title]
        assert len(h3_001) == 1
        assert h3_001[0].severity == Severity.LOW

    def test_silent_when_no_capability_and_425(self):
        result = H3ScanResult(
            url="https://example.com/",
            status=425,
            headers={},
            early_data_capability=0,
            error=None,
        )
        findings = self._audit(result)
        h3_001 = [f for f in findings if "0-RTT" in f.title]
        assert h3_001 == []  # safe baseline — nothing to report


# ---------------------------------------------------------------------------
# H1/H3 header diff finding
# ---------------------------------------------------------------------------

class TestHeaderDiff:
    def _audit(self, h3_headers, h1_headers):
        result = H3ScanResult(
            url="https://example.com/",
            status=200,
            headers=h3_headers,
            early_data_capability=0,  # silent on 0-RTT
            error=None,
        )
        with patch("corsair.h3.auditor.scan_h3", AsyncMock(return_value=result)):
            a = H3Auditor(timeout=5)
            return a.audit("https://example.com/", h1_headers)

    def test_missing_in_h3_emits_medium(self):
        h1 = {
            "Alt-Svc": 'h3=":443"',
            "Strict-Transport-Security": "max-age=31536000",
        }
        h3 = {}
        findings = self._audit(h3, h1)
        h3_002 = [f for f in findings if f.title.startswith("HTTP/3 and HTTP/1.1 security headers diverge")]
        assert len(h3_002) == 1
        assert h3_002[0].severity == Severity.MEDIUM
        assert "Strict-Transport-Security" in h3_002[0].description

    def test_value_drift_emits_medium(self):
        h1 = {
            "Alt-Svc": 'h3=":443"',
            "Strict-Transport-Security": "max-age=31536000",
        }
        h3 = {"strict-transport-security": "max-age=0"}
        findings = self._audit(h3, h1)
        h3_002 = [f for f in findings if f.title.startswith("HTTP/3 and HTTP/1.1 security headers diverge")]
        assert len(h3_002) == 1
        assert h3_002[0].severity == Severity.MEDIUM

    def test_pass_when_no_drift(self):
        h1 = {
            "Alt-Svc": 'h3=":443"',
            "Strict-Transport-Security": "max-age=31536000",
        }
        h3 = {"strict-transport-security": "max-age=31536000"}
        findings = self._audit(h3, h1)
        h3_002 = [f for f in findings if "consistent" in f.title]
        assert len(h3_002) == 1
        assert h3_002[0].severity == Severity.PASS


# ---------------------------------------------------------------------------
# LSQUIC fingerprint (passive — fires before probe)
# ---------------------------------------------------------------------------

class TestLSQUICFingerprint:
    def test_emits_h3_003_when_litespeed_and_h3(self):
        # Probe will time out — but LSQUIC fingerprint should still fire
        h1 = {
            "Alt-Svc": 'h3=":443"',
            "Server": "LiteSpeed/6.0",
        }
        result = H3ScanResult(
            url="https://example.com/",
            error="timeout after 5s",
        )
        with patch("corsair.h3.auditor.scan_h3", AsyncMock(return_value=result)):
            a = H3Auditor(timeout=5)
            findings = a.audit("https://example.com/", h1)
        lsquic = [f for f in findings if "LSQUIC" in f.title]
        assert len(lsquic) == 1
        assert lsquic[0].severity == Severity.CRITICAL

    def test_no_lsquic_for_other_servers(self):
        h1 = {"Alt-Svc": 'h3=":443"', "Server": "nginx/1.27"}
        result = H3ScanResult(
            url="https://example.com/",
            status=200,
            headers={},
            early_data_capability=0,
        )
        with patch("corsair.h3.auditor.scan_h3", AsyncMock(return_value=result)):
            a = H3Auditor(timeout=5)
            findings = a.audit("https://example.com/", h1)
        assert not any("LSQUIC" in f.title for f in findings)


# ---------------------------------------------------------------------------
# Inconclusive / error paths
# ---------------------------------------------------------------------------

class TestInconclusive:
    @pytest.mark.parametrize("error", [
        "timeout after 5s",
        "connection refused: [Errno 111]",
        "tls: certificate verify failed",
        "quic: handshake failed",
        "unexpected: ValueError: bogus",
    ])
    def test_inconclusive_for_each_error_class(self, error):
        result = H3ScanResult(url="https://example.com/", error=error)
        h1 = {"Alt-Svc": 'h3=":443"'}
        with patch("corsair.h3.auditor.scan_h3", AsyncMock(return_value=result)):
            a = H3Auditor(timeout=5)
            findings = a.audit("https://example.com/", h1)
        inconclusive = [f for f in findings if "inconclusive" in f.title.lower()]
        assert len(inconclusive) == 1
        assert error in inconclusive[0].current_value


# ---------------------------------------------------------------------------
# Top-level exception handler
# ---------------------------------------------------------------------------

class TestTopLevelExceptionHandler:
    def test_unexpected_exception_returns_inconclusive(self):
        h1 = {"Alt-Svc": 'h3=":443"'}
        with patch(
            "corsair.h3.auditor.scan_h3",
            AsyncMock(side_effect=RuntimeError("simulated bug")),
        ):
            a = H3Auditor(timeout=5)
            findings = a.audit("https://example.com/", h1)
        assert len(findings) == 1
        assert "inconclusive" in findings[0].title.lower()
        assert "simulated bug" in (findings[0].current_value or "") or "RuntimeError" in (findings[0].current_value or "")


# ---------------------------------------------------------------------------
# Metadata shape
# ---------------------------------------------------------------------------

class TestFindingMetadataShape:
    def test_all_findings_categorized_as_h3(self):
        h1 = {
            "Alt-Svc": 'h3=":443"',
            "Strict-Transport-Security": "max-age=31536000",
            "Server": "LiteSpeed/6.0",
        }
        result = H3ScanResult(
            url="https://example.com/",
            status=200,
            headers={},
            early_data_capability=16384,
        )
        with patch("corsair.h3.auditor.scan_h3", AsyncMock(return_value=result)):
            a = H3Auditor(timeout=5)
            findings = a.audit("https://example.com/", h1)
        for f in findings:
            assert f.category == HeaderCategory.H3, f.title


# ---------------------------------------------------------------------------
# Scanner integration smoke
# ---------------------------------------------------------------------------

class TestScannerIntegration:
    def test_h3_finding_emitted_via_full_pipeline(self):
        from corsair.scanner import HeadScanner

        h1_headers = {
            "Alt-Svc": 'h3=":443"',
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Type": "text/html",
        }
        result = H3ScanResult(
            url="https://example.com/",
            status=200,
            headers={},  # missing in h3 -> H3-002 MEDIUM
            early_data_capability=16384,
        )

        with patch.object(
            HeadScanner,
            "_fetch_headers",
            return_value=(200, h1_headers, "https://example.com/", None),
        ), patch(
            "corsair.h3.auditor.scan_h3", AsyncMock(return_value=result)
        ), patch(
            "corsair.cache.auditor.CacheAuditor.audit", return_value=[]
        ), patch(
            "corsair.cors.auditor.CORSAuditor.audit", return_value=[]
        ), patch(
            "corsair.fetch_metadata.FetchMetadataAuditor.audit", return_value=[]
        ), patch(
            "corsair.integrity_policy.IntegrityPolicyAuditor.audit", return_value=[]
        ):
            scanner = HeadScanner(
                timeout=5,
                cache_probe=False, cors_probe=False, fm_probe=False,
                ip_probe=False, h3_probe=True,
            )
            scan_result = scanner.scan_target("https://example.com/")

        h3_findings = [f for f in scan_result.findings if f.category == HeaderCategory.H3]
        # Expect at least: 0-RTT HIGH (capability + no 425) and H3-002 MEDIUM (HSTS missing in h3).
        assert any(f.severity == Severity.HIGH and "0-RTT" in f.title for f in h3_findings)
        assert any(f.severity == Severity.MEDIUM and "diverge" in f.title for f in h3_findings)
```

- [ ] **Run tests to verify they fail with import error**

Run: `python3 -m pytest tests/test_h3_auditor.py -v 2>&1 | head -10`
Expected: `ImportError: cannot import name 'H3Auditor'`.

### Step 6.2: Implement `auditor.py`

- [ ] **Create `corsair/h3/auditor.py`**

```python
"""H3Auditor — orchestrates Alt-Svc derivation, LSQUIC fingerprint,
QUIC probe, 0-RTT classification, and H1/H3 header diff into a single
audit() method.

Tests must mock scan_h3 at corsair.h3.auditor.scan_h3 (this module's
bound name), NOT corsair.h3.client.scan_h3 — the auditor imports the
function into its own namespace at import time. This is the v0.5.5
integrity-policy lesson preserved here.
"""

import asyncio
import logging
from typing import List, Mapping, Optional
from urllib.parse import urlparse

from ..models import Finding
from .diff import diff_security_headers
from .findings import (
    build_h3_001_high,
    build_h3_001_low,
    build_h3_001_pass,
    build_h3_002_finding,
    build_h3_002_pass,
    build_h3_003_finding,
    build_h3_inconclusive_finding,
    build_h3_extras_missing_finding,
)
from .probe import derive_h3_target, is_lsquic_fingerprint

# Imported via the package __init__ availability flag. When [h3] extra is
# absent, H3_AVAILABLE is False and scan_h3 is None (we never call it).
try:
    from .client import scan_h3  # noqa: F401
    H3_AVAILABLE = True
except ImportError:
    H3_AVAILABLE = False
    scan_h3 = None  # type: ignore

logger = logging.getLogger(__name__)


class H3Auditor:
    """Two-stage H3 validation orchestrator."""

    def __init__(
        self,
        timeout: int = 10,
        active: bool = True,
        user_agent: str = "Corsair/0.6.0 (HTTP Security Scanner)",
    ):
        self.timeout = timeout
        self.active = active
        self.user_agent = user_agent

    def audit(self, url: str, h1_headers: Mapping[str, str]) -> List[Finding]:
        try:
            return self._audit_inner(url, h1_headers)
        except Exception as e:
            logger.exception("H3 audit unexpectedly failed")
            return [build_h3_inconclusive_finding(error=f"audit error: {type(e).__name__}: {e}")]

    def _audit_inner(self, url: str, h1_headers: Mapping[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Gate checks
        if not self.active:
            return []
        if not url.lower().startswith("https://"):
            return []

        # 2. Trigger derivation
        parsed = urlparse(url)
        target = derive_h3_target(h1_headers, parsed.hostname or "")
        if target is None:
            return []
        host, port = target

        # 3. Extras gate (must be after Alt-Svc check so we don't spam INFO
        # findings on every site that doesn't ship h3)
        if not H3_AVAILABLE:
            return [build_h3_extras_missing_finding()]

        # 4. LSQUIC passive fingerprint — fires before the probe
        if is_lsquic_fingerprint(h1_headers, has_h3_advertisement=True):
            findings.append(build_h3_003_finding())

        # 5. H3 probe (async → sync bridge)
        target_url = f"https://{host}:{port}{parsed.path or '/'}"
        try:
            result = asyncio.run(scan_h3(
                url=target_url,
                timeout=float(self.timeout),
                user_agent=self.user_agent,
            ))
        except Exception as e:
            findings.append(build_h3_inconclusive_finding(
                error=f"asyncio.run error: {type(e).__name__}: {e}"
            ))
            return findings

        # 6. Probe error → INCONCLUSIVE (LSQUIC finding from step 4 stays)
        if result.error is not None:
            findings.append(build_h3_inconclusive_finding(error=result.error))
            return findings

        # 7. 0-RTT evaluation
        capability = result.early_data_capability > 0
        hint_rejected = (result.status == 425)
        if capability and not hint_rejected:
            findings.append(build_h3_001_high(
                early_data_capability=result.early_data_capability,
                status=result.status or 0,
            ))
        elif capability and hint_rejected:
            findings.append(build_h3_001_pass(early_data_capability=result.early_data_capability))
        elif (not capability) and (not hint_rejected):
            findings.append(build_h3_001_low(status=result.status or 0))
        # else: silent baseline — no emit

        # 8. H1/H3 security-header diff
        diff = diff_security_headers(h1_headers, result.headers)
        if diff.missing_in_h3 or diff.missing_in_h1 or diff.value_drift:
            findings.append(build_h3_002_finding(diff))
        else:
            findings.append(build_h3_002_pass())

        return findings
```

- [ ] **Run tests to verify they pass**

Run: `python3 -m pytest tests/test_h3_auditor.py -v 2>&1 | tail -10`
Expected: `~30 passed`.

### Step 6.3: Commit Task 6

- [ ] **Stage and commit**

```bash
git add corsair/h3/auditor.py tests/test_h3_auditor.py
git commit -m "$(cat <<'EOF'
feat(h3): add H3Auditor orchestrator with 0-RTT matrix and H1/H3 diff

Orchestrates probe.py + diff.py + findings.py + client.py into a single
sync audit() method. Bridges async via asyncio.run(), matching the
CacheAuditor pattern.

Two-stage flow:
  Stage 1 (always passive): Alt-Svc gate, extras-installed check,
    LSQUIC fingerprint (fires before probe so it surfaces on probe failure).
  Stage 2 (active): single QUIC HEAD with Early-Data: 1; classifies
    0-RTT severity tier (HIGH/LOW/PASS/silent) and emits H1/H3 diff
    finding (MEDIUM/LOW/PASS).

Top-level try/except around _audit_inner converts any unexpected error
into a single INCONCLUSIVE INFO finding rather than letting it propagate
to scan_target. The lesson from v0.5.5: tests patch scan_h3 at this
module's bound name, NOT at corsair.h3.client.

30 unit tests + 1 scanner-integration smoke; total 73 H3 tests so far.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Scanner integration + CLI flag

**Files:**
- Modify: `corsair/scanner.py:25-229` (HeadScanner.__init__ and scan_target)
- Modify: `corsair/cli.py:174,200,247` (add option, signature, plumbing)

This task wires the auditor into the live pipeline. No new tests — the smoke test already lives in `test_h3_auditor.py::TestScannerIntegration`, which will start passing once the scanner accepts `h3_probe`.

### Step 7.1: Add `h3_probe` to `HeadScanner`

- [ ] **Modify `corsair/scanner.py`**

Around line 38, after `ip_probe: bool = True,`, add:

```python
        h3_probe: bool = True,
```

Around line 52, after the `ip_probe:` docstring line, add:

```python
            h3_probe: Whether to run HTTP/3 validation (requires [h3] extra)
```

Around line 62, after `self.ip_probe = ip_probe`, add:

```python
        self.h3_probe = h3_probe
```

### Step 7.2: Add the H3Auditor block in `scan_target`

- [ ] **Modify `corsair/scanner.py`**

After the existing Integrity-Policy block (around line 230), insert:

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

### Step 7.3: Add the CLI flag

- [ ] **Modify `corsair/cli.py`**

After line 174 (`--ip-probe/--no-ip-probe`), insert:

```python
@click.option("--h3-probe/--no-h3-probe", default=True, help="Run HTTP/3 validation (requires `pip install corsair-scan[h3]`)")
```

Around line 201, after `ip_probe: bool,`, add:

```python
    h3_probe: bool,
```

Around line 247, after `ip_probe=ip_probe,`, add:

```python
        h3_probe=h3_probe,
```

### Step 7.4: Verify the smoke test now passes and CLI reflects the flag

- [ ] **Run the smoke test**

Run: `python3 -m pytest tests/test_h3_auditor.py::TestScannerIntegration -v 2>&1 | tail -5`
Expected: `1 passed`.

- [ ] **Verify the CLI flag**

Run: `python3 -m corsair.cli scan --help 2>&1 | grep -E "h3-probe|ip-probe"`
Expected:
```
--ip-probe / --no-ip-probe      Run Integrity-Policy validation
--h3-probe / --no-h3-probe      Run HTTP/3 validation (requires `pip install corsair-scan[h3]`)
```

### Step 7.5: Run the full suite (gated for the [h3] extras presence)

- [ ] **Full test run**

Run: `python3 -m pytest --ignore=tests/test_tls_auditor.py -q 2>&1 | tail -3`
Expected: `~615 passed` (544 baseline + ~70 unit + ~3 integration if extras present, or 0 integration if not).

### Step 7.6: Commit Task 7

- [ ] **Stage and commit**

```bash
git add corsair/scanner.py corsair/cli.py
git commit -m "$(cat <<'EOF'
feat(h3): wire H3Auditor into HeadScanner and CLI

HeadScanner gains an h3_probe parameter (default True) and instantiates
H3Auditor after the Integrity-Policy block, with try/except matching the
established auditor-block pattern.

CLI gains --h3-probe / --no-h3-probe (default ON) plumbed through the
scan command parameters. When the [h3] extra is missing, the auditor
emits a single INFO finding rather than skipping silently.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: v0.6.0 release

**Files:**
- Modify: `corsair/__init__.py:27` (`__version__`)
- Modify: `pyproject.toml:7` (`version`)
- Modify: `README.md` (insert `### v0.6.0` block above `### v0.5.5`)

This task ships the version bump and the changelog entry. No new code or tests.

### Step 8.1: Bump `corsair/__init__.py`

- [ ] **Update `__version__`**

In `corsair/__init__.py`, change line 27 from `__version__ = "0.5.5"` to:

```python
__version__ = "0.6.0"
```

- [ ] **Verify**

Run: `python3 -c "import corsair; print(corsair.__version__)"`
Expected: `0.6.0`

### Step 8.2: Bump `pyproject.toml`

- [ ] **Update `version`**

In `pyproject.toml`, change `version = "0.5.5"` to:

```toml
version = "0.6.0"
```

### Step 8.3: Add v0.6.0 changelog entry to README

- [ ] **Insert above the v0.5.5 entry**

In `README.md`, locate `### v0.5.5 — Integrity-Policy Validation` and insert above it:

```markdown
### v0.6.0 — HTTP/3 Validation (2026-05-07)

**Headline:** First public scanner with end-to-end HTTP/3 security validation — 0-RTT replay detection (CVE-2024-39321) and HTTP/1.1 ↔ HTTP/3 security-header drift analysis in a single scan.

**New optional subsystem:** `corsair/h3/` (gated behind `[h3]` extras)
- `probe.py` — Alt-Svc → h3 target derivation; LSQUIC passive fingerprint (CVE-2025-54939).
- `diff.py` — H1/H3 security-header diff over an 18-header allowlist (presence + value drift).
- `findings.py` — 3 finding templates + PASS variants + INFO auxiliaries.
- `client.py` — aioquic-backed single-connection QUIC HEAD probe; captures `max_early_data_size` from the TLS NewSessionTicket and the response status to `Early-Data: 1` (RFC 8470).
- `auditor.py` — `H3Auditor` orchestrator with two-stage flow.

**Findings:**
- H3-001 (HIGH/LOW/PASS) — 0-RTT replay vulnerability, severity tiered by `(capability × hint-honored)` matrix.
- H3-002 (MEDIUM/LOW/PASS) — HTTP/1.1 vs HTTP/3 security-header divergence.
- H3-003 (CRITICAL) — LSQUIC pre-handshake DoS fingerprint (CVE-2025-54939).
- H3-INCONCLUSIVE / H3-EXTRAS-MISSING (INFO).

**CLI:** New flag `--h3-probe / --no-h3-probe` (default ON).

**Install:** `pip install corsair-scan[h3]` enables HTTP/3 probing. Without the extra, `--h3-probe` emits a single INFO finding pointing to the install command.

**Compliance:** OWASP A05/A06/A07; PCI-DSS 6.2.4/6.4.3; CWE-294/400/693/770; CVE-2024-39321 / CVE-2025-54939.

**Tests:** ~73 new tests across `tests/test_h3_*.py` (70 unit + 3 integration; integration suite skipped automatically when `[h3]` extra absent).

**Models:** `HeaderCategory.H3` enum value added.

**Deferred to v0.6.1+:** QPACK `SETTINGS_MAX_FIELD_SECTION_SIZE` advertisement check, Alt-Svc-without-HSTS, Alt-Svc long max-age, Connection-ID rotation. Tracked in `~/.claude/projects/-Users-fevra-Apps-HeadScan/memory/project_h3_v060_scope.md`.

```

- [ ] **Verify ordering**

Run: `grep -n "v0.6.0\|v0.5.5" /Users/fevra/Apps/HeadScan/.worktrees/feature-h3-v0.6.0/README.md | head -5`
Expected: Line with `### v0.6.0 — HTTP/3 Validation` precedes `### v0.5.5 — Integrity-Policy Validation`.

### Step 8.4: Final test run

- [ ] **Final full test pass**

Run: `python3 -m pytest --ignore=tests/test_tls_auditor.py -q 2>&1 | tail -3`
Expected: `~615 passed`, zero new failures.

### Step 8.5: Commit the release

- [ ] **Stage and commit**

```bash
git add corsair/__init__.py pyproject.toml README.md
git commit -m "$(cat <<'EOF'
release: v0.6.0 — HTTP/3 Validation

First public scanner with end-to-end HTTP/3 security validation: 0-RTT
replay detection (CVE-2024-39321) and HTTP/1.1 vs HTTP/3 security-header
drift analysis. Three core findings (H3-001/002/003) plus INFO
auxiliaries, gated behind a new [h3] extras group with aioquic.

Cutting-edge positioning: no other public scanner — testssl.sh, sslyze,
Mozilla Observatory, SecurityHeaders.com, Snyk — combines a live QUIC
client with security-header analysis in a single binary.

LSQUIC fingerprint (CVE-2025-54939) is a free passive win on ~14% of
all websites and ~34% of HTTP/3-enabled sites.

Tier B/C findings (QPACK SETTINGS, Alt-Svc-without-HSTS, Alt-Svc
long-max-age, Connection-ID rotation) deferred to v0.6.1+.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

### Step 8.6: Hand off to finishing-a-development-branch

- [ ] **Announce and invoke the finishing skill**

Per superpowers:subagent-driven-development Step 7: after all tasks complete, run the final code reviewer subagent across the full implementation, then announce:

> "I'm using the finishing-a-development-branch skill to complete this work."

Follow that skill to verify tests, present the four standard options (merge locally / create PR / keep as-is / discard), and execute the chosen path.

---

## Acceptance criteria checklist

Map of spec §13 acceptance criteria → tasks that satisfy each:

| # | Criterion | Satisfied by |
|---|---|---|
| 1 | `from corsair.h3 import H3Auditor` works without aioquic | Task 1 (Step 1.2-1.3) |
| 2 | `H3Auditor.audit(url, headers)` returns `list[Finding]` for every documented scenario | Task 6 (all auditor tests) |
| 3 | `corsair scan --help` shows `--h3-probe / --no-h3-probe` | Task 7 (Step 7.4) |
| 4 | All ~70 unit tests pass | Tasks 2, 3, 4, 6 |
| 5 | Integration tests pass with `[h3]` extra; skip cleanly without | Task 5 (Step 5.4) |
| 6 | Full suite shows zero new failures vs v0.5.5 baseline (~615 total) | Tasks 7.5 + 8.4 |
| 7 | `H3Auditor` wired into `HeadScanner.scan_target()` after IP block | Task 7 (Step 7.2) |
| 8 | v0.6.0 release artifacts updated | Task 8 (Steps 8.1-8.3) |
| 9 | LSQUIC fingerprint fires passively even when QUIC probe times out | Task 6 (TestLSQUICFingerprint) |
| 10 | All four cells of H3-001 matrix produce documented outcome | Task 6 (TestZeroRttMatrix) |
