# Alt-Svc Cache Poisoning Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden Corsair's existing Alt-Svc cache-poisoning detection (v0.4.1) by replacing the substring canary check with an alt-authority-anchored regex, adding a CDN pre-check that suppresses guaranteed-false probes on Cloudflare/Fastly/Akamai+HTTP/3, and adding three passive analyzers that catch Alt-Svc misconfiguration without firing the active probe (cross-domain, private-host, excessive-persistence).

**Architecture:** A new `corsair/cache/altsvc.py` module owns all Alt-Svc grammar knowledge (parser, canary detector, passive analyzers, pre-check). Existing `reflect.py`, `probe.py`/`auditor.py`, and `findings.py` get small wire-up edits. `corsair/cache/oracle.py` gains an `alt_svc` field captured from the baseline response so both passive analysis and the pre-check have what they need without re-fetching.

**Tech Stack:** Python 3.9+, httpx (existing), `tldextract>=5.0.0` (new core dep, replaces ad-hoc label-stripping), `ipaddress` stdlib, `re` stdlib. `unittest.mock.patch("httpx.AsyncClient")` for integration tests, matching the pattern in `tests/test_cors_wave2_auditor.py`.

**Spec:** `docs/superpowers/specs/2026-04-24-alt-svc-hardening-design.md`. Read §1–§7 before starting.

---

## File Structure

**Create:**
- `corsair/cache/altsvc.py` — `AltSvcEntry`, `parse_alt_svc()`, `detect_alt_svc_canary()`, `analyze_alt_svc_suspicious()`, `should_probe_alt_svc()`. Pure logic over strings; no httpx, no I/O.
- `tests/test_cache_altsvc.py` — unit tests for the five public functions/classes above (~30 tests).
- `tests/test_cache_altsvc_integration.py` — end-to-end CacheAuditor scenarios (~5 tests, mocked httpx).

**Modify:**
- `corsair/cache/oracle.py` — add `alt_svc: Optional[str]` field to `CacheOracle`; capture from baseline `r1_headers` in `establish_oracle()`.
- `corsair/cache/reflect.py` — branch on header name in the `HEADER_CONTEXTS` loop; call `altsvc.detect_alt_svc_canary()` for `alt-svc`.
- `corsair/cache/auditor.py` — call `altsvc.analyze_alt_svc_suspicious()` in `_passive_checks()`; in `_active_probes()` result loop, drop `WCP_ALT_SVC_POISONING` results and emit `WCP_PROBE_SKIPPED` when `should_probe_alt_svc()` returns False.
- `corsair/cache/findings.py` — register `_WCP_ALT_SVC_CROSS_DOMAIN`, `_WCP_ALT_SVC_PRIVATE_HOST`, `_WCP_ALT_SVC_EXCESSIVE_PERSISTENCE`; insert into `ALL_CACHE_FINDINGS` between `WCP_ALT_SVC_POISONING` and `WCP_SET_COOKIE_POISONING`.
- `tests/test_cache_findings.py` — bump registry-size assertion from 19 to 22.
- `pyproject.toml` — add `tldextract>=5.0.0` to core `dependencies`; bump version to `0.5.2`.
- `corsair/__init__.py` — bump `__version__` to `0.5.2`.
- `README.md` — add `### v0.5.2 — Alt-Svc Hardening` changelog section above v0.5.1.

**Architectural note (deviation from spec §4.2):** The spec places the pre-check in `probe.py` "before dispatching the Alt-Svc-targeted canary batch." There is no Alt-Svc-targeted batch — `probe.py` runs `PROBE_HEADERS` generically and any header can land in the alt-svc sink during classification. The pre-check therefore goes in `auditor._active_probes()` after results return: if `should_probe_alt_svc()` is False, drop any result with `finding_id == "WCP_ALT_SVC_POISONING"` and emit `WCP_PROBE_SKIPPED` instead. Net effect matches the spec's intent; mechanics differ.

---

## Task 1: Parser & Primitives

**Files:**
- Create: `corsair/cache/altsvc.py`
- Test: `tests/test_cache_altsvc.py` (TestParseAltSvc class only)

- [ ] **Step 1: Write failing parser tests**

Create `tests/test_cache_altsvc.py`:

```python
"""Unit tests for corsair.cache.altsvc."""

from corsair.cache.altsvc import AltSvcEntry, parse_alt_svc


class TestParseAltSvc:
    def test_port_only_authority(self):
        entries = parse_alt_svc('h3=":443"; ma=86400')
        assert entries == [AltSvcEntry(protocol_id="h3", host=None, port=443, ma=86400, persist=False)]

    def test_host_port_ma_persist(self):
        entries = parse_alt_svc('h3="cdn.example.com:443"; ma=3600; persist=1')
        assert entries == [
            AltSvcEntry(protocol_id="h3", host="cdn.example.com", port=443, ma=3600, persist=True)
        ]

    def test_multi_value_order_preserved(self):
        entries = parse_alt_svc('h2="a:443", h3="b.example.com:443"; ma=60')
        assert len(entries) == 2
        assert entries[0].protocol_id == "h2"
        assert entries[0].host == "a"
        assert entries[1].protocol_id == "h3"
        assert entries[1].host == "b.example.com"

    def test_draft_protocol_id(self):
        entries = parse_alt_svc('h3-29=":443"')
        assert entries[0].protocol_id == "h3-29"

    def test_clear_directive(self):
        assert parse_alt_svc("clear") == []

    def test_empty_and_whitespace(self):
        assert parse_alt_svc("") == []
        assert parse_alt_svc("   ") == []

    def test_malformed_no_exception(self):
        # Unclosed quote, missing equals — must return [], not raise.
        assert parse_alt_svc('h3="foo:443') == []
        assert parse_alt_svc('h3 ":443"') == []

    def test_unknown_parameters_ignored(self):
        entries = parse_alt_svc('h3=":443"; ma=60; foo=bar; persist=1')
        assert entries == [AltSvcEntry(protocol_id="h3", host=None, port=443, ma=60, persist=True)]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cache_altsvc.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'corsair.cache.altsvc'`.

- [ ] **Step 3: Implement parser**

Create `corsair/cache/altsvc.py`:

```python
"""
Alt-Svc grammar, canary detection, passive analysis, and CDN pre-check.

Pure logic over strings and fingerprint tags. No httpx, no I/O.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import List, Mapping, Optional


@dataclass(frozen=True)
class AltSvcEntry:
    protocol_id: str
    host: Optional[str]
    port: int
    ma: Optional[int]
    persist: bool


_ENTRY_RE = re.compile(
    r'\s*([A-Za-z0-9\-]+)\s*=\s*"([^"]*)"\s*((?:;\s*[A-Za-z0-9_\-]+\s*=\s*[^;,]+\s*)*)'
)
_PARAM_RE = re.compile(r"([A-Za-z0-9_\-]+)\s*=\s*([^;,]+)")


def parse_alt_svc(value: str) -> List[AltSvcEntry]:
    """
    Parse an Alt-Svc header value into AltSvcEntry instances.

    Returns [] for "clear", empty input, or malformed input. Never raises.
    """
    if value is None:
        return []
    stripped = value.strip()
    if not stripped or stripped.lower() == "clear":
        return []

    entries: List[AltSvcEntry] = []
    for match in _ENTRY_RE.finditer(stripped):
        protocol_id = match.group(1)
        authority = match.group(2)
        params_str = match.group(3) or ""

        if ":" not in authority:
            continue
        host_part, _, port_part = authority.rpartition(":")
        try:
            port = int(port_part)
        except ValueError:
            continue
        host = host_part if host_part else None

        ma: Optional[int] = None
        persist = False
        for p in _PARAM_RE.finditer(params_str):
            key = p.group(1).lower()
            val = p.group(2).strip().strip('"')
            if key == "ma":
                try:
                    ma = int(val)
                except ValueError:
                    pass
            elif key == "persist" and val == "1":
                persist = True

        entries.append(
            AltSvcEntry(protocol_id=protocol_id, host=host, port=port, ma=ma, persist=persist)
        )
    return entries
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cache_altsvc.py -v`
Expected: 8 tests pass (TestParseAltSvc).

- [ ] **Step 5: Commit**

```bash
git add corsair/cache/altsvc.py tests/test_cache_altsvc.py
git commit -m "feat(altsvc): add Alt-Svc parser and AltSvcEntry primitive"
```

---

## Task 2: Canary Detector & reflect.py Wire-Up

**Files:**
- Modify: `corsair/cache/altsvc.py` (add `detect_alt_svc_canary`)
- Modify: `corsair/cache/reflect.py:22-29` (branch on `alt-svc`)
- Test: `tests/test_cache_altsvc.py` (add TestDetectAltSvcCanary class)
- Test: `tests/test_cache_reflect.py` (verify existing alt-svc behavior unchanged)

- [ ] **Step 1: Write failing detector tests**

Append to `tests/test_cache_altsvc.py`:

```python
from corsair.cache.altsvc import detect_alt_svc_canary


class TestDetectAltSvcCanary:
    CANARY = "x9k3p7q1.invalid"

    def test_canary_in_single_entry_host(self):
        value = f'h3="{self.CANARY}:443"; ma=60'
        assert detect_alt_svc_canary(value, self.CANARY) is True

    def test_canary_in_second_entry_of_multi_value(self):
        value = f'h2="origin:443", h3="{self.CANARY}:443"'
        assert detect_alt_svc_canary(value, self.CANARY) is True

    def test_clear_directive_returns_false(self):
        assert detect_alt_svc_canary("clear", self.CANARY) is False

    def test_empty_returns_false(self):
        assert detect_alt_svc_canary("", self.CANARY) is False
        assert detect_alt_svc_canary("   ", self.CANARY) is False

    def test_canary_absent_returns_false(self):
        assert detect_alt_svc_canary('h3="cdn.example.com:443"', self.CANARY) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cache_altsvc.py::TestDetectAltSvcCanary -v`
Expected: FAIL — `ImportError: cannot import name 'detect_alt_svc_canary'`.

- [ ] **Step 3: Implement detector**

Append to `corsair/cache/altsvc.py`:

```python
def detect_alt_svc_canary(value: str, canary: str) -> bool:
    """
    Alt-authority-anchored canary detection.

    Returns True only when the canary appears inside a quoted alt-authority value.
    Returns False for "clear", empty, or canary-absent input.
    """
    if not value:
        return False
    stripped = value.strip()
    if not stripped or stripped.lower() == "clear":
        return False
    pattern = re.compile(
        r'=\s*"[^"]*' + re.escape(canary) + r'[^"]*"',
        re.IGNORECASE,
    )
    return bool(pattern.search(value))
```

- [ ] **Step 4: Run detector tests to verify they pass**

Run: `pytest tests/test_cache_altsvc.py::TestDetectAltSvcCanary -v`
Expected: 5 tests pass.

- [ ] **Step 5: Wire detector into reflect.py**

Read `corsair/cache/reflect.py:22-29` first to confirm structure, then edit. Replace the `HEADER_CONTEXTS` loop body:

```python
from . import altsvc as _altsvc  # add to imports near top of file

# inside the existing find_reflections function:
for header_name, context_id in HEADER_CONTEXTS:
    for key, value in headers.items():
        if key.lower() != header_name:
            continue
        if header_name == "alt-svc":
            matched = _altsvc.detect_alt_svc_canary(value, canary)
        else:
            matched = canary in value
        if matched:
            found_contexts.append(context_id)
            break
```

- [ ] **Step 6: Run reflect.py regression tests**

Run: `pytest tests/test_cache_reflect.py -v`
Expected: All existing tests pass (the alt-svc cases continue to work — the regex matches the substring case those tests use).

- [ ] **Step 7: Commit**

```bash
git add corsair/cache/altsvc.py corsair/cache/reflect.py tests/test_cache_altsvc.py
git commit -m "feat(altsvc): regex-anchored canary detector; wire into reflect.py"
```

---

## Task 3: Passive Analyzers + tldextract Dependency

**Files:**
- Modify: `corsair/cache/altsvc.py` (add `analyze_alt_svc_suspicious`)
- Modify: `pyproject.toml` (add `tldextract>=5.0.0` to core deps)
- Test: `tests/test_cache_altsvc.py` (add TestCrossDomain, TestPrivateHost, TestExcessivePersistence)

- [ ] **Step 1: Add tldextract to core dependencies**

Edit `pyproject.toml`. In the `[project] dependencies` list (currently lines 48-55), add `"tldextract>=5.0.0",` after the `"cachetools>=5.3.0",` entry:

```toml
dependencies = [
    "httpx>=0.27.0",
    "click>=8.1.0",
    "rich>=13.0.0",
    "colorama>=0.4.6",
    "jinja2>=3.1.0",
    "cachetools>=5.3.0",
    "tldextract>=5.0.0",
]
```

Install it locally so tests can import:

```bash
pip install -e .
```

Expected: `Successfully installed tldextract-5.x.x` (or similar).

- [ ] **Step 2: Write failing passive-analyzer tests**

Append to `tests/test_cache_altsvc.py`:

```python
from corsair.cache.altsvc import analyze_alt_svc_suspicious


class TestCrossDomain:
    def test_different_registrable_domain_emits(self):
        ids = analyze_alt_svc_suspicious('h3="evil.net:443"', "api.example.com")
        assert "WCP_ALT_SVC_CROSS_DOMAIN" in ids

    def test_same_registrable_domain_no_emit(self):
        ids = analyze_alt_svc_suspicious('h3="h3.example.com:443"', "api.example.com")
        assert "WCP_ALT_SVC_CROSS_DOMAIN" not in ids

    def test_psl_multilabel_tld_no_emit(self):
        ids = analyze_alt_svc_suspicious('h3="cdn.example.co.uk:443"', "api.example.co.uk")
        assert "WCP_ALT_SVC_CROSS_DOMAIN" not in ids

    def test_psl_multilabel_tld_cross_domain_emits(self):
        ids = analyze_alt_svc_suspicious('h3="example.co.uk:443"', "api.example.com")
        assert "WCP_ALT_SVC_CROSS_DOMAIN" in ids

    def test_port_only_authority_no_emit(self):
        ids = analyze_alt_svc_suspicious('h3=":443"', "api.example.com")
        assert "WCP_ALT_SVC_CROSS_DOMAIN" not in ids


class TestPrivateHost:
    def test_loopback_ipv4_emits(self):
        ids = analyze_alt_svc_suspicious('h3="127.0.0.1:443"', "api.example.com")
        assert "WCP_ALT_SVC_PRIVATE_HOST" in ids

    def test_rfc1918_emits(self):
        for host in ("10.0.0.1", "192.168.1.1", "172.16.0.1"):
            ids = analyze_alt_svc_suspicious(f'h3="{host}:443"', "api.example.com")
            assert "WCP_ALT_SVC_PRIVATE_HOST" in ids, host

    def test_ipv6_loopback_and_linklocal_emit(self):
        for host in ("[::1]", "[fe80::1]"):
            ids = analyze_alt_svc_suspicious(f'h3="{host}:443"', "api.example.com")
            assert "WCP_ALT_SVC_PRIVATE_HOST" in ids, host

    def test_reserved_tlds_emit(self):
        for host in ("server.local", "db.internal", "x.invalid", "x.localhost", "x.test", "x.example"):
            ids = analyze_alt_svc_suspicious(f'h3="{host}:443"', "api.example.com")
            assert "WCP_ALT_SVC_PRIVATE_HOST" in ids, host

    def test_bare_hostname_emits(self):
        ids = analyze_alt_svc_suspicious('h3="corp-server:443"', "api.example.com")
        assert "WCP_ALT_SVC_PRIVATE_HOST" in ids

    def test_public_hostname_no_emit(self):
        ids = analyze_alt_svc_suspicious('h3="cdn.example.com:443"', "api.example.com")
        assert "WCP_ALT_SVC_PRIVATE_HOST" not in ids


class TestExcessivePersistence:
    def test_above_30d_with_persist_emits(self):
        ids = analyze_alt_svc_suspicious('h3=":443"; ma=2592001; persist=1', "api.example.com")
        assert "WCP_ALT_SVC_EXCESSIVE_PERSISTENCE" in ids

    def test_exactly_30d_with_persist_no_emit(self):
        ids = analyze_alt_svc_suspicious('h3=":443"; ma=2592000; persist=1', "api.example.com")
        assert "WCP_ALT_SVC_EXCESSIVE_PERSISTENCE" not in ids

    def test_long_ma_without_persist_no_emit(self):
        ids = analyze_alt_svc_suspicious('h3=":443"; ma=31536000', "api.example.com")
        assert "WCP_ALT_SVC_EXCESSIVE_PERSISTENCE" not in ids

    def test_persist_with_default_ma_no_emit(self):
        ids = analyze_alt_svc_suspicious('h3=":443"; persist=1', "api.example.com")
        assert "WCP_ALT_SVC_EXCESSIVE_PERSISTENCE" not in ids
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_cache_altsvc.py::TestCrossDomain tests/test_cache_altsvc.py::TestPrivateHost tests/test_cache_altsvc.py::TestExcessivePersistence -v`
Expected: FAIL — `ImportError: cannot import name 'analyze_alt_svc_suspicious'`.

- [ ] **Step 4: Implement passive analyzers**

Append to `corsair/cache/altsvc.py`:

```python
import tldextract  # add to top of file with other imports

_RESERVED_PSEUDO_TLDS = (".local", ".internal", ".invalid", ".localhost", ".test", ".example")
_THIRTY_DAYS_SECONDS = 30 * 24 * 60 * 60  # 2_592_000


def _is_private_host(host: str) -> bool:
    """True if host is a private/loopback IP, reserved pseudo-TLD, or bare hostname."""
    # IPv6 literals arrive in [bracketed] form from authority parsing.
    candidate = host.strip("[]")
    try:
        ip = ipaddress.ip_address(candidate)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass

    lowered = host.lower()
    for suffix in _RESERVED_PSEUDO_TLDS:
        if lowered.endswith(suffix):
            return True

    extracted = tldextract.extract(host)
    if extracted.suffix == "":
        return True
    return False


def analyze_alt_svc_suspicious(value: str, target_hostname: str) -> List[str]:
    """
    Run all three passive analyzers against an Alt-Svc value.

    Returns a list of finding IDs (subset of WCP_ALT_SVC_CROSS_DOMAIN,
    WCP_ALT_SVC_PRIVATE_HOST, WCP_ALT_SVC_EXCESSIVE_PERSISTENCE).
    Each finding emits at most once even when multiple entries qualify.
    """
    findings: List[str] = []
    entries = parse_alt_svc(value)
    if not entries:
        return findings

    target_domain = tldextract.extract(target_hostname).registered_domain.lower()

    cross_domain = False
    private_host = False
    excessive = False

    for entry in entries:
        if entry.host:
            entry_domain = tldextract.extract(entry.host).registered_domain.lower()
            if (
                entry_domain
                and target_domain
                and entry_domain != target_domain
                and entry.host.lower() != target_hostname.lower()
            ):
                cross_domain = True
            if _is_private_host(entry.host):
                private_host = True
        if entry.ma is not None and entry.ma > _THIRTY_DAYS_SECONDS and entry.persist:
            excessive = True

    if cross_domain:
        findings.append("WCP_ALT_SVC_CROSS_DOMAIN")
    if private_host:
        findings.append("WCP_ALT_SVC_PRIVATE_HOST")
    if excessive:
        findings.append("WCP_ALT_SVC_EXCESSIVE_PERSISTENCE")

    return findings
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_cache_altsvc.py -v`
Expected: All 28 tests pass (8 parser + 5 detector + 5 cross-domain + 6 private-host + 4 persistence).

- [ ] **Step 6: Commit**

```bash
git add corsair/cache/altsvc.py tests/test_cache_altsvc.py pyproject.toml
git commit -m "feat(altsvc): three passive analyzers + tldextract>=5.0.0 core dep"
```

---

## Task 4: CDN Pre-Check

**Files:**
- Modify: `corsair/cache/altsvc.py` (add `should_probe_alt_svc`)
- Test: `tests/test_cache_altsvc.py` (add TestShouldProbeAltSvc)

- [ ] **Step 1: Write failing pre-check tests**

Append to `tests/test_cache_altsvc.py`:

```python
from corsair.cache.altsvc import should_probe_alt_svc


class TestShouldProbeAltSvc:
    def test_cloudflare_returns_false(self):
        assert should_probe_alt_svc("cloudflare", {"alt-svc": 'h3=":443"'}) is False

    def test_fastly_returns_false(self):
        assert should_probe_alt_svc("fastly", {}) is False

    def test_akamai_with_h3_marker_returns_false(self):
        assert should_probe_alt_svc("akamai", {"alt-svc": 'h3=":443"; ma=93600'}) is False

    def test_akamai_without_h3_marker_returns_true(self):
        assert should_probe_alt_svc("akamai", {"alt-svc": 'h3=":443"; ma=86400'}) is True

    def test_unknown_or_none_returns_true(self):
        assert should_probe_alt_svc(None, {}) is True
        assert should_probe_alt_svc("nginx", {}) is True
        assert should_probe_alt_svc("cloudfront", {}) is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cache_altsvc.py::TestShouldProbeAltSvc -v`
Expected: FAIL — `ImportError: cannot import name 'should_probe_alt_svc'`.

- [ ] **Step 3: Implement pre-check**

Append to `corsair/cache/altsvc.py`:

```python
def should_probe_alt_svc(
    cdn_fingerprint: Optional[str],
    baseline_headers: Mapping[str, str],
) -> bool:
    """
    Decide whether the active Alt-Svc reflection probe is worth running.

    Returns False on Cloudflare, Fastly, and Akamai-with-HTTP/3
    (detected by ma=93600 in baseline). True for unknown / no CDN.
    """
    fp = (cdn_fingerprint or "").lower()
    if fp in {"cloudflare", "fastly"}:
        return False
    if fp == "akamai":
        baseline = ""
        for key, value in baseline_headers.items():
            if key.lower() == "alt-svc":
                baseline = value
                break
        if "93600" in baseline:
            return False
    return True
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cache_altsvc.py::TestShouldProbeAltSvc -v`
Expected: 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add corsair/cache/altsvc.py tests/test_cache_altsvc.py
git commit -m "feat(altsvc): CDN pre-check for Cloudflare/Fastly/Akamai+H3"
```

---

## Task 5: Register Three New Findings

**Files:**
- Modify: `corsair/cache/findings.py` (add three Finding templates + registry entries)
- Modify: `tests/test_cache_findings.py:27` (registry-size assertion 19 → 22)

- [ ] **Step 1: Update registry-size assertion to fail first**

Edit `tests/test_cache_findings.py:27`:

```python
        assert len(ALL_CACHE_FINDINGS) == 22
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cache_findings.py -v`
Expected: FAIL — `assert 19 == 22`.

- [ ] **Step 3: Add three Finding templates**

Read `corsair/cache/findings.py:198-219` first to confirm the existing `_WCP_ALT_SVC_POISONING` template is still there. Insert the three new templates immediately after `_WCP_ALT_SVC_POISONING` (between the existing template at line 219 and `_WCP_SET_COOKIE_POISONING` at line 221):

```python
_WCP_ALT_SVC_CROSS_DOMAIN = Finding(
    header="Alt-Svc",
    category=HeaderCategory.CACHING,
    severity=Severity.MEDIUM,
    title="Alt-Svc alt-authority on different registrable domain",
    description=(
        "The Alt-Svc header advertises an alternative service on a different "
        "registrable domain than the request target. A poisoned or malicious "
        "Alt-Svc value can pin browsers to an attacker-controlled HTTP/3 "
        "endpoint; a cross-domain alt-authority is a strong indicator of either "
        "misconfiguration or active exploitation."
    ),
    current_value=None,
    recommendation=(
        "Restrict Alt-Svc alt-authorities to the same registrable domain as the "
        "origin, or omit the host portion (port-only alt-authority) so the "
        "alternative defaults to the origin hostname."
    ),
    example_value='Alt-Svc: h3=":443"; ma=86400',
    reference_url="https://datatracker.ietf.org/doc/html/rfc7838#section-2.1",
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_444],
)

_WCP_ALT_SVC_PRIVATE_HOST = Finding(
    header="Alt-Svc",
    category=HeaderCategory.CACHING,
    severity=Severity.MEDIUM,
    title="Alt-Svc advertises private or non-public alt-authority",
    description=(
        "The Alt-Svc alt-authority resolves to a private-network address "
        "(RFC1918, loopback) or a non-public TLD (.local, .internal, .invalid). "
        "This is almost always an internal-infrastructure leak into a public-"
        "facing response and indicates the Alt-Svc value is generated from an "
        "untrusted source or a stale internal config."
    ),
    current_value=None,
    recommendation=(
        "Strip Alt-Svc from responses served to the public internet when the "
        "alt-authority points to internal infrastructure. Configure the origin "
        "or CDN to override Alt-Svc at the edge."
    ),
    example_value='Alt-Svc: h3=":443"; ma=86400',
    reference_url="https://datatracker.ietf.org/doc/html/rfc7838#section-2.1",
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_444],
)

_WCP_ALT_SVC_EXCESSIVE_PERSISTENCE = Finding(
    header="Alt-Svc",
    category=HeaderCategory.CACHING,
    severity=Severity.LOW,
    title="Alt-Svc ma > 30 days combined with persist=1",
    description=(
        "The Alt-Svc header uses both a max-age greater than 30 days and "
        "persist=1, causing browsers to retain the alternative service mapping "
        "across network-configuration changes for an extended window. This "
        "amplifies the impact of any future Alt-Svc cache poisoning event by "
        "extending victim lock-in beyond the CDN cache TTL."
    ),
    current_value=None,
    recommendation=(
        "Reduce max-age to 86400 (24h) or less. Omit persist=1 unless the "
        "deployment specifically requires alternative services to survive "
        "network changes."
    ),
    example_value='Alt-Svc: h3=":443"; ma=86400',
    reference_url="https://datatracker.ietf.org/doc/html/rfc7838#section-3.1",
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_444],
)
```

- [ ] **Step 4: Insert into ALL_CACHE_FINDINGS registry**

In `corsair/cache/findings.py`, edit the `ALL_CACHE_FINDINGS` dict (currently lines 333-356). Insert three new entries between the existing `"WCP_ALT_SVC_POISONING": _WCP_ALT_SVC_POISONING,` line and `"WCP_SET_COOKIE_POISONING": _WCP_SET_COOKIE_POISONING,`:

```python
    "WCP_ALT_SVC_POISONING": _WCP_ALT_SVC_POISONING,
    "WCP_ALT_SVC_CROSS_DOMAIN": _WCP_ALT_SVC_CROSS_DOMAIN,
    "WCP_ALT_SVC_PRIVATE_HOST": _WCP_ALT_SVC_PRIVATE_HOST,
    "WCP_ALT_SVC_EXCESSIVE_PERSISTENCE": _WCP_ALT_SVC_EXCESSIVE_PERSISTENCE,
    "WCP_SET_COOKIE_POISONING": _WCP_SET_COOKIE_POISONING,
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_cache_findings.py -v`
Expected: All tests pass, including `assert len(ALL_CACHE_FINDINGS) == 22`.

- [ ] **Step 6: Commit**

```bash
git add corsair/cache/findings.py tests/test_cache_findings.py
git commit -m "feat(cache): register 3 new Alt-Svc passive findings (registry 19→22)"
```

---

## Task 6: Auditor Integration & Integration Tests

**Files:**
- Modify: `corsair/cache/oracle.py:26-38` (add `alt_svc` field)
- Modify: `corsair/cache/oracle.py:180-184` (capture `alt-svc` in `establish_oracle`)
- Modify: `corsair/cache/auditor.py` (passive call + active result-loop pre-check filter)
- Create: `tests/test_cache_altsvc_integration.py`

- [ ] **Step 1: Write failing integration test for passive findings**

Create `tests/test_cache_altsvc_integration.py`:

```python
"""End-to-end CacheAuditor scenarios for Alt-Svc hardening."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from corsair.cache.auditor import CacheAuditor


def _mock_response(headers=None, status_code=200, text="ok"):
    response = MagicMock()
    response.status_code = status_code
    response.headers = headers or {}
    response.text = text
    return response


def _audit_with_baseline_headers(url, baseline_headers):
    auditor = CacheAuditor(active=False)  # passive only

    async def fake_get(*args, **kwargs):
        return _mock_response(headers=baseline_headers)

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=fake_get)
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client_cls.return_value = mock_client
        return auditor.audit(url, {})


class TestAltSvcPassiveIntegration:
    def test_cross_domain_and_excessive_persistence_both_emit(self):
        baseline = {
            "alt-svc": 'h3="evil.net:443"; ma=3600000; persist=1',
            "cache-control": "public, max-age=60",
            "x-cache": "HIT",
        }
        findings = _audit_with_baseline_headers("https://api.example.com/v1", baseline)
        ids = [f.title for f in findings]
        assert any("different registrable domain" in t for t in ids)
        assert any("ma > 30 days" in t for t in ids)

    def test_internal_ip_emits_private_host(self):
        baseline = {
            "alt-svc": 'h3="10.0.0.5:443"; ma=86400',
            "cache-control": "public, max-age=60",
            "x-cache": "HIT",
        }
        findings = _audit_with_baseline_headers("https://api.example.com/v1", baseline)
        assert any("private or non-public" in f.title for f in findings)

    def test_missing_alt_svc_no_new_findings(self):
        baseline = {"cache-control": "public, max-age=60", "x-cache": "HIT"}
        findings = _audit_with_baseline_headers("https://api.example.com/v1", baseline)
        for f in findings:
            assert "Alt-Svc" not in f.header or f.header == "Alt-Svc" and "alt-authority" not in f.title.lower()
```

- [ ] **Step 2: Run integration tests to verify they fail**

Run: `pytest tests/test_cache_altsvc_integration.py -v`
Expected: FAIL — passive Alt-Svc findings are not yet emitted by the auditor.

- [ ] **Step 3: Add `alt_svc` field to CacheOracle**

Edit `corsair/cache/oracle.py:26-38`. Add `alt_svc: Optional[str] = None` to the dataclass:

```python
@dataclass
class CacheOracle:
    url: str
    is_cached: bool = False
    cdn_fingerprint: Optional[str] = None
    status_header: Optional[str] = None
    buster_strategy: str = "query_param"
    buster_param: str = "_cb"
    query_string_keyed: Optional[bool] = None
    age_increments: bool = False
    cache_control: Optional[str] = None
    vary_header: Optional[str] = None
    akamai_cache_key: Optional[str] = None
    alt_svc: Optional[str] = None
```

- [ ] **Step 4: Capture `alt-svc` in establish_oracle**

In `corsair/cache/oracle.py`, find the block at lines 180-184 that reads `r1_headers` into oracle fields and add the alt-svc capture:

```python
    r1_headers = {k.lower(): v for k, v in r1.headers.items()}
    oracle.cdn_fingerprint = fingerprint_cdn(r1_headers)
    oracle.cache_control = r1_headers.get("cache-control")
    oracle.vary_header = r1_headers.get("vary")
    oracle.alt_svc = r1_headers.get("alt-svc")
```

- [ ] **Step 5: Wire passive analyzer into auditor**

Edit `corsair/cache/auditor.py`. Add the import near the top:

```python
from urllib.parse import urlparse

from . import altsvc as _altsvc
```

In `_passive_checks()` (after the existing `WCP_PERMISSIVE_CACHE_CONTROL` block, before `return findings`), add:

```python
        if oracle.alt_svc:
            target_host = urlparse(oracle.url).hostname or ""
            for fid in _altsvc.analyze_alt_svc_suspicious(oracle.alt_svc, target_host):
                f = get_finding(fid)
                if f:
                    f.current_value = f"Alt-Svc: {oracle.alt_svc}"
                    findings.append(f)
```

- [ ] **Step 6: Run passive integration tests to verify they pass**

Run: `pytest tests/test_cache_altsvc_integration.py::TestAltSvcPassiveIntegration -v`
Expected: 3 tests pass.

- [ ] **Step 7: Write failing pre-check integration tests**

Append to `tests/test_cache_altsvc_integration.py`:

```python
def _audit_with_oracle(url, baseline_headers, probe_response_headers, probe_status=200):
    """Active audit. First request returns baseline; subsequent (probe) requests
    return probe_response_headers. Caller must include CDN-status hit header
    in baseline so oracle marks is_cached=True."""
    auditor = CacheAuditor(active=True)

    call_count = {"n": 0}

    async def fake_get(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] <= 4:  # baseline + cache-key probes
            return _mock_response(headers=baseline_headers)
        return _mock_response(headers=probe_response_headers, status_code=probe_status)

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=fake_get)
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client_cls.return_value = mock_client
        return auditor.audit(url, {})


class TestAltSvcPreCheckIntegration:
    def test_cloudflare_skips_alt_svc_probe(self):
        baseline = {
            "alt-svc": 'h3=":443"; ma=86400',
            "cf-cache-status": "HIT",
            "cf-ray": "abc",
            "cache-control": "public, max-age=60",
        }
        # Even if the probe response *would* reflect a canary into Alt-Svc,
        # we must not emit WCP_ALT_SVC_POISONING when CDN is Cloudflare.
        probe_resp = {"cf-cache-status": "HIT", "alt-svc": 'h3="canary.invalid:443"'}
        findings = _audit_with_oracle(
            "https://api.example.com/v1", baseline, probe_resp
        )
        ids = [f.title for f in findings]
        assert not any("Alt-Svc cache poisoning" in t for t in ids)
```

- [ ] **Step 8: Run pre-check integration test to verify it fails**

Run: `pytest tests/test_cache_altsvc_integration.py::TestAltSvcPreCheckIntegration -v`
Expected: FAIL — `WCP_ALT_SVC_POISONING` is currently emitted when probe reflects canary, regardless of CDN.

- [ ] **Step 9: Wire pre-check filter into _active_probes**

Edit `corsair/cache/auditor.py`, in `_active_probes()`, modify the result loop (currently lines 189-202). Compute the gate before the loop and drop matching results:

```python
        baseline_alt_svc_headers = {"alt-svc": oracle.alt_svc} if oracle.alt_svc else {}
        alt_svc_probeable = _altsvc.should_probe_alt_svc(
            oracle.cdn_fingerprint, baseline_alt_svc_headers
        )

        alt_svc_skipped = False
        for r in results:
            if isinstance(r, asyncio.CancelledError):
                continue
            if isinstance(r, Exception):
                logger.warning(f"Probe failed: {r}")
                continue
            if not r.confirmed_unkeyed:
                continue

            if r.finding_id == "WCP_ALT_SVC_POISONING" and not alt_svc_probeable:
                alt_svc_skipped = True
                continue

            finding = get_finding(r.finding_id)
            if finding:
                finding.header = r.header_name
                finding.current_value = r.detail
                findings.append(finding)

        if alt_svc_skipped:
            skipped = get_finding("WCP_PROBE_SKIPPED")
            if skipped:
                skipped.current_value = (
                    f"alt_svc_reflection_precheck: cdn={oracle.cdn_fingerprint}"
                )
                findings.append(skipped)

        return findings
```

- [ ] **Step 10: Run integration tests to verify all pass**

Run: `pytest tests/test_cache_altsvc_integration.py -v`
Expected: 4 tests pass.

- [ ] **Step 11: Run full cache test suite to confirm no regressions**

Run: `pytest tests/test_cache_oracle.py tests/test_cache_reflect.py tests/test_cache_probe.py tests/test_cache_auditor_unit.py tests/test_cache_findings.py tests/test_scanner_cache_integration.py tests/test_cache_altsvc.py tests/test_cache_altsvc_integration.py -v`
Expected: All cache tests pass, no regressions in pre-existing test files.

- [ ] **Step 12: Run full project test suite**

Run: `pytest -v`
Expected: All tests pass, count is now ~310+ (was 283 after CORS Wave 2; +28 unit + ~4 integration = ~315).

- [ ] **Step 13: Commit**

```bash
git add corsair/cache/oracle.py corsair/cache/auditor.py tests/test_cache_altsvc_integration.py
git commit -m "feat(altsvc): auditor integration + oracle.alt_svc + pre-check filter"
```

---

## Task 7: Release v0.5.2

**Files:**
- Modify: `corsair/__init__.py` (`__version__`)
- Modify: `pyproject.toml` (`version`)
- Modify: `README.md` (changelog section)

- [ ] **Step 1: Bump version in corsair/__init__.py**

Edit `corsair/__init__.py`. Change `__version__ = "0.5.1"` to:

```python
__version__ = "0.5.2"
```

- [ ] **Step 2: Bump version in pyproject.toml**

Edit `pyproject.toml`. Change `version = "0.5.1"` to:

```toml
version = "0.5.2"
```

- [ ] **Step 3: Add v0.5.2 changelog section to README**

Read `README.md` first to confirm the existing v0.5.1 section header, then insert a new section immediately above v0.5.1. Use today's date (run `date +%Y-%m-%d` to get it; substitute that for `<release-date>`):

```markdown
### v0.5.2 — Alt-Svc Hardening (<release-date>)

**Robustness:**
- Replaced plain-substring canary check on `Alt-Svc` with an alt-authority-anchored regex. Correctly handles `Alt-Svc: clear`, multi-value headers, and draft protocol-ids (`h3-29`).
- Added CDN pre-check: skip the Alt-Svc reflection probe on Cloudflare, Fastly, and Akamai-with-HTTP/3 (`ma=93600` tell). Emits `WCP_PROBE_SKIPPED` instead of a guaranteed-false negative.

**New passive findings (3):**
- `WCP_ALT_SVC_CROSS_DOMAIN` (MEDIUM) — alt-authority on a different registrable domain than the request target. PSL-aware via `tldextract`.
- `WCP_ALT_SVC_PRIVATE_HOST` (MEDIUM) — alt-authority resolves to RFC1918/loopback IP, reserved pseudo-TLD (`.local`, `.internal`, `.invalid`, `.localhost`, `.test`, `.example`), or bare intranet hostname.
- `WCP_ALT_SVC_EXCESSIVE_PERSISTENCE` (LOW) — `ma > 30d` combined with `persist=1`, amplifying browser-side lock-in for any future poisoning event.

**Architecture:**
- New `corsair/cache/altsvc.py` module owns Alt-Svc grammar, canary detection, passive analyzers, and pre-check.
- `CacheOracle` gained an `alt_svc` field captured from the baseline response.

**Dependency:** `tldextract>=5.0.0` added to core dependencies (Public Suffix List parsing).

**Cache findings registry:** 19 → 22.
```

- [ ] **Step 4: Run full test suite one more time before tagging**

Run: `pytest -v`
Expected: All tests pass.

- [ ] **Step 5: Commit release**

```bash
git add corsair/__init__.py pyproject.toml README.md
git commit -m "release: v0.5.2 — Alt-Svc cache poisoning hardening"
```

- [ ] **Step 6: Verify version**

Run: `python -c "import corsair; print(corsair.__version__)"`
Expected: `0.5.2`

---

## Self-Review (post-write checklist)

**Spec coverage:**
- §2.1 public API (5 symbols): Tasks 1, 2, 3, 4 — ✓
- §2.3 touch points (reflect, probe→auditor, auditor passive, findings, pyproject): Tasks 2, 3, 5, 6 — ✓ (probe.py touch redirected to auditor.py per architectural deviation noted in File Structure section)
- §3.1–§3.3 passive rules: Task 3 — ✓
- §4.1 regex: Task 2 — ✓
- §4.2 pre-check: Task 4 (logic) + Task 6 (wire-up) — ✓
- §5 Finding registrations: Task 5 — ✓
- §6 testing (unit + integration + regression): Tasks 1–6 — ✓
- §7 release: Task 7 — ✓

**Placeholder scan:** `<release-date>` is the only token, and Task 7 Step 3 explicitly tells the engineer to substitute `date +%Y-%m-%d` output. No TBDs, no "implement later", no "similar to Task N", no "appropriate error handling".

**Type consistency:**
- `AltSvcEntry` field names (`protocol_id`, `host`, `port`, `ma`, `persist`) consistent across Tasks 1, 3.
- Function names: `parse_alt_svc`, `detect_alt_svc_canary`, `analyze_alt_svc_suspicious`, `should_probe_alt_svc` consistent across all tasks.
- Finding IDs (`WCP_ALT_SVC_CROSS_DOMAIN`, `WCP_ALT_SVC_PRIVATE_HOST`, `WCP_ALT_SVC_EXCESSIVE_PERSISTENCE`) consistent across Tasks 3, 5, 6.
- Registry size: actual count is 19 (verified via grep) — plan uses 19 → 22, which matches reality. Spec text said 20 → 23 (off by one); plan corrects this.
