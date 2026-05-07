# Corsair

```
   ██████╗ ██████╗ ██████╗ ███████╗ █████╗ ██╗██████╗ 
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗██║██╔══██╗
  ██║     ██║   ██║██████╔╝███████╗███████║██║██████╔╝
  ██║     ██║   ██║██╔══██╗╚════██║██╔══██║██║██╔══██╗
  ╚██████╗╚██████╔╝██║  ██║███████║██║  ██║██║██║  ██║
   ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
```

**HTTP Security Header Scanner & Analyzer**

![Python](https://img.shields.io/badge/python-3.9+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-0.2.0-orange)

A comprehensive security scanner with HTTP header analysis, TLS/SSL auditing, CVE correlation, technology fingerprinting, and AI-powered remediation. Built for the 2026 threat landscape.

## Features

- **60+ Header Checks** - CSP, HSTS, COOP, COEP, CORP, Permissions-Policy, and more
- **TLS/SSL Auditing** - Protocol versions, cipher suites, certificate validation, and vulnerability detection (Heartbleed, ROBOT, CRIME, and more)
- **Web Cache Poisoning Detection** - CDN fingerprinting, unkeyed header probing, CPDoS detection, and cache oracle analysis
- **1,200+ Fingerprinting Signatures** - Detect servers, CDNs, WAFs, and frameworks
- **CVE Correlation** - Map misconfigurations to known vulnerabilities with CISA KEV integration
- **Compliance Mapping** - OWASP Top 10 2025, PCI-DSS 4.0, NIST SP 800-52r2, SOC 2
- **Historical Tracking** - Monitor security posture changes with drift detection
- **AI Integration** - MCP server for Claude/GPT-powered remediation
- **Multiple Outputs** - Console, JSON, HTML, SARIF (GitHub Code Scanning)

## Installation

```bash
# From source
git clone https://github.com/fevra-dev/Corsair.git
cd corsair
pip install -e .

# With TLS/SSL auditing
pip install -e ".[tls]"

# With all features (includes TLS)
pip install -e ".[full]"

# With MCP/AI integration (Python 3.10+)
pip install -e ".[mcp]"
```

> **Note:** TLS auditing uses [sslyze](https://github.com/nabla-c0d3/sslyze) (AGPL-3.0), which is kept as an optional dependency to preserve Corsair's MIT license.

## Quick Start

```bash
# Scan a URL
corsair scan https://example.com

# Scan multiple URLs
corsair scan https://google.com https://github.com

# Output as SARIF for GitHub
corsair scan https://example.com --output sarif --out-file results.sarif

# Save to history and track changes
corsair scan https://example.com --save-history
corsair compare https://example.com

# View scan history
corsair history https://example.com
```

## Python API

```python
from corsair import HeadScanner

scanner = HeadScanner()
result = scanner.scan_target("https://example.com")

print(f"Score: {result.score}/100 ({result.grade})")
print(f"Critical Issues: {result.critical_count}")

for finding in result.findings:
    print(f"[{finding.severity.name}] {finding.title}")
```

## CI/CD Integration

```yaml
# GitHub Actions
- run: pip install corsair-scan
- run: |
    corsair scan https://your-site.com \
      --output sarif \
      --out-file results.sarif \
      --min-score 70
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Score >= 80 (Good) |
| 1 | Score >= 50 (Needs improvement) |
| 2 | Score < 50 (Critical issues) |
| 3 | Error |

## Headers Analyzed

**Security**: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy

**Cross-Origin Isolation**: Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, Cross-Origin-Resource-Policy, Origin-Agent-Cluster

**Cookies**: Secure, HttpOnly, SameSite, __Host- prefix, __Secure- prefix

**Information Disclosure**: Server, X-Powered-By, X-AspNet-Version

## TLS/SSL Auditing

When sslyze is installed, Corsair automatically audits TLS configuration on HTTPS targets. 25 checks across four categories:

**Protocols**: SSLv2 (DROWN), SSLv3 (POODLE), TLS 1.0 (BEAST), TLS 1.1, TLS 1.3 support

**Cipher Suites**: RC4, 3DES (Sweet32), NULL, EXPORT (LOGJAM), forward secrecy, weak DH parameters

**Certificates**: Expiry, hostname mismatch, self-signed, weak signatures (SHA-1/MD5), short keys, OCSP stapling

**Vulnerabilities**: Heartbleed (CVE-2014-0160), ROBOT, CCS Injection (CVE-2014-0224), TLS compression (CRIME), missing FALLBACK_SCSV

TLS findings deduct from the same 0-100 score as header findings. A site with perfect headers but broken TLS will get a bad grade.

## Web Cache Poisoning Detection

Corsair automatically tests for web cache poisoning vulnerabilities on all targets. 16 checks across three categories:

**Passive**: Missing `Vary: Origin`, public caching of authenticated content, unkeyed query strings, permissive cache TTLs

**Active (Canary Injection)**: Probes 16 unkeyed headers (X-Forwarded-Host, X-Original-URL, etc.) using a 3-phase canary injection protocol that safely detects whether injected values persist in cached responses

**CPDoS**: Tests for Cache Poisoning Denial of Service via oversized headers, malformed headers, and method override headers

Active probing uses cache busters to isolate test requests and includes a safety abort if any canary leaks into the live cache. Disable active probing with `--no-cache-probe`.

## Scoring

| Grade | Score | Description |
|-------|-------|-------------|
| A | 90-100 | Excellent |
| B | 80-89 | Good |
| C | 70-79 | Fair |
| D | 60-69 | Poor |
| F | 0-59 | Critical |

## Changelog

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

### v0.5.4 — Reporting-Endpoints Coherence Detection

**Released:** 2026-05-03

#### New: Reporting-Endpoints Coherence Analyzer

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

### v0.5.2 — Alt-Svc Hardening (2026-04-25)

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

### v0.5.0 — CORS DAST Wave 1 (2026-04-23)

**New `corsair/cors/` package** — actively probes CORS misconfigurations by sending Origin-varied GETs and analyzing ACAO/ACAC reflection. Ships 5 Core finding classes:

- `CORS_ARBITRARY_ORIGIN_CRED` (CRITICAL) — arbitrary origin reflected with credentials.
- `CORS_ARBITRARY_ORIGIN` (HIGH) — arbitrary origin reflected without credentials.
- `CORS_NULL_ORIGIN_CRED` (HIGH) — `Origin: null` trusted with credentials.
- `CORS_NULL_ORIGIN` (MEDIUM) — `Origin: null` trusted without credentials.
- `CORS_WILDCARD_CRED` (MEDIUM) — ACAO `*` alongside `Access-Control-Allow-Credentials: true`.

**Signal-driven severity heuristic** — CRITICAL/HIGH findings on the arbitrary-origin class downgrade one step when no sensitivity signal (Set-Cookie, Authorization request header, JSON response, or login redirect) is observed.

**CLI flags**
- `--cors-probe / --no-cors-probe` (default on)
- `--cors-evil-origin URL` (default `https://evil.example`)

**Safety**
- Preemptive abort on confirmed CRITICAL — same pattern as cache v0.4.1.
- No state-changing probes, no credentialed probes, no traffic to internal networks.

**Refactor** — static CORS analyzer migrated into `corsair/cors/passive.py` as a pure function. `corsair/analyzers/cors.py` is now a thin adapter so the analyzer registry keeps working; `CORSAuditor` is the source of truth for CORS findings and duplicates from the legacy path are stripped during `scan_target()`.

**Deferred to later waves**
- Subdomain/regex bypass matrix, protocol downgrade, internal-network origin probes (v0.5.1 — Wave 2).
- Preflight divergence and CDN cache-key divergence probes (v0.5.2 — Wave 3).
- State-changing probes, framework-default heuristic, third-party XSS correlation (v0.5.3 — Wave 4).

### v0.4.1 — Cache Module Hardening (2026-04-19)

**Detection gaps closed:**
- `WCP_ALT_SVC_POISONING` (HIGH): Alt-Svc cache poisoning via unkeyed header — HTTP/3 cross-protocol vector where attacker pins victim browsers to a malicious QUIC endpoint.
- `WCP_SET_COOKIE_POISONING` (HIGH): Set-Cookie cache poisoning via unkeyed header — session fixation and cookie injection via cached response headers.

**Correctness:**
- `is_cached` now falls back to Age-increment evidence when cache-status headers are absent.
- `query_string_keyed` is now conservative (`Optional[bool]`). Akamai `X-Cache-Key` is parsed as an authoritative signal for cache-key composition.
- `WCP_CACHE_KEYING_UNDETERMINED` (INFO) fires when keying cannot be confirmed; active probing is skipped in that state to avoid inadvertent live-cache poisoning.

**Spec compliance:**
- Active probing is preemptively cancelled when live poisoning is confirmed (was: cooperative, allowed 4 in-flight probes to complete).

## Author

**Fevra** - [GitHub](https://github.com/fevra-dev)

## License

MIT
