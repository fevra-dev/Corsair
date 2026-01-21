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
![Version](https://img.shields.io/badge/version-0.1.0-orange)

A comprehensive security header analysis tool with CVE correlation, technology fingerprinting, and AI-powered remediation. Built for the 2026 threat landscape.

## Features

- **60+ Header Checks** - CSP, HSTS, COOP, COEP, CORP, Permissions-Policy, and more
- **1,200+ Fingerprinting Signatures** - Detect servers, CDNs, WAFs, and frameworks
- **CVE Correlation** - Map misconfigurations to known vulnerabilities with CISA KEV integration
- **Compliance Mapping** - OWASP Top 10 2025, PCI-DSS 4.0, SOC 2
- **Historical Tracking** - Monitor security posture changes with drift detection
- **AI Integration** - MCP server for Claude/GPT-powered remediation
- **Multiple Outputs** - Console, JSON, HTML, SARIF (GitHub Code Scanning)

## Installation

```bash
# From source
git clone https://github.com/fevra-dev/Corsair.git
cd corsair
pip install -e .

# With all features
pip install -e ".[full]"

# With MCP/AI integration (Python 3.10+)
pip install -e ".[mcp]"
```

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

## Scoring

| Grade | Score | Description |
|-------|-------|-------------|
| A | 90-100 | Excellent |
| B | 80-89 | Good |
| C | 70-79 | Fair |
| D | 60-69 | Poor |
| F | 0-59 | Critical |

## Author

**Fevra** - [GitHub](https://github.com/fevra-dev)

## License

MIT
