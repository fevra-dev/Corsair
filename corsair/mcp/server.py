"""
Corsair MCP Server.

Exposes scanning capabilities to LLM agents via Model Context Protocol.
Enables autonomous security scanning from Claude, GPT, and other AI agents.

Run with:
    corsair mcp-server

Or programmatically:
    from corsair.mcp.server import mcp
    mcp.run()

MCP Tools Provided:
    - scan_headers: Scan HTTP security headers for a URL
    - generate_csp: Generate a Content-Security-Policy
    - compare_with_history: Compare current scan with historical data
    - get_remediation: Get framework-specific remediation code
"""

from typing import Dict, List, Optional, Any
import json

from ..utils.logger import get_logger

logger = get_logger(__name__)

# Try to import FastMCP
try:
    from fastmcp import FastMCP

    FASTMCP_AVAILABLE = True
except ImportError:
    FASTMCP_AVAILABLE = False
    logger.warning("[MCP] fastmcp not installed. MCP server unavailable.")


# Initialize MCP server only if available
if FASTMCP_AVAILABLE:
    mcp = FastMCP(
        "Corsair",
        description=(
            "⚓ HTTP security header scanner with CVE correlation and AI remediation. "
            "Analyzes 60+ security headers and provides framework-specific fixes."
        ),
    )
else:
    mcp = None


def _scan_headers_impl(
    url: str, save_history: bool = False, framework: str = "generic"
) -> Dict[str, Any]:
    """
    Implementation of scan_headers tool.

    Separate from decorator for testability.
    """
    from ..scanner import HeadScanner
    from ..fingerprint.engine import FingerprintEngine
    from ..intelligence.cve_correlator import CVECorrelator
    from ..compliance.frameworks import ComplianceMapper
    from ..history.database import HistoryDatabase

    logger.info(f"[MCP] scan_headers called for {url}")

    # Initialize components
    scanner = HeadScanner()
    fingerprint_engine = FingerprintEngine()
    cve_correlator = CVECorrelator()
    compliance_mapper = ComplianceMapper()

    # Run scan
    result = scanner.scan_target(url)

    if result.error:
        return {"error": result.error, "url": url}

    # Run fingerprinting
    fingerprints = fingerprint_engine.detect(result.headers)
    result.fingerprints = fingerprints

    # Enrich with CVE data
    cve_correlator.initialize_sync()
    result.findings = cve_correlator.enrich_all_findings_sync(result.findings)

    # Map compliance
    result.findings = compliance_mapper.map_all_findings(result.findings)

    # Save to history if requested
    if save_history:
        try:
            db = HistoryDatabase()
            scan_id = db.save_scan(result)
            logger.info(f"[MCP] Saved scan {scan_id} to history")
        except Exception as e:
            logger.warning(f"[MCP] Failed to save history: {e}")

    # Generate remediation suggestions
    remediation = _generate_remediation_impl(result.findings, framework)

    # Build response
    response = {
        "url": result.url,
        "final_url": result.final_url,
        "score": result.score,
        "grade": result.grade,
        "status_code": result.status_code,
        "scan_time_ms": result.scan_time_ms,
        "summary": {
            "total_findings": len(result.findings),
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "pass": result.pass_count,
            "cve_count": result.cve_count,
            "kev_count": result.kev_count,
        },
        "findings": [
            {
                "header": f.header,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "recommendation": f.recommendation,
                "cve_ids": [c.cve_id for c in f.cve_correlations],
                "in_cisa_kev": any(c.in_cisa_kev for c in f.cve_correlations),
            }
            for f in result.findings
            if f.severity.value not in ["PASS", "INFO"]
        ],
        "fingerprints": [
            {"name": fp.name, "version": fp.version, "category": fp.category}
            for fp in result.fingerprints[:5]  # Limit to top 5
        ],
        "remediation": remediation,
    }

    logger.info(f"[MCP] Scan complete: {result.score}/100 ({result.grade})")

    return response


def _generate_remediation_impl(findings: List, framework: str) -> Dict[str, Dict]:
    """Generate remediation code for findings."""
    remediation = {}

    # Framework-specific templates
    templates = {
        "nextjs": {
            "Content-Security-Policy": """
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
  
  const csp = `
    default-src 'self';
    script-src 'self' 'nonce-${nonce}' 'strict-dynamic';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data: https:;
    font-src 'self';
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
  `.replace(/\\s+/g, ' ').trim();

  const response = NextResponse.next();
  response.headers.set('Content-Security-Policy', csp);
  response.headers.set('x-nonce', nonce);
  return response;
}
""",
            "Strict-Transport-Security": """
// next.config.js
module.exports = {
  async headers() {
    return [{
      source: '/:path*',
      headers: [{
        key: 'Strict-Transport-Security',
        value: 'max-age=31536000; includeSubDomains; preload'
      }]
    }];
  }
};
""",
        },
        "express": {
            "Content-Security-Policy": """
// Install helmet: npm install helmet
const helmet = require('helmet');

app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'strict-dynamic'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"]
  }
}));
""",
            "Strict-Transport-Security": """
app.use(helmet.hsts({
  maxAge: 31536000,
  includeSubDomains: true,
  preload: true
}));
""",
        },
        "generic": {
            "Content-Security-Policy": """
# Add to your web server configuration:
Content-Security-Policy: default-src 'self'; script-src 'self' 'strict-dynamic'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
""",
            "Strict-Transport-Security": """
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
""",
        },
    }

    framework_templates = templates.get(framework, templates["generic"])

    for finding in findings:
        if finding.severity.value in ["CRITICAL", "HIGH", "MEDIUM"]:
            header = finding.header
            if header in framework_templates:
                remediation[header] = {
                    "code": framework_templates[header],
                    "framework": framework,
                    "explanation": f"Fix for {finding.title}",
                }

    return remediation


def _generate_csp_impl(
    requirements: str, framework: str = "generic", strict: bool = True
) -> Dict[str, Any]:
    """Implementation of generate_csp tool."""
    logger.info(f"[MCP] generate_csp called: {requirements[:50]}...")

    # Build CSP based on requirements
    if strict:
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'strict-dynamic' 'nonce-{NONCE}'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "upgrade-insecure-requests"
        )
    else:
        csp = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "object-src 'none'"
        )

    # Framework-specific implementation
    implementations = {
        "nextjs": """
// middleware.ts
import { NextResponse } from 'next/server';
import crypto from 'crypto';

export function middleware(request) {
  const nonce = crypto.randomUUID();
  const cspHeader = `%CSP%`.replace('{NONCE}', nonce);
  
  const response = NextResponse.next();
  response.headers.set('Content-Security-Policy', cspHeader);
  response.headers.set('x-nonce', nonce);
  return response;
}
""",
        "express": """
const crypto = require('crypto');

app.use((req, res, next) => {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.locals.nonce = nonce;
  res.setHeader('Content-Security-Policy', 
    `%CSP%`.replace('{NONCE}', nonce));
  next();
});
""",
        "generic": "Content-Security-Policy: %CSP%",
    }

    impl_template = implementations.get(framework, implementations["generic"])
    implementation = impl_template.replace("%CSP%", csp)

    return {
        "csp_header": csp,
        "framework": framework,
        "strict_mode": strict,
        "implementation": implementation,
        "explanation": (
            f"Generated {'strict' if strict else 'basic'} CSP for {framework}. "
            + ("Uses nonces and strict-dynamic for modern browsers." if strict else "")
        ),
    }


# Register MCP tools if available
if FASTMCP_AVAILABLE and mcp:

    @mcp.tool()
    def scan_headers(url: str, save_history: bool = False, framework: str = "generic") -> Dict:
        """
        Scan HTTP security headers for a given URL.

        Analyzes 60+ security headers and returns:
        - Security score (0-100) and grade (A-F)
        - Detailed findings with severity levels
        - CVE correlations for misconfigurations
        - CISA KEV (Known Exploited Vulnerabilities) correlation
        - Framework-specific remediation suggestions

        Args:
            url: The URL to scan (e.g., "https://example.com")
            save_history: Save results to history database for trend tracking
            framework: Target framework for remediation code (nextjs, express, generic)

        Returns:
            Complete scan result with findings and recommendations

        Example:
            result = scan_headers("https://google.com", framework="nextjs")
            print(f"Score: {result['score']}/100 ({result['grade']})")
        """
        return _scan_headers_impl(url, save_history, framework)

    @mcp.tool()
    def generate_csp(requirements: str, framework: str = "generic", strict: bool = True) -> Dict:
        """
        Generate a Content-Security-Policy based on requirements.

        Creates a secure CSP that meets your application's needs
        while following security best practices.

        Args:
            requirements: Natural language description of what your app needs
                         (e.g., "React SPA with Google Analytics and Stripe")
            framework: Target framework (nextjs, express, generic)
            strict: Use strict-dynamic and nonces (recommended for modern apps)

        Returns:
            Generated CSP header and implementation code

        Example:
            result = generate_csp(
                "React app with YouTube embeds",
                framework="nextjs",
                strict=True
            )
        """
        return _generate_csp_impl(requirements, framework, strict)

    @mcp.tool()
    def compare_with_history(url: str, days: int = 30) -> Dict:
        """
        Compare current scan with historical data.

        Detects configuration drift and security regressions.

        Args:
            url: URL to scan and compare
            days: Number of days of history to compare against

        Returns:
            Current scan result with historical comparison
        """
        from ..history.database import HistoryDatabase

        logger.info(f"[MCP] compare_with_history for {url}")

        # Run current scan
        current = _scan_headers_impl(url, save_history=True, framework="generic")

        if "error" in current:
            return current

        # Get historical data
        db = HistoryDatabase()
        history = db.get_history(url, limit=10)

        if not history:
            return {
                "current": current,
                "comparison": None,
                "message": "No historical data available for comparison",
            }

        # Compare with most recent
        previous = history[0]

        return {
            "current": current,
            "comparison": {
                "previous_date": previous["scan_date"],
                "previous_score": previous["score"],
                "score_delta": current["score"] - previous["score"],
                "trend": (
                    "improving"
                    if current["score"] > previous["score"]
                    else "declining" if current["score"] < previous["score"] else "stable"
                ),
            },
            "history_count": len(history),
        }

    @mcp.tool()
    def get_remediation(header_name: str, issue_type: str, framework: str = "generic") -> Dict:
        """
        Get AI-generated remediation code for a specific header issue.

        Args:
            header_name: The header with the issue (e.g., "Content-Security-Policy")
            issue_type: Type of issue (e.g., "missing", "unsafe-inline")
            framework: Target framework for code generation

        Returns:
            Remediation code and explanation
        """
        logger.info(f"[MCP] get_remediation: {header_name} - {issue_type}")

        # Build mock finding to get remediation
        from ..models import Finding, Severity, HeaderCategory

        mock_finding = Finding(
            header=header_name,
            category=HeaderCategory.CONTENT,
            severity=Severity.HIGH,
            title=f"{header_name} {issue_type}",
            description="",
            current_value=None,
            recommendation="",
            example_value="",
            reference_url="",
        )

        remediation = _generate_remediation_impl([mock_finding], framework)

        return remediation.get(
            header_name,
            {
                "code": f"// No specific remediation template for {header_name}",
                "framework": framework,
                "explanation": f"Add {header_name} header per documentation",
            },
        )


def run_server():
    """Run the MCP server."""
    if not FASTMCP_AVAILABLE:
        logger.error("[MCP] Cannot run server: fastmcp not installed")
        print("Error: fastmcp not installed. Run: pip install fastmcp")
        return

    logger.info("[MCP] Starting Corsair MCP server...")
    mcp.run()


# Entry point
if __name__ == "__main__":
    run_server()
