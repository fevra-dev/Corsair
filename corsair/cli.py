"""
Corsair CLI Interface.

Provides command-line interface for security header scanning with:
- Single and batch URL scanning
- Multiple output formats (console, JSON, HTML, SARIF, PDF)
- Historical tracking and comparison
- CI/CD integration with exit codes
- MCP server for AI integration

Usage:
    corsair scan https://example.com
    corsair scan -f urls.txt --output sarif --out-file results.sarif
    corsair history https://example.com
    corsair compare https://example.com
    corsair mcp-server
"""

import sys
import click
import logging
from typing import Optional, List
from pathlib import Path

from . import __version__
from .scanner import HeadScanner
from .reporters import ConsoleReporter, JSONReporter, HTMLReporter
from .reporters.sarif import SARIFReporter
from .utils.logger import CorsairLogger, get_logger

logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# ASCII Art Banner - Corsair (Simple Text)
# ═══════════════════════════════════════════════════════════════════════════════

CORSAIR_BANNER = r"""
   ██████╗ ██████╗ ██████╗ ███████╗ █████╗ ██╗██████╗ 
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗██║██╔══██╗
  ██║     ██║   ██║██████╔╝███████╗███████║██║██████╔╝
  ██║     ██║   ██║██╔══██╗╚════██║██╔══██║██║██╔══██╗
  ╚██████╗╚██████╔╝██║  ██║███████║██║  ██║██║██║  ██║
   ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
                                              v{version}
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ☠  HTTP Security Header Scanner & Analyzer  ☠
"""

CORSAIR_BANNER_SIMPLE = r"""
   ██████╗ ██████╗ ██████╗ ███████╗ █████╗ ██╗██████╗ 
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗██║██╔══██╗
  ██║     ██║   ██║██████╔╝███████╗███████║██║██████╔╝
  ██║     ██║   ██║██╔══██╗╚════██║██╔══██║██║██╔══██╗
  ╚██████╗╚██████╔╝██║  ██║███████║██║  ██║██║██║  ██║
   ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
"""

CORSAIR_MINI = "☠ CORSAIR"


def print_banner(style: str = "full") -> None:
    """Print the Corsair banner."""
    try:
        from rich.console import Console

        console = Console()

        if style == "full":
            console.print(f"[cyan]{CORSAIR_BANNER.format(version=__version__)}[/cyan]")
        elif style == "simple":
            console.print(f"[cyan]{CORSAIR_BANNER_SIMPLE}[/cyan]")
        else:
            console.print(f"[cyan bold]{CORSAIR_MINI}[/cyan bold] v{__version__}")
    except ImportError:
        # Fallback without rich
        if style == "full":
            print(CORSAIR_BANNER.format(version=__version__))
        else:
            print(f"☠ CORSAIR v{__version__}")


def setup_logging(verbose: bool, quiet: bool) -> None:
    """Configure logging based on CLI options."""
    if quiet:
        level = "ERROR"
    elif verbose:
        level = "DEBUG"
    else:
        level = "WARNING"

    CorsairLogger.setup(level=level, verbose=verbose)


def load_targets_from_file(filepath: str) -> List[str]:
    """Load target URLs from a file."""
    targets = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


# ═══════════════════════════════════════════════════════════════════════════════
# Main CLI Group
# ═══════════════════════════════════════════════════════════════════════════════


@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True, help="Show version and exit")
@click.pass_context
def cli(ctx, version):
    """☠ Corsair - HTTP Security Header Scanner

    Analyze security headers for web applications with:

    \b
    • 60+ header checks (CSP, HSTS, COOP, COEP, etc.)
    • CVE correlation with CISA KEV integration
    • Technology fingerprinting (1,200+ signatures)
    • Compliance mapping (OWASP, PCI-DSS)
    • Historical tracking with drift detection
    • AI-powered remediation via MCP

    Examples:

    \b
      corsair scan https://example.com
      corsair scan -f urls.txt --output sarif
      corsair history https://example.com
      corsair compare https://example.com
    """
    if version:
        click.echo(f"☠ Corsair v{__version__}")
        sys.exit(0)

    if ctx.invoked_subcommand is None:
        print_banner("full")
        click.echo(ctx.get_help())


# ═══════════════════════════════════════════════════════════════════════════════
# Scan Command
# ═══════════════════════════════════════════════════════════════════════════════


@cli.command()
@click.argument("targets", nargs=-1)
@click.option("-f", "--file", type=click.Path(exists=True), help="File containing target URLs")
@click.option(
    "-o",
    "--output",
    type=click.Choice(["console", "json", "html", "sarif"]),
    default="console",
    help="Output format",
)
@click.option("--out-file", type=click.Path(), help="Write output to file")
@click.option("-t", "--timeout", default=10, help="Request timeout in seconds")
@click.option("--follow-redirects/--no-follow-redirects", default=True)
@click.option("--max-redirects", default=5, help="Maximum redirects to follow")
@click.option("-q", "--quiet", is_flag=True, help="Minimal output")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("--no-color", is_flag=True, help="Disable colors")
@click.option("--no-banner", is_flag=True, help="Hide ASCII banner")
@click.option("--user-agent", default="Corsair/0.1.0", help="Custom User-Agent")
@click.option("--min-score", default=0, help="Fail if score below threshold (for CI)")
@click.option("--save-history", is_flag=True, help="Save results to history database")
@click.option("--fingerprint/--no-fingerprint", default=True, help="Run fingerprinting")
@click.option("--correlate-cve/--no-correlate-cve", default=True, help="Correlate with CVEs")
@click.option("--cache-probe/--no-cache-probe", default=True, help="Run cache poisoning detection")
@click.option("--cors-probe/--no-cors-probe", default=True, help="Run CORS DAST probing")
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
    cors_evil_origin: str,
) -> None:
    """Scan HTTP security headers for target URLs.

    Examples:

    \b
      corsair scan https://example.com
      corsair scan https://google.com https://github.com
      corsair scan -f urls.txt --output json --out-file results.json
      corsair scan https://example.com --output sarif --min-score 70
    """
    setup_logging(verbose, quiet)

    # Show banner
    if not quiet and not no_banner and output == "console":
        print_banner("mini")
        click.echo()

    # Collect targets
    target_list = list(targets)
    if file:
        target_list.extend(load_targets_from_file(file))

    if not target_list:
        click.echo(click.style("Error: No targets specified", fg="red"), err=True)
        click.echo("Usage: corsair scan <url> [url2 ...]")
        sys.exit(3)

    # Deduplicate
    target_list = list(dict.fromkeys(target_list))

    if not quiet:
        click.echo(f"Scanning {len(target_list)} target(s)...\n")

    # Create scanner
    scanner = HeadScanner(
        timeout=timeout,
        follow_redirects=follow_redirects,
        max_redirects=max_redirects,
        user_agent=user_agent,
        cache_probe=cache_probe,
        cors_probe=cors_probe,
        cors_evil_origin=cors_evil_origin,
    )

    # Run scan
    try:
        report = scanner.scan(target_list)
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        logger.error(f"Scan failed: {e}")
        sys.exit(3)

    # Run fingerprinting if enabled
    if fingerprint:
        try:
            from .fingerprint.engine import FingerprintEngine

            engine = FingerprintEngine()

            for result in report.results:
                if not result.error:
                    result.fingerprints = engine.detect(result.headers)
        except Exception as e:
            logger.warning(f"Fingerprinting failed: {e}")

    # Correlate CVEs if enabled
    if correlate_cve:
        try:
            from .intelligence.cve_correlator import CVECorrelator

            correlator = CVECorrelator()
            correlator.initialize_sync()

            for result in report.results:
                result.findings = correlator.enrich_all_findings_sync(result.findings)
        except Exception as e:
            logger.warning(f"CVE correlation failed: {e}")

    # Save to history if requested
    if save_history:
        try:
            from .history.database import HistoryDatabase

            db = HistoryDatabase()

            for result in report.results:
                if not result.error:
                    db.save_scan(result)

            if not quiet:
                click.echo("Results saved to history database")
        except Exception as e:
            logger.warning(f"Failed to save history: {e}")

    # Select reporter
    reporters = {
        "console": ConsoleReporter,
        "json": JSONReporter,
        "html": HTMLReporter,
        "sarif": SARIFReporter,
    }
    reporter = reporters[output](quiet=quiet, verbose=verbose, no_color=no_color)

    # Generate output
    output_str = reporter.generate(report)

    # Write output
    if out_file:
        with open(out_file, "w") as f:
            f.write(output_str)
        if not quiet:
            click.echo(f"\nReport written to: {out_file}")
    else:
        click.echo(output_str)

    # Summary line
    if not quiet and output == "console":
        grade_colors = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}
        grade = report.average_grade
        color = grade_colors.get(grade, "white")
        click.echo(f"\nAverage Score: {report.average_score:.0f}/100 ", nl=False)
        click.echo(click.style(f"({grade})", fg=color, bold=True))

    # Determine exit code
    if min_score > 0 and report.average_score < min_score:
        click.echo(
            click.style(
                f"\nFailed: Average score {report.average_score:.1f} < {min_score}", fg="red"
            ),
            err=True,
        )
        sys.exit(2)

    # Exit codes based on score
    if report.average_score >= 80:
        sys.exit(0)  # Good
    elif report.average_score >= 50:
        sys.exit(1)  # Needs improvement
    else:
        sys.exit(2)  # Critical issues


# ═══════════════════════════════════════════════════════════════════════════════
# History Command
# ═══════════════════════════════════════════════════════════════════════════════


@cli.command()
@click.argument("url")
@click.option("--limit", default=10, help="Number of records to show")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def history(url: str, limit: int, as_json: bool) -> None:
    """Show scan history for a URL.

    Example:

        corsair history https://example.com
    """
    try:
        from .history.database import HistoryDatabase
        import json

        db = HistoryDatabase()
        records = db.get_history(url, limit=limit)

        if not records:
            click.echo(f"No history found for {url}")
            return

        if as_json:
            click.echo(json.dumps(records, indent=2))
        else:
            click.echo(f"\nScan History for {url}\n")
            click.echo("─" * 60)

            for record in records:
                date = record["scan_date"][:19]
                score = record["score"]
                grade = record["grade"]

                color = "green" if score >= 80 else "yellow" if score >= 50 else "red"

                click.echo(f"{date}  Score: " + click.style(f"{score}/100 ({grade})", fg=color))

        # Show statistics
        stats = db.get_statistics(url)
        if not as_json:
            click.echo("─" * 60)
            click.echo(f"Total Scans: {stats['total_scans']}")
            click.echo(f"Average Score: {stats['average_score']}")
            click.echo(f"Trend: {stats['trend']}")
            click.echo(f"Drift Alerts: {stats['drift_alerts']}")

    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# Compare Command
# ═══════════════════════════════════════════════════════════════════════════════


@cli.command()
@click.argument("url")
def compare(url: str) -> None:
    """Compare current scan with previous results.

    Example:

        corsair compare https://example.com
    """
    try:
        from .history.database import HistoryDatabase

        # Run new scan
        click.echo(f"Scanning {url}...")

        scanner = HeadScanner()
        result = scanner.scan_target(url)

        if result.error:
            click.echo(click.style(f"Scan failed: {result.error}", fg="red"))
            return

        # Get history
        db = HistoryDatabase()
        history = db.get_history(url, limit=1)

        click.echo(f"\nCurrent Score: {result.score}/100 ({result.grade})")

        if not history:
            click.echo("\nNo previous scans to compare with.")
            # Save current scan
            db.save_scan(result)
            click.echo("Current scan saved to history.")
            return

        previous = history[0]
        delta = result.score - previous["score"]

        # Show comparison
        click.echo(f"Previous Score: {previous['score']}/100 ({previous['grade']})")
        click.echo(f"Previous Date: {previous['scan_date'][:10]}")

        if delta > 0:
            click.echo(click.style(f"Change: +{delta} (Improving)", fg="green"))
        elif delta < 0:
            click.echo(click.style(f"Change: {delta} (Declining)", fg="red"))
        else:
            click.echo(click.style("Change: 0 (Stable)", fg="yellow"))

        # Save current scan
        db.save_scan(result)

        # Check for drift alerts
        alerts = db.get_drift_alerts(url, limit=5)
        if alerts:
            click.echo("\nRecent Drift Alerts:")
            for alert in alerts[:3]:
                click.echo(f"  - [{alert['severity']}] {alert['description']}")

    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# Stats Command
# ═══════════════════════════════════════════════════════════════════════════════


@cli.command()
@click.argument("url")
def stats(url: str) -> None:
    """Show statistics for a URL.

    Example:

        corsair stats https://example.com
    """
    try:
        from .history.database import HistoryDatabase

        db = HistoryDatabase()
        statistics = db.get_statistics(url)

        if statistics["total_scans"] == 0:
            click.echo(f"No scan history for {url}")
            return

        click.echo(f"\nStatistics for {url}\n")
        click.echo(f"Total Scans: {statistics['total_scans']}")
        click.echo(f"Average Score: {statistics['average_score']}")
        click.echo(f"Trend: {statistics['trend']}")
        click.echo(f"Drift Alerts: {statistics['drift_alerts']}")

        if statistics["recent_scores"]:
            scores = statistics["recent_scores"]
            click.echo(f"\nRecent Scores: {' -> '.join(map(str, reversed(scores)))}")

    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# Cleanup Command
# ═══════════════════════════════════════════════════════════════════════════════


@cli.command()
@click.option("--days", default=90, help="Delete records older than N days")
@click.option("--yes", is_flag=True, help="Skip confirmation")
def cleanup(days: int, yes: bool) -> None:
    """Clean up old history records.

    Example:

        corsair cleanup --days 30
    """
    try:
        from .history.database import HistoryDatabase

        if not yes:
            click.confirm(f"Delete scan records older than {days} days?", abort=True)

        db = HistoryDatabase()
        deleted = db.cleanup(days=days)

        click.echo(f"Deleted {deleted} old records")

    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# MCP Server Command
# ═══════════════════════════════════════════════════════════════════════════════


@cli.command("mcp-server")
def mcp_server() -> None:
    """Start the MCP server for AI/LLM integration.

    The MCP server exposes Corsair tools to AI agents
    via the Model Context Protocol.

    Example:

        corsair mcp-server
    """
    try:
        from .mcp.server import run_server

        print_banner("simple")
        click.echo("\nStarting MCP Server...\n")
        run_server()
    except ImportError:
        click.echo(
            click.style("Error: fastmcp not installed. Run: pip install fastmcp", fg="red"),
            err=True,
        )
        sys.exit(1)
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# About Command
# ═══════════════════════════════════════════════════════════════════════════════


@cli.command()
def about() -> None:
    """Show information about Corsair."""
    print_banner("full")
    click.echo(
        f"""
  Author:  Fevra
  License: MIT
  
  Features:
    - 60+ HTTP security header checks
    - 1,200+ fingerprinting signatures
    - CVE correlation with CISA KEV integration
    - OWASP Top 10 2025 & PCI-DSS 4.0 mapping
    - Historical tracking with drift detection
    - AI-powered remediation via MCP
    - SARIF output for GitHub Code Scanning

  Built for the 2026 threat landscape.
  
  GitHub: https://github.com/fevra-dev/Corsair
    """
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════════


def main():
    """Main entry point for CLI."""
    cli()


if __name__ == "__main__":
    main()
