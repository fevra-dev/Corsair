"""Colored console output reporter."""

import click
from ..models import ScanReport, TargetResult, Finding, Severity
from ..tls import tls_available
from .base import BaseReporter


class ConsoleReporter(BaseReporter):
    """Console reporter with colored output."""

    SEVERITY_COLORS = {
        Severity.CRITICAL: ("red", True),
        Severity.HIGH: ("red", False),
        Severity.MEDIUM: ("yellow", False),
        Severity.LOW: ("green", False),
        Severity.INFO: ("blue", False),
        Severity.PASS: ("green", False),
    }

    def severity_style(self, severity: Severity) -> str:
        """Get styled severity string."""
        color, bold = self.SEVERITY_COLORS.get(severity, ("white", False))
        if self.no_color:
            return severity.value
        return click.style(severity.value, fg=color, bold=bold)

    def generate(self, report: ScanReport) -> str:
        """Generate console output."""
        lines = []

        if not self.quiet:
            lines.append("")
            lines.append("╔══════════════════════════════════════════════════════════════╗")
            lines.append("║  ☠ Corsair - HTTP Security Header Scanner                     ║")
            lines.append("╚══════════════════════════════════════════════════════════════╝")

        for result in report.results:
            lines.extend(self._format_result(result))

        # TLS hint when sslyze is not installed
        if not tls_available():
            has_https = any(
                r.final_url.startswith("https://") for r in report.results if not r.error
            )
            if has_https:
                hint = "  ℹ TLS analysis available: pip install corsair-scan[tls]"
                if not self.no_color:
                    hint = click.style(hint, dim=True)
                lines.append(hint)

        # Summary
        if not self.quiet and len(report.results) > 1:
            lines.append("")
            lines.append("═" * 64)
            lines.append(f"Targets Scanned: {report.targets_scanned}")
            lines.append(f"Average Score: {report.average_score:.1f}/100")
            lines.append(f"Duration: {report.scan_duration_ms / 1000:.2f}s")
            lines.append("═" * 64)

        return "\n".join(lines)

    def _format_result(self, result: TargetResult) -> list:
        """Format a single target result."""
        lines = []

        lines.append("")
        lines.append(f"Target: {result.url}")

        if result.error:
            lines.append(click.style(f"Error: {result.error}", fg="red"))
            return lines

        if result.url != result.final_url:
            lines.append(f"Final URL: {result.final_url}")

        lines.append(f"Status: {result.status_code}")
        lines.append("")

        # Score with color
        score_color = "green" if result.score >= 80 else "yellow" if result.score >= 50 else "red"
        score_str = (
            click.style(
                f"Security Score: {result.score}/100 (Grade: {result.grade})",
                fg=score_color,
                bold=True,
            )
            if not self.no_color
            else f"Security Score: {result.score}/100 (Grade: {result.grade})"
        )

        lines.append("═" * 64)
        lines.append(score_str)
        lines.append("═" * 64)

        # Findings
        lines.append("")
        lines.append("┌" + "─" * 62 + "┐")
        lines.append("│ FINDINGS" + " " * 53 + "│")
        lines.append("└" + "─" * 62 + "┘")

        # Group by severity
        for finding in result.findings:
            if finding.severity == Severity.PASS and not self.verbose:
                continue
            lines.extend(self._format_finding(finding))

        # Summary line
        lines.append("")
        lines.append("─" * 64)
        summary = (
            f"Summary: {result.critical_count} Critical | "
            f"{result.high_count} High | {result.medium_count} Medium | "
            f"{result.low_count} Low | {result.pass_count} Pass"
        )
        lines.append(summary)
        lines.append("─" * 64)

        return lines

    def _format_finding(self, finding: Finding) -> list:
        """Format a single finding."""
        lines = []
        lines.append("")

        if finding.severity == Severity.PASS:
            check = click.style("✓", fg="green") if not self.no_color else "✓"
            lines.append(f"[{self.severity_style(finding.severity)}] {finding.header}")
            lines.append(f"  {check} {finding.title}")
            if finding.current_value:
                lines.append(f"  Value: {finding.current_value[:60]}...")
        else:
            lines.append(f"[{self.severity_style(finding.severity)}] {finding.title}")
            lines.append(f"  {finding.description}")
            if finding.current_value:
                lines.append(f"  Current: {finding.current_value[:60]}...")
            lines.append(f"")
            lines.append(f"  Recommendation: {finding.recommendation}")
            lines.append(f"  Example: {finding.example_value}")
            if finding.reference_url:
                lines.append(f"  Reference: {finding.reference_url}")

        return lines
