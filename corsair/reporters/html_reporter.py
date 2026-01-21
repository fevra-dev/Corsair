"""HTML report generator."""

from jinja2 import Template
from ..models import ScanReport, Severity
from .base import BaseReporter


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HeadScan Security Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #e0e0e0; line-height: 1.6; padding: 20px; }
        .container { max-width: 1000px; margin: 0 auto; }
        h1 { text-align: center; margin-bottom: 30px; color: #fff; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .summary-card { background: #2d2d44; padding: 20px; border-radius: 8px; text-align: center; }
        .summary-card .value { font-size: 2em; font-weight: bold; }
        .summary-card .label { font-size: 0.9em; color: #888; }
        .target { background: #2d2d44; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .target-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px solid #3d3d54; }
        .target-url { font-size: 1.2em; word-break: break-all; }
        .score { font-size: 1.5em; font-weight: bold; }
        .score.good { color: #69db7c; }
        .score.medium { color: #ffd43b; }
        .score.poor { color: #ff6b6b; }
        .finding { background: #1a1a2e; border-radius: 6px; padding: 15px; margin-bottom: 10px; border-left: 4px solid #888; }
        .finding.critical { border-left-color: #ff4757; }
        .finding.high { border-left-color: #ff6b6b; }
        .finding.medium { border-left-color: #ffd43b; }
        .finding.low { border-left-color: #69db7c; }
        .finding.pass { border-left-color: #69db7c; background: #1e3a2f; }
        .finding-header { display: flex; justify-content: space-between; margin-bottom: 10px; }
        .finding-title { font-weight: 600; }
        .severity { padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 600; }
        .severity.critical { background: #ff4757; }
        .severity.high { background: #ff6b6b; }
        .severity.medium { background: #ffd43b; color: #000; }
        .severity.low { background: #69db7c; color: #000; }
        .severity.pass { background: #69db7c; color: #000; }
        .finding-description { color: #aaa; margin-bottom: 10px; }
        .finding-recommendation { background: #2d2d44; padding: 10px; border-radius: 4px; font-size: 0.9em; }
        .finding-recommendation strong { color: #69db7c; }
        code { background: #3d3d54; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
        footer { text-align: center; margin-top: 30px; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 HeadScan Security Report</h1>

        <div class="summary">
            <div class="summary-card">
                <div class="value">{{ report.targets_scanned }}</div>
                <div class="label">Targets Scanned</div>
            </div>
            <div class="summary-card">
                <div class="value">{{ "%.1f"|format(report.average_score) }}</div>
                <div class="label">Average Score</div>
            </div>
            <div class="summary-card">
                <div class="value">{{ total_findings }}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="summary-card">
                <div class="value">{{ "%.2f"|format(report.scan_duration_ms / 1000) }}s</div>
                <div class="label">Scan Duration</div>
            </div>
        </div>

        {% for result in report.results %}
        <div class="target">
            <div class="target-header">
                <div class="target-url">{{ result.url }}</div>
                <div class="score {% if result.score >= 80 %}good{% elif result.score >= 50 %}medium{% else %}poor{% endif %}">
                    {{ result.score }}/100 ({{ result.grade }})
                </div>
            </div>

            {% if result.error %}
            <div class="finding critical">
                <div class="finding-title">Error: {{ result.error }}</div>
            </div>
            {% else %}
            {% for finding in result.findings %}
            <div class="finding {{ finding.severity.value|lower }}">
                <div class="finding-header">
                    <span class="finding-title">{{ finding.title }}</span>
                    <span class="severity {{ finding.severity.value|lower }}">{{ finding.severity.value }}</span>
                </div>
                {% if finding.severity.value != 'PASS' %}
                <div class="finding-description">{{ finding.description }}</div>
                {% if finding.current_value %}
                <div><strong>Current:</strong> <code>{{ finding.current_value[:80] }}{% if finding.current_value|length > 80 %}...{% endif %}</code></div>
                {% endif %}
                <div class="finding-recommendation">
                    <strong>Recommendation:</strong> {{ finding.recommendation }}<br>
                    <strong>Example:</strong> <code>{{ finding.example_value }}</code>
                </div>
                {% endif %}
            </div>
            {% endfor %}
            {% endif %}
        </div>
        {% endfor %}

        <footer>
            Generated by HeadScan | {{ report.scan_start }}
        </footer>
    </div>
</body>
</html>
"""


class HTMLReporter(BaseReporter):
    """HTML report generator."""

    def generate(self, report: ScanReport) -> str:
        """Generate HTML report."""
        template = Template(HTML_TEMPLATE)

        # Calculate total findings
        total_findings = sum(
            len([f for f in r.findings if f.severity.value not in ('PASS', 'INFO')])
            for r in report.results
        )

        return template.render(
            report=report,
            total_findings=total_findings
        )

