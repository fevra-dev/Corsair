"""
SARIF Reporter for GitHub Code Scanning Integration.

Generates SARIF 2.1.0 compatible output that can be uploaded
to GitHub via the github/codeql-action/upload-sarif action.

SARIF (Static Analysis Results Interchange Format) is an OASIS
standard for representing static analysis results.
"""

import json
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime

from .base import BaseReporter
from ..models import ScanReport, TargetResult, Finding, Severity
from ..utils.logger import get_logger

logger = get_logger(__name__)


class SARIFReporter(BaseReporter):
    """
    Generate SARIF 2.1.0 output for GitHub Code Scanning.

    Usage:
        reporter = SARIFReporter()
        sarif_json = reporter.generate(scan_report)

        # Save and upload to GitHub
        with open("results.sarif", "w") as f:
            f.write(sarif_json)

    GitHub Actions integration:
        - name: Upload SARIF
          uses: github/codeql-action/upload-sarif@v3
          with:
            sarif_file: results.sarif
            category: corsair
    """

    SARIF_VERSION = "2.1.0"
    SCHEMA_URL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    # Map Severity to SARIF level
    SEVERITY_TO_LEVEL = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
        Severity.PASS: "none",
    }

    # SARIF rule ID prefix
    RULE_PREFIX = "HG"

    def __init__(
        self,
        tool_name: str = "Corsair",
        tool_version: str = "0.1.0",
        tool_uri: str = "https://github.com/fevra-dev/Corsair",
        quiet: bool = False,
        verbose: bool = False,
        no_color: bool = False,
    ):
        """
        Initialize SARIF reporter.

        Args:
            tool_name: Name of the tool
            tool_version: Version of the tool
            tool_uri: URL to tool repository/documentation
            quiet: Minimize output
            verbose: Detailed output
            no_color: Disable color output (not applicable for SARIF)
        """
        super().__init__(quiet=quiet, verbose=verbose, no_color=no_color)

        self.tool_name = tool_name
        self.tool_version = tool_version
        self.tool_uri = tool_uri

        # Rule tracking
        self._rule_index: Dict[str, int] = {}
        self._rules: List[Dict] = []

        logger.info("[SARIF] Reporter initialized")

    def generate(self, report: ScanReport) -> str:
        """
        Generate SARIF JSON from scan report.

        Args:
            report: Complete scan report

        Returns:
            SARIF JSON string
        """
        logger.info(f"[SARIF] Generating report for {report.targets_scanned} targets")

        # Reset rule tracking for new report
        self._rule_index = {}
        self._rules = []

        # Build rules from all findings
        self._build_rules(report)

        # Build results
        results = self._build_results(report)

        # Construct SARIF document
        sarif = {
            "$schema": self.SCHEMA_URL,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": self.tool_uri,
                            "rules": self._rules,
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": report.scan_start,
                            "endTimeUtc": report.scan_end,
                        }
                    ],
                }
            ],
        }

        # Add taxonomies for OWASP correlation
        sarif["runs"][0]["taxonomies"] = self._build_taxonomies()

        logger.info(f"[SARIF] Generated {len(results)} results with {len(self._rules)} rules")

        return json.dumps(sarif, indent=2)

    def _build_rules(self, report: ScanReport) -> None:
        """Build unique rules from all findings."""
        rule_counter = 1

        for target in report.results:
            for finding in target.findings:
                # Skip PASS findings
                if finding.severity == Severity.PASS:
                    continue

                rule_key = self._get_rule_key(finding)

                if rule_key not in self._rule_index:
                    rule_id = f"{self.RULE_PREFIX}{rule_counter:03d}"
                    self._rule_index[rule_key] = len(self._rules)

                    rule = {
                        "id": rule_id,
                        "name": self._sanitize_name(finding.title),
                        "shortDescription": {"text": finding.title},
                        "fullDescription": {"text": finding.description},
                        "defaultConfiguration": {"level": self.SEVERITY_TO_LEVEL[finding.severity]},
                        "properties": {
                            "tags": self._get_tags(finding),
                            "precision": "high",
                            "security-severity": self._get_security_severity(finding.severity),
                        },
                    }

                    # Add help URI if available
                    if finding.reference_url:
                        rule["helpUri"] = finding.reference_url

                    # Add relationships to taxonomies (OWASP)
                    relationships = self._get_taxonomy_relationships(finding)
                    if relationships:
                        rule["relationships"] = relationships

                    self._rules.append(rule)
                    rule_counter += 1

    def _build_results(self, report: ScanReport) -> List[Dict]:
        """Build SARIF results from findings."""
        results = []

        for target in report.results:
            for finding in target.findings:
                # Skip PASS findings
                if finding.severity == Severity.PASS:
                    continue

                rule_key = self._get_rule_key(finding)
                rule_idx = self._rule_index[rule_key]
                rule_id = self._rules[rule_idx]["id"]

                result = {
                    "ruleId": rule_id,
                    "ruleIndex": rule_idx,
                    "level": self.SEVERITY_TO_LEVEL[finding.severity],
                    "message": {"text": self._format_message(finding, target.url)},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": target.url, "uriBaseId": "WEBROOT"}
                            },
                            "logicalLocations": [{"name": finding.header, "kind": "httpHeader"}],
                        }
                    ],
                    "partialFingerprints": {
                        "primaryLocationLineHash": self._generate_fingerprint(
                            target.url, finding.header, finding.title
                        )
                    },
                }

                # Add fix suggestions if available
                if finding.recommendation:
                    result["fixes"] = [{"description": {"text": finding.recommendation}}]

                # Add CVE references if present
                if finding.cve_correlations:
                    result["relatedLocations"] = []
                    for cve in finding.cve_correlations:
                        result["relatedLocations"].append(
                            {
                                "message": {
                                    "text": f"Related: {cve.cve_id}"
                                    + (" (CISA KEV)" if cve.in_cisa_kev else "")
                                },
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}"
                                    }
                                },
                            }
                        )

                results.append(result)

        return results

    def _build_taxonomies(self) -> List[Dict]:
        """Build taxonomies for OWASP correlation."""
        return [
            {
                "name": "OWASP",
                "version": "2025",
                "informationUri": "https://owasp.org/www-project-top-ten/",
                "isComprehensive": False,
                "taxa": [
                    {
                        "id": "A02",
                        "name": "Security Misconfiguration",
                        "shortDescription": {
                            "text": "Security misconfiguration including missing headers"
                        },
                    },
                    {
                        "id": "A03",
                        "name": "Injection",
                        "shortDescription": {"text": "Injection vulnerabilities including XSS"},
                    },
                ],
            }
        ]

    def _get_taxonomy_relationships(self, finding: Finding) -> List[Dict]:
        """Get taxonomy relationships for a finding."""
        relationships = []

        for mapping in finding.compliance_mappings:
            if "OWASP" in mapping.framework:
                relationships.append(
                    {
                        "target": {
                            "id": mapping.requirement_id,
                            "toolComponent": {"name": "OWASP"},
                        },
                        "kinds": ["relevant"],
                    }
                )

        return relationships

    def _get_rule_key(self, finding: Finding) -> str:
        """Generate unique key for a rule."""
        return f"{finding.header}:{finding.title}"

    def _sanitize_name(self, name: str) -> str:
        """Sanitize rule name for SARIF (alphanumeric only)."""
        # Remove spaces and special characters
        sanitized = "".join(c for c in name if c.isalnum())
        return sanitized[:64]  # Max 64 chars

    def _get_tags(self, finding: Finding) -> List[str]:
        """Get tags for a finding."""
        tags = ["security", f"header/{finding.header.lower().replace('-', '_')}"]

        # Add severity tag
        tags.append(f"severity/{finding.severity.value.lower()}")

        # Add category tag
        tags.append(f"category/{finding.category.value}")

        # Add OWASP tags from compliance mappings
        for mapping in finding.compliance_mappings:
            if "OWASP" in mapping.framework:
                tags.append(f"owasp/{mapping.requirement_id.lower()}")

        # Add CVE/KEV tags
        for cve in finding.cve_correlations:
            if cve.in_cisa_kev:
                tags.append("cisa-kev")
                break

        return list(set(tags))  # Deduplicate

    def _get_security_severity(self, severity: Severity) -> str:
        """Get SARIF security-severity score (0.0-10.0)."""
        scores = {
            Severity.CRITICAL: "9.0",
            Severity.HIGH: "7.0",
            Severity.MEDIUM: "5.0",
            Severity.LOW: "3.0",
            Severity.INFO: "1.0",
            Severity.PASS: "0.0",
        }
        return scores.get(severity, "1.0")

    def _format_message(self, finding: Finding, url: str) -> str:
        """Format finding as SARIF message."""
        parts = [f"{finding.title} on {url}"]

        if finding.current_value:
            parts.append(f"\n\nCurrent value: {finding.current_value}")

        parts.append(f"\n\nRecommendation: {finding.recommendation}")

        if finding.example_value:
            parts.append(f"\n\nExample: {finding.example_value}")

        # Add CVE info
        kev_cves = [c for c in finding.cve_correlations if c.in_cisa_kev]
        if kev_cves:
            cve_list = ", ".join(c.cve_id for c in kev_cves)
            parts.append(f"\n\nCISA KEV: {cve_list}")

        return "".join(parts)

    def _generate_fingerprint(self, url: str, header: str, title: str) -> str:
        """
        Generate stable fingerprint for deduplication.

        The fingerprint ensures the same issue on the same URL
        is recognized across multiple scans.
        """
        content = f"{url}:{header}:{title}"
        return hashlib.sha256(content.encode()).hexdigest()[:32]
