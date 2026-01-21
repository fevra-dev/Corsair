"""
CVE Correlator.

Maps security header misconfigurations to related CVEs
and provides threat intelligence context.

Integrates with CISA KEV for known exploited vulnerabilities.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass

from ..models import Finding, CVECorrelation, Severity
from ..utils.logger import get_logger
from .cisa_kev import CISAKEVClient

logger = get_logger(__name__)


# CVE/CWE mappings for header misconfigurations
# Format: { "issue_type": ["CVE-xxx", "CWE-xxx", ...] }
HEADER_CVE_MAPPINGS: Dict[str, Dict[str, List[str]]] = {
    "Content-Security-Policy": {
        "missing": ["CWE-79", "CVE-2025-55182"],  # XSS, React2Shell
        "unsafe-inline": ["CWE-79"],
        "unsafe-eval": ["CWE-94"],  # Code Injection
        "wildcard": ["CWE-79"],
    },
    "Strict-Transport-Security": {
        "missing": ["CWE-311", "CWE-319"],  # Missing Encryption, Cleartext Transmission
        "short-max-age": ["CWE-311"],
    },
    "X-Frame-Options": {
        "missing": ["CWE-1021"],  # Clickjacking
    },
    "Cross-Origin-Opener-Policy": {
        "missing": ["CWE-200", "CWE-203"],  # Info Disclosure, Observable Timing
    },
    "Referrer-Policy": {
        "missing": ["CWE-200"],  # Information Exposure
        "unsafe-url": ["CWE-200"],
    },
    "X-Content-Type-Options": {
        "missing": ["CWE-79"],  # MIME Sniffing can lead to XSS
    },
}

# CWE descriptions
CWE_DESCRIPTIONS: Dict[str, str] = {
    "CWE-79": "Improper Neutralization of Input During Web Page Generation (XSS)",
    "CWE-94": "Improper Control of Generation of Code (Code Injection)",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-203": "Observable Discrepancy (Timing Side-Channel)",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames (Clickjacking)",
}


class CVECorrelator:
    """
    Correlates header misconfigurations with CVEs and threat intelligence.

    Usage:
        correlator = CVECorrelator()
        await correlator.initialize()

        enriched_finding = await correlator.enrich_finding(finding)
    """

    def __init__(self, kev_client: Optional[CISAKEVClient] = None):
        """
        Initialize CVE correlator.

        Args:
            kev_client: Optional CISA KEV client (creates one if not provided)
        """
        self.kev_client = kev_client or CISAKEVClient()
        self._initialized = False

        logger.info("[CVECorrelator] Initialized")

    async def initialize(self) -> None:
        """Initialize the correlator by fetching KEV data."""
        if self._initialized:
            return

        try:
            await self.kev_client.fetch_catalog()
            self._initialized = True
            logger.info(f"[CVECorrelator] Loaded {self.kev_client.catalog_size} KEV entries")
        except Exception as e:
            logger.warning(f"[CVECorrelator] Failed to initialize KEV: {e}")

    def initialize_sync(self) -> None:
        """Initialize the correlator synchronously."""
        if self._initialized:
            return

        try:
            self.kev_client.fetch_catalog_sync()
            self._initialized = True
            logger.info(f"[CVECorrelator] Loaded {self.kev_client.catalog_size} KEV entries")
        except Exception as e:
            logger.warning(f"[CVECorrelator] Failed to initialize KEV: {e}")

    def get_cves_for_finding(self, finding: Finding) -> List[str]:
        """
        Get related CVE/CWE IDs for a finding.

        Args:
            finding: Security finding to correlate

        Returns:
            List of CVE/CWE identifiers
        """
        header = finding.header
        title = finding.title.lower()

        # Get mappings for this header
        header_mappings = HEADER_CVE_MAPPINGS.get(header, {})

        # Find matching issue type
        cves = []
        for issue_type, cve_list in header_mappings.items():
            if issue_type.lower() in title:
                cves.extend(cve_list)

        # Always include "missing" mappings for missing headers
        if "missing" in title or "not set" in title:
            cves.extend(header_mappings.get("missing", []))

        # Deduplicate
        return list(set(cves))

    async def enrich_finding(self, finding: Finding) -> Finding:
        """
        Enrich a finding with CVE correlation data.

        Args:
            finding: Finding to enrich

        Returns:
            Finding with populated cve_correlations
        """
        if not self._initialized:
            await self.initialize()

        # Get CVE/CWE IDs
        cve_ids = self.get_cves_for_finding(finding)

        # Also include any existing CVE correlations
        existing_cves = {c.cve_id for c in finding.cve_correlations}
        cve_ids.extend(existing_cves)
        cve_ids = list(set(cve_ids))

        if not cve_ids:
            return finding

        # Build enriched correlations
        correlations = []
        for cve_id in cve_ids:
            correlation = await self._build_correlation(cve_id)
            if correlation:
                correlations.append(correlation)

        # Update finding
        finding.cve_correlations = correlations

        logger.debug(f"[CVECorrelator] Enriched {finding.header} with {len(correlations)} CVEs")

        return finding

    def enrich_finding_sync(self, finding: Finding) -> Finding:
        """Enrich a finding synchronously."""
        if not self._initialized:
            self.initialize_sync()

        cve_ids = self.get_cves_for_finding(finding)
        existing_cves = {c.cve_id for c in finding.cve_correlations}
        cve_ids.extend(existing_cves)
        cve_ids = list(set(cve_ids))

        if not cve_ids:
            return finding

        correlations = []
        for cve_id in cve_ids:
            correlation = self._build_correlation_sync(cve_id)
            if correlation:
                correlations.append(correlation)

        finding.cve_correlations = correlations

        return finding

    async def _build_correlation(self, cve_id: str) -> Optional[CVECorrelation]:
        """Build a CVECorrelation object for a CVE/CWE ID."""
        # Handle CWE IDs
        if cve_id.startswith("CWE-"):
            return CVECorrelation(
                cve_id=cve_id,
                cvss_score=0.0,
                description=CWE_DESCRIPTIONS.get(cve_id, ""),
                in_cisa_kev=False,
                ransomware_associated=False,
                mitigation="",
            )

        # Handle CVE IDs - check KEV
        kev_entry = await self.kev_client.get_entry(cve_id)

        if kev_entry:
            return CVECorrelation(
                cve_id=cve_id,
                cvss_score=0.0,  # Could fetch from NVD
                description=kev_entry.description,
                in_cisa_kev=True,
                ransomware_associated=kev_entry.is_ransomware_associated,
                mitigation=kev_entry.required_action,
            )
        else:
            return CVECorrelation(
                cve_id=cve_id,
                cvss_score=0.0,
                description="",
                in_cisa_kev=False,
                ransomware_associated=False,
                mitigation="",
            )

    def _build_correlation_sync(self, cve_id: str) -> Optional[CVECorrelation]:
        """Build a CVECorrelation object synchronously."""
        if cve_id.startswith("CWE-"):
            return CVECorrelation(
                cve_id=cve_id,
                cvss_score=0.0,
                description=CWE_DESCRIPTIONS.get(cve_id, ""),
                in_cisa_kev=False,
                ransomware_associated=False,
                mitigation="",
            )

        kev_entry = self.kev_client.get_entry_sync(cve_id)

        if kev_entry:
            return CVECorrelation(
                cve_id=cve_id,
                cvss_score=0.0,
                description=kev_entry.description,
                in_cisa_kev=True,
                ransomware_associated=kev_entry.is_ransomware_associated,
                mitigation=kev_entry.required_action,
            )
        else:
            return CVECorrelation(
                cve_id=cve_id,
                cvss_score=0.0,
                description="",
                in_cisa_kev=False,
                ransomware_associated=False,
                mitigation="",
            )

    async def enrich_all_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Enrich multiple findings with CVE data.

        Args:
            findings: List of findings to enrich

        Returns:
            List of enriched findings
        """
        if not self._initialized:
            await self.initialize()

        enriched = []
        for finding in findings:
            enriched_finding = await self.enrich_finding(finding)
            enriched.append(enriched_finding)

        return enriched

    def enrich_all_findings_sync(self, findings: List[Finding]) -> List[Finding]:
        """Enrich multiple findings synchronously."""
        if not self._initialized:
            self.initialize_sync()

        return [self.enrich_finding_sync(f) for f in findings]
