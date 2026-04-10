"""
TLS Auditor — orchestrates sslyze scanning for Corsair.

Main entry point: TLSAuditor.audit(url) -> list[Finding]
Called by HeadScanner.scan_target() for HTTPS targets.
"""

import logging
from typing import List, Tuple
from urllib.parse import urlparse

from ..models import Finding
from .findings import get_finding
from .analyzers import analyze_scan_result

logger = logging.getLogger(__name__)


class TLSAuditor:
    """TLS/SSL configuration auditor using sslyze."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def audit(self, url: str) -> List[Finding]:
        """
        Audit TLS configuration for a URL.

        Args:
            url: HTTPS URL to audit

        Returns:
            List of Finding objects for detected TLS issues
        """
        hostname, port = self._parse_target(url)
        logger.info(f"TLS audit: {hostname}:{port}")

        try:
            scan_result = self._run_scan(hostname, port)
            findings = analyze_scan_result(scan_result)
            logger.info(f"TLS audit complete: {len(findings)} findings")
            return findings
        except ConnectionError as e:
            logger.warning(f"TLS connection failed for {hostname}:{port}: {e}")
            finding = get_finding("TLS_CONNECT_FAILED")
            if finding:
                finding.current_value = str(e)
                return [finding]
            return []
        except Exception as e:
            logger.error(f"TLS audit error for {hostname}:{port}: {e}")
            finding = get_finding("TLS_CONNECT_FAILED")
            if finding:
                finding.current_value = f"Scan error: {e}"
                return [finding]
            return []

    def _parse_target(self, url: str) -> Tuple[str, int]:
        """Extract hostname and port from URL. Handles IPv6."""
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc
        port = parsed.port or 443
        return hostname, port

    def _run_scan(self, hostname: str, port: int):
        """Execute sslyze scan with all relevant ScanCommands."""
        from sslyze import (
            Scanner,
            ServerScanRequest,
            ServerNetworkLocation,
            ScanCommand,
        )

        location = ServerNetworkLocation(hostname=hostname, port=port)
        scan_request = ServerScanRequest(
            server_location=location,
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
                ScanCommand.TLS_COMPRESSION,
                ScanCommand.OPENSSL_CCS_INJECTION,
                ScanCommand.TLS_FALLBACK_SCSV,
            },
        )

        scanner = Scanner()
        scanner.queue_scans([scan_request])

        for result in scanner.get_results():
            if result.scan_result:
                return result
            # If scan had errors, raise ConnectionError
            errors = []
            for cmd, error in (result.scan_commands_errors or {}).items():
                errors.append(f"{cmd.name}: {error.reason}")
            if errors:
                raise ConnectionError("; ".join(errors))

        raise ConnectionError("No scan results returned")
