"""
HTTP header scanner.

Fetches headers from targets and runs all analyzers.
"""

import httpx
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import logging

from .models import TargetResult, ScanReport, Finding, Severity
from .analyzers import ALL_ANALYZERS
from .scoring import calculate_score, calculate_grade
from .tls import tls_available
from .tls.auditor import TLSAuditor
from .tls.findings import get_finding as get_tls_finding
from .cache.auditor import CacheAuditor
from .cors.auditor import CORSAuditor
from .fetch_metadata import FetchMetadataAuditor

logger = logging.getLogger(__name__)


class HeadScanner:
    """HTTP security header scanner."""

    def __init__(
        self,
        timeout: int = 10,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        user_agent: str = "HeadScan/1.0 (Security Header Analyzer)",
        cache_probe: bool = True,
        cors_probe: bool = True,
        cors_evil_origin: str = "https://evil.example",
        fm_probe: bool = True,
        ip_probe: bool = True,
    ):
        """
        Initialize scanner.

        Args:
            timeout: Request timeout in seconds
            follow_redirects: Whether to follow redirects
            max_redirects: Maximum redirects to follow
            user_agent: User-Agent header value
            cache_probe: Whether to run active cache poisoning probes
            cors_probe: Whether to run active CORS reflection probes
            cors_evil_origin: Origin value used by the attacker-origin probe
            fm_probe: Whether to run Fetch Metadata enforcement probing
            ip_probe: Whether to run Integrity-Policy active body fetch
        """
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self.cache_probe = cache_probe
        self.cors_probe = cors_probe
        self.cors_evil_origin = cors_evil_origin
        self.fm_probe = fm_probe
        self.ip_probe = ip_probe

        logger.info(
            f"Scanner initialized: timeout={timeout}s, " f"follow_redirects={follow_redirects}"
        )

    def _fetch_headers(self, url: str) -> Tuple[int, Dict[str, str], str, Optional[str]]:
        """
        Fetch headers from URL.

        Returns:
            Tuple of (status_code, headers_dict, final_url, error_or_none)
        """
        headers = {"User-Agent": self.user_agent, "Accept": "*/*"}

        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=self.follow_redirects,
                max_redirects=self.max_redirects,
                verify=True,
            ) as client:
                # Try HEAD first
                try:
                    response = client.head(url, headers=headers)
                except Exception:
                    # Fallback to GET
                    response = client.get(url, headers=headers)

                return (response.status_code, dict(response.headers), str(response.url), None)

        except httpx.TimeoutException:
            return (0, {}, url, "Request timeout")
        except httpx.ConnectError as e:
            return (0, {}, url, f"Connection error: {e}")
        except httpx.TooManyRedirects:
            return (0, {}, url, "Too many redirects")
        except Exception as e:
            return (0, {}, url, f"Error: {e}")

    def _analyze_headers(self, headers: Dict[str, str], url: str) -> List[Finding]:
        """Run all analyzers on headers."""
        findings = []

        for analyzer_class in ALL_ANALYZERS:
            logger.debug(f"Running {analyzer_class.__name__}")

            try:
                analyzer = analyzer_class(headers, url)
                analyzer_findings = analyzer.analyze()
                findings.extend(analyzer_findings)
            except Exception as e:
                logger.error(f"Analyzer {analyzer_class.__name__} failed: {e}")

        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
            Severity.PASS: 5,
        }
        findings.sort(key=lambda f: severity_order.get(f.severity, 99))

        return findings

    def scan_target(self, url: str) -> TargetResult:
        """
        Scan a single target.

        Args:
            url: Target URL

        Returns:
            TargetResult with findings
        """
        start_time = datetime.now()
        logger.info(f"Scanning: {url}")

        # Normalize URL
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        # Fetch headers
        status_code, headers, final_url, error = self._fetch_headers(url)

        if error:
            logger.error(f"Failed to scan {url}: {error}")
            duration = int((datetime.now() - start_time).total_seconds() * 1000)
            return TargetResult(
                url=url,
                final_url=final_url,
                status_code=status_code,
                headers={},
                findings=[],
                score=0,
                grade="F",
                scan_time_ms=duration,
                error=error,
            )

        logger.info(f"Got response: {status_code} from {final_url}")
        logger.debug(f"Headers: {list(headers.keys())}")

        # Analyze headers
        findings = self._analyze_headers(headers, final_url)

        # TLS audit (auto-detect HTTPS)
        if final_url.startswith("https://") and tls_available():
            try:
                tls_auditor = TLSAuditor(timeout=self.timeout)
                tls_findings = tls_auditor.audit(final_url)
                findings.extend(tls_findings)
            except Exception as e:
                logger.error(f"TLS audit failed: {e}")
        elif final_url.startswith("http://") and not final_url.startswith("https://"):
            tls_missing = get_tls_finding("TLS_MISSING")
            if tls_missing:
                findings.append(tls_missing)

        # Cache poisoning audit
        try:
            cache_auditor = CacheAuditor(timeout=self.timeout, active=self.cache_probe)
            cache_findings = cache_auditor.audit(final_url, headers)
            findings.extend(cache_findings)
        except Exception as e:
            logger.error(f"Cache audit failed: {e}")

        # CORS DAST audit — supersedes the legacy passive CORSAnalyzer, so
        # drop its output before the auditor appends fresh CORS findings.
        findings = [f for f in findings if f.category.value != "cors"]
        try:
            cors_auditor = CORSAuditor(
                timeout=self.timeout,
                active=self.cors_probe,
                evil_origin=self.cors_evil_origin,
            )
            cors_findings = cors_auditor.audit(final_url, headers)
            findings.extend(cors_findings)
        except Exception as e:
            logger.error(f"CORS audit failed: {e}")

        # Fetch Metadata enforcement probe
        try:
            fm_auditor = FetchMetadataAuditor(timeout=self.timeout, active=self.fm_probe)
            fm_findings = fm_auditor.audit(final_url, headers)
            findings.extend(fm_findings)
        except Exception as e:
            logger.error(f"Fetch Metadata audit failed: {e}")

        # Integrity-Policy validation
        try:
            from .integrity_policy import IntegrityPolicyAuditor
            ip_auditor = IntegrityPolicyAuditor(
                timeout=self.timeout,
                active=self.ip_probe,
                user_agent=self.user_agent,
            )
            ip_findings = ip_auditor.audit(final_url, headers)
            findings.extend(ip_findings)
        except Exception as e:
            logger.error(f"Integrity-Policy audit failed: {e}")

        # Calculate score
        score = calculate_score(findings)
        grade = calculate_grade(score)

        duration = int((datetime.now() - start_time).total_seconds() * 1000)

        logger.info(
            f"Scan complete: {url} - Score: {score}/100 ({grade}) - "
            f"{len([f for f in findings if f.severity not in (Severity.PASS, Severity.INFO)])} issues"
        )

        return TargetResult(
            url=url,
            final_url=final_url,
            status_code=status_code,
            headers=headers,
            findings=findings,
            score=score,
            grade=grade,
            scan_time_ms=duration,
        )

    def scan(self, targets: List[str]) -> ScanReport:
        """
        Scan multiple targets.

        Args:
            targets: List of target URLs

        Returns:
            Complete ScanReport
        """
        start_time = datetime.now()
        logger.info(f"Starting scan of {len(targets)} targets")

        # Deduplicate and normalize
        normalized = []
        for target in targets:
            if not target.startswith(("http://", "https://")):
                target = f"https://{target}"
            normalized.append(target)
        targets = list(dict.fromkeys(normalized))

        # Scan each target
        results = []
        for target in targets:
            result = self.scan_target(target)
            results.append(result)

        # Calculate averages
        end_time = datetime.now()
        duration = int((end_time - start_time).total_seconds() * 1000)

        valid_scores = [r.score for r in results if not r.error]
        avg_score = sum(valid_scores) / len(valid_scores) if valid_scores else 0

        report = ScanReport(
            targets_scanned=len(targets),
            average_score=round(avg_score, 1),
            scan_start=start_time.isoformat(),
            scan_end=end_time.isoformat(),
            scan_duration_ms=duration,
            results=results,
        )

        logger.info(f"Scan complete: {len(targets)} targets, " f"average score: {avg_score:.1f}")

        return report
