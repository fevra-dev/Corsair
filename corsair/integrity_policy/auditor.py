"""IntegrityPolicyAuditor — two-stage Integrity-Policy validation.

Stage 1 (static, always runs): parse Integrity-Policy and Integrity-Policy-
Report-Only headers and emit IP-001/002/003/004 or static PASS.

Stage 2 (active, gated): when active=True AND enforcing IP detected AND
'script' in blocked-destinations AND HTML Content-Type, GET the document
body and check cross-origin <script> tags for integrity attributes.
Emits IP-006, IP-006 PASS, or IP-006 INCONCLUSIVE.
"""

import logging
from typing import Dict, List, Mapping, Optional, Tuple

from ..models import Finding
from .body import ONE_MEGABYTE, _extract_cross_origin_scripts, _fetch_body
from .findings import (
    build_ip_003_finding,
    build_ip_006_finding,
    build_ip_006_inconclusive_finding,
    build_ip_006_pass_finding,
    build_ip_static_pass_finding,
    get_finding,
)
from .parser import _is_html_response, _parse_integrity_policy


logger = logging.getLogger(__name__)


_RECOGNIZED_DESTINATIONS = frozenset({"script", "style"})


class IntegrityPolicyAuditor:
    def __init__(
        self,
        timeout: int = 10,
        active: bool = True,
        user_agent: str = "HeadScan/1.0 (Security Header Analyzer)",
    ):
        self.timeout = timeout
        self.active = active
        self.user_agent = user_agent

    def audit(self, url: str, headers: Mapping[str, str]) -> List[Finding]:
        try:
            return self._audit_inner(url, headers)
        except Exception as e:
            logger.error(f"Integrity-Policy audit failed for {url}: {e}")
            # Surface the gap rather than swallow it.
            inconclusive = build_ip_006_inconclusive_finding(
                f"Auditor exception: {type(e).__name__}: {e}"
            )
            inconclusive.title = "Integrity-Policy analysis failed"
            return [inconclusive]

    def _audit_inner(
        self, url: str, headers: Mapping[str, str]
    ) -> List[Finding]:
        ip_value = self._get_header(headers, "integrity-policy")
        ip_ro_value = self._get_header(headers, "integrity-policy-report-only")
        static_findings, parsed = self._static_audit(ip_value, ip_ro_value)
        findings: List[Finding] = list(static_findings)

        # Stage 2 gate: must be active AND parse succeeded AND script blocked
        # AND HTML response.
        if not self.active:
            return findings
        if parsed is None or parsed.get("parse_error"):
            return findings
        if "script" not in parsed.get("blocked_destinations", []):
            return findings
        if not _is_html_response(dict(headers)):
            return findings

        # Stage 2: body fetch + IP-006 dispatch
        body, error = _fetch_body(url, self.timeout, self.user_agent)
        if error is not None:
            findings.append(build_ip_006_inconclusive_finding(error))
            return findings
        truncated = len(body) >= ONE_MEGABYTE
        scripts = _extract_cross_origin_scripts(body, url)
        if scripts:
            findings.append(build_ip_006_finding(scripts, truncated))
        else:
            findings.append(build_ip_006_pass_finding(truncated))
        return findings

    @staticmethod
    def _get_header(headers: Mapping[str, str], name: str) -> Optional[str]:
        for k, v in headers.items():
            if k.lower() == name:
                return v
        return None

    def _static_audit(
        self, ip_value: Optional[str], ip_ro_value: Optional[str]
    ) -> Tuple[List[Finding], Optional[Dict]]:
        # Both headers absent -> IP-001
        if not ip_value and not ip_ro_value:
            return ([get_finding("IP-001")], None)
        # IP absent, IP-RO present -> IP-002
        if not ip_value and ip_ro_value:
            return ([get_finding("IP-002")], None)
        # IP present (with or without IP-RO): parse and dispatch
        parsed = _parse_integrity_policy(ip_value or "")
        if parsed["parse_error"]:
            return ([build_ip_003_finding(ip_value or "")], parsed)
        recognized = [
            t for t in parsed["blocked_destinations"]
            if t in _RECOGNIZED_DESTINATIONS
        ]
        if not recognized:
            return ([build_ip_003_finding(ip_value or "")], parsed)
        if "script" not in parsed["blocked_destinations"]:
            return ([get_finding("IP-004")], parsed)
        # Healthy static config
        return ([build_ip_static_pass_finding()], parsed)
