"""H3Auditor — orchestrates Alt-Svc derivation, LSQUIC fingerprint,
QUIC probe, 0-RTT classification, and H1/H3 header diff into a single
audit() method.

Tests must mock scan_h3 at corsair.h3.auditor.scan_h3 (this module's
bound name), NOT corsair.h3.client.scan_h3 — the auditor imports the
function into its own namespace at import time. This is the v0.5.5
integrity-policy lesson preserved here.
"""

import asyncio
import logging
from typing import List, Mapping, Optional
from urllib.parse import urlparse

from ..models import Finding
from .diff import diff_security_headers
from .findings import (
    build_h3_001_high,
    build_h3_001_low,
    build_h3_001_pass,
    build_h3_002_finding,
    build_h3_002_pass,
    build_h3_003_finding,
    build_h3_inconclusive_finding,
    build_h3_extras_missing_finding,
)
from .probe import derive_h3_target, is_lsquic_fingerprint

# Imported via the package __init__ availability flag. When [h3] extra is
# absent, H3_AVAILABLE is False and scan_h3 is None (we never call it).
try:
    from .client import scan_h3  # noqa: F401
    H3_AVAILABLE = True
except ImportError:
    H3_AVAILABLE = False
    scan_h3 = None  # type: ignore

logger = logging.getLogger(__name__)


class H3Auditor:
    """Two-stage H3 validation orchestrator."""

    def __init__(
        self,
        timeout: int = 10,
        active: bool = True,
        user_agent: str = "Corsair/0.6.0 (HTTP Security Scanner)",
    ):
        self.timeout = timeout
        self.active = active
        self.user_agent = user_agent

    def audit(self, url: str, h1_headers: Mapping[str, str]) -> List[Finding]:
        try:
            return self._audit_inner(url, h1_headers)
        except Exception as e:
            logger.exception("H3 audit unexpectedly failed")
            return [build_h3_inconclusive_finding(error=f"audit error: {type(e).__name__}: {e}")]

    def _audit_inner(self, url: str, h1_headers: Mapping[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Gate checks
        if not self.active:
            return []
        if not url.lower().startswith("https://"):
            return []

        # 2. Trigger derivation
        parsed = urlparse(url)
        target = derive_h3_target(h1_headers, parsed.hostname or "")
        if target is None:
            return []
        host, port = target

        # 3. Extras gate (must be after Alt-Svc check so we don't spam INFO
        # findings on every site that doesn't ship h3)
        if not H3_AVAILABLE:
            return [build_h3_extras_missing_finding()]

        # 4. LSQUIC passive fingerprint — fires before the probe
        if is_lsquic_fingerprint(h1_headers, has_h3_advertisement=True):
            findings.append(build_h3_003_finding())

        # 5. H3 probe (async → sync bridge)
        target_url = f"https://{host}:{port}{parsed.path or '/'}"
        try:
            result = asyncio.run(scan_h3(
                url=target_url,
                timeout=float(self.timeout),
                user_agent=self.user_agent,
            ))
        except Exception as e:
            findings.append(build_h3_inconclusive_finding(
                error=f"asyncio.run error: {type(e).__name__}: {e}"
            ))
            return findings

        # 6. Probe error → INCONCLUSIVE (LSQUIC finding from step 4 stays)
        if result.error is not None:
            findings.append(build_h3_inconclusive_finding(error=result.error))
            return findings

        # 7. 0-RTT evaluation
        capability = result.early_data_capability > 0
        hint_rejected = (result.status == 425)
        if capability and not hint_rejected:
            findings.append(build_h3_001_high(
                early_data_capability=result.early_data_capability,
                status=result.status or 0,
            ))
        elif capability and hint_rejected:
            findings.append(build_h3_001_pass(early_data_capability=result.early_data_capability))
        elif (not capability) and (not hint_rejected):
            findings.append(build_h3_001_low(status=result.status or 0))
        # else: silent baseline — no emit

        # 8. H1/H3 security-header diff
        diff = diff_security_headers(h1_headers, result.headers)
        if diff.missing_in_h3 or diff.missing_in_h1 or diff.value_drift:
            findings.append(build_h3_002_finding(diff))
        else:
            findings.append(build_h3_002_pass())

        return findings
