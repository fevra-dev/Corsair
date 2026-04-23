"""
CORSAuditor — orchestrates CORS DAST for Corsair.

Three-phase pipeline:
  Phase 1 (passive): header-only analysis (always runs).
  Phase 2 (active reflection): Origin-varied GETs, ~2 probes in Wave 1.
  Phase 3 (preflight + cache-key): stub in Wave 1, lit up in Wave 3.

Mirrors corsair.cache.auditor.CacheAuditor post-v0.4.1 (asyncio.Event
abort + semaphore + gather(return_exceptions=True) + finally-cancelled
watcher). Classification is folded into the as_completed loop so CRITICAL
verdicts can preemptively cancel pending probes.
"""

import asyncio
import logging
from typing import Dict, List

import httpx

from ..models import Finding
from .analyzers import classify_reflection
from .findings import get_finding
from .passive import analyze as passive_analyze
from .probe import ProbeResult, build_probes, run_probe

logger = logging.getLogger(__name__)


class CORSAuditor:
    def __init__(
        self,
        timeout: int = 10,
        max_concurrency: int = 5,
        active: bool = True,
        evil_origin: str = "https://evil.example",
        phase_timeout: int = 60,
    ):
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.active = active
        self.evil_origin = evil_origin
        self.phase_timeout = phase_timeout

    def audit(self, url: str, headers: Dict[str, str]) -> List[Finding]:
        try:
            return asyncio.run(self._audit_async(url, headers))
        except Exception as e:
            logger.error(f"CORS audit failed for {url}: {e}")
            return []

    async def _audit_async(
        self, url: str, headers: Dict[str, str]
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Phase 1: passive, always runs.
        findings.extend(passive_analyze(headers, url))

        if not self.active:
            return findings

        # Phase 2: active reflection probes.
        async with httpx.AsyncClient(
            follow_redirects=False,  # We need to inspect 302 locations.
            verify=True,
        ) as client:
            try:
                phase2_findings = await asyncio.wait_for(
                    self._active_reflection_phase(client, url, headers),
                    timeout=self.phase_timeout,
                )
                findings.extend(phase2_findings)
            except asyncio.TimeoutError:
                logger.warning(f"[cors] reflection phase timeout on {url}")
                timeout_finding = get_finding("CORS_PHASE_TIMEOUT")
                if timeout_finding:
                    findings.append(timeout_finding)

        # Phase 3: preflight + cache-key — Wave 3. Stub returns no findings.

        return findings

    async def _active_reflection_phase(
        self,
        client: httpx.AsyncClient,
        url: str,
        request_headers: Dict[str, str],
    ) -> List[Finding]:
        findings: List[Finding] = []
        abort_event = asyncio.Event()
        semaphore = asyncio.Semaphore(self.max_concurrency)
        probes = build_probes(url=url, evil_origin=self.evil_origin)

        async def limited(probe) -> ProbeResult:
            async with semaphore:
                if abort_event.is_set():
                    return ProbeResult(
                        label=probe.label,
                        origin_sent=probe.origin,
                        error="aborted",
                    )
                try:
                    return await run_probe(client, probe, timeout=self.timeout)
                except asyncio.CancelledError:
                    return ProbeResult(
                        label=probe.label,
                        origin_sent=probe.origin,
                        error="aborted",
                    )

        tasks = [asyncio.create_task(limited(p)) for p in probes]

        async def abort_watcher():
            await abort_event.wait()
            for t in tasks:
                if not t.done():
                    t.cancel()

        watcher = asyncio.create_task(abort_watcher())
        results: List[ProbeResult] = []
        try:
            for coro in asyncio.as_completed(tasks):
                try:
                    result = await coro
                except asyncio.CancelledError:
                    continue
                results.append(result)
                if result.error:
                    continue

                verdict = classify_reflection(
                    result,
                    evil_origin=self.evil_origin,
                    request_headers=request_headers,
                )
                if verdict is None:
                    continue

                finding = get_finding(verdict.finding_id)
                if finding is None:
                    continue
                finding.severity = verdict.effective_severity
                finding.current_value = (
                    f"Origin: {result.origin_sent} → "
                    f"ACAO: {result.acao}, ACAC: {result.acac or 'absent'}"
                )
                if verdict.downgraded:
                    finding.description = (
                        f"{finding.description} "
                        f"Severity downgraded from "
                        f"{verdict.default_severity.value} to "
                        f"{verdict.effective_severity.value} because no "
                        f"sensitivity signal (authenticated session, JSON "
                        f"API, or login redirect) was observed. If this "
                        f"endpoint returns sensitive data under "
                        f"authentication, manually confirm and escalate."
                    )
                findings.append(finding)

                # Preemptive abort: a CRITICAL verdict is conclusive —
                # cancel pending probes.
                if verdict.effective_severity.value == "CRITICAL":
                    abort_event.set()
        finally:
            watcher.cancel()
            try:
                await watcher
            except (asyncio.CancelledError, Exception):
                pass

        # Meta finding: if no reflection findings fired and every non-aborted
        # probe hit an auth gate, the anonymous probes couldn't verdict the
        # endpoint.
        if not findings:
            non_aborted = [r for r in results if r.error != "aborted"]
            all_auth_gated = (
                len(non_aborted) > 0
                and all(r.status_code in (401, 403) for r in non_aborted)
            )
            if all_auth_gated:
                incon = get_finding("CORS_PROBE_INCONCLUSIVE")
                if incon:
                    findings.append(incon)

        return findings
