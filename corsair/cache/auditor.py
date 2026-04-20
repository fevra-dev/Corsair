"""
CacheAuditor -- orchestrates cache poisoning detection for Corsair.

Main entry point: CacheAuditor.audit(url, headers) -> list[Finding]
Called by HeadScanner.scan_target() for all targets.
"""

import asyncio
import logging
import re
from typing import List

import httpx

from ..models import Finding
from .findings import get_finding
from .oracle import CacheOracle, establish_oracle
from .probe import (
    PROBE_HEADERS,
    CanaryResult,
    probe_cpdos_malformed,
    probe_cpdos_method_override,
    probe_cpdos_oversize,
    probe_single_header,
)

logger = logging.getLogger(__name__)


class CacheAuditor:
    def __init__(
        self,
        timeout: int = 10,
        max_concurrency: int = 5,
        active: bool = True,
    ):
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.active = active

    def audit(self, url: str, headers: dict[str, str]) -> List[Finding]:
        try:
            return asyncio.run(self._audit_async(url, headers))
        except Exception as e:
            logger.error(f"Cache audit failed for {url}: {e}")
            return []

    async def _audit_async(self, url: str, headers: dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        async with httpx.AsyncClient(
            follow_redirects=True,
            verify=True,
        ) as client:
            oracle = await establish_oracle(client, url, timeout=self.timeout)
            logger.info(
                f"Cache oracle: cached={oracle.is_cached}, "
                f"cdn={oracle.cdn_fingerprint}, "
                f"buster={oracle.buster_strategy}"
            )

            findings.extend(self._passive_checks(oracle, headers))

            if not self.active:
                return findings

            if not oracle.is_cached:
                return findings

            if oracle.query_string_keyed is None:
                return findings

            if oracle.buster_strategy == "none":
                skipped = get_finding("WCP_PROBE_SKIPPED")
                if skipped:
                    findings.append(skipped)
                return findings

            active_findings = await self._active_probes(client, oracle)
            findings.extend(active_findings)

        return findings

    def _passive_checks(self, oracle: CacheOracle, headers: dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []
        h = {k.lower(): v for k, v in headers.items()}

        if not oracle.is_cached:
            finding = get_finding("WCP_NOT_CACHED")
            if finding:
                findings.append(finding)
            return findings

        if oracle.cdn_fingerprint:
            finding = get_finding("WCP_CDN_DETECTED")
            if finding:
                finding.current_value = oracle.cdn_fingerprint
                findings.append(finding)

        if oracle.query_string_keyed is False:
            finding = get_finding("WCP_NO_CACHE_KEY_QS")
            if finding:
                findings.append(finding)
        elif oracle.query_string_keyed is None:
            finding = get_finding("WCP_CACHE_KEYING_UNDETERMINED")
            if finding:
                findings.append(finding)

        acao = h.get("access-control-allow-origin")
        if acao and acao != "*":
            vary = (oracle.vary_header or "").lower()
            if "origin" not in vary:
                finding = get_finding("WCP_NO_VARY_ORIGIN")
                if finding:
                    finding.current_value = f"ACAO: {acao}, Vary: {oracle.vary_header or 'absent'}"
                    findings.append(finding)

        cc = (oracle.cache_control or "").lower()
        if "public" in cc and "set-cookie" in h:
            finding = get_finding("WCP_CACHE_PUBLIC_SENSITIVE")
            if finding:
                finding.current_value = f"Cache-Control: {oracle.cache_control}"
                findings.append(finding)

        if cc and "no-store" not in cc and "private" not in cc:
            max_age_match = re.search(r"(?:s-)?max-age=(\d+)", cc)
            if max_age_match and int(max_age_match.group(1)) > 86400:
                finding = get_finding("WCP_PERMISSIVE_CACHE_CONTROL")
                if finding:
                    finding.current_value = f"Cache-Control: {oracle.cache_control}"
                    findings.append(finding)

        return findings

    async def _active_probes(
        self, client: httpx.AsyncClient, oracle: CacheOracle
    ) -> List[Finding]:
        findings: List[Finding] = []
        abort_event = asyncio.Event()
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def limited_probe(header_name, value_template):
            async with semaphore:
                if abort_event.is_set():
                    return CanaryResult(header_name=header_name, canary="", detail="Aborted")
                return await probe_single_header(
                    client,
                    oracle,
                    header_name,
                    value_template,
                    timeout=self.timeout,
                    abort_event=abort_event,
                )

        async def limited_cpdos(probe_func):
            async with semaphore:
                if abort_event.is_set():
                    return CanaryResult(header_name="CPDoS", canary="", detail="Aborted")
                return await probe_func(
                    client,
                    oracle,
                    timeout=self.timeout,
                    abort_event=abort_event,
                )

        tasks: list[asyncio.Task] = []
        for header_name, value_template in PROBE_HEADERS:
            tasks.append(asyncio.create_task(limited_probe(header_name, value_template)))
        tasks.append(asyncio.create_task(limited_cpdos(probe_cpdos_oversize)))
        tasks.append(asyncio.create_task(limited_cpdos(probe_cpdos_malformed)))
        tasks.append(asyncio.create_task(limited_cpdos(probe_cpdos_method_override)))

        async def abort_watcher():
            await abort_event.wait()
            for t in tasks:
                if not t.done():
                    t.cancel()

        watcher = asyncio.create_task(abort_watcher())
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            watcher.cancel()
            try:
                await watcher
            except (asyncio.CancelledError, Exception):
                pass

        for r in results:
            if isinstance(r, asyncio.CancelledError):
                continue
            if isinstance(r, Exception):
                logger.warning(f"Probe failed: {r}")
                continue
            if not r.confirmed_unkeyed:
                continue

            finding = get_finding(r.finding_id)
            if finding:
                finding.header = r.header_name
                finding.current_value = r.detail
                findings.append(finding)

        return findings
