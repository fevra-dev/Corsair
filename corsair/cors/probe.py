"""
Active CORS reflection probing.

Builds Origin-varied probe requests, executes them over httpx.AsyncClient
under a semaphore-bounded gather() with an abort_event escape hatch. Pattern
mirrors corsair.cache.auditor._active_probes() post-v0.4.1.
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass
from typing import List, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class OriginProbe:
    """A single Origin-varied probe to send."""

    url: str
    origin: str  # Value to send in the Origin request header.
    label: str  # Classifier tag, e.g. "arbitrary_origin", "null_origin".
    cache_buster: str  # UUID-based unique query param value.


@dataclass
class ProbeResult:
    """Outcome of executing a single OriginProbe."""

    label: str
    origin_sent: str
    acao: Optional[str] = None
    acac: Optional[str] = None
    vary: Optional[str] = None
    set_cookie: Optional[str] = None
    content_type: Optional[str] = None
    status_code: int = 0
    location: Optional[str] = None
    error: Optional[str] = None


def _make_cache_buster() -> str:
    return uuid.uuid4().hex[:16]


def build_probes(url: str, evil_origin: str) -> List[OriginProbe]:
    """
    Build the Wave 1 probe set: arbitrary origin + null origin.

    Later waves extend this with the bypass matrix, protocol downgrade,
    and internal-network origins.
    """
    return [
        OriginProbe(
            url=url,
            origin=evil_origin,
            label="arbitrary_origin",
            cache_buster=_make_cache_buster(),
        ),
        OriginProbe(
            url=url,
            origin="null",
            label="null_origin",
            cache_buster=_make_cache_buster(),
        ),
    ]


async def run_probe(
    client: httpx.AsyncClient,
    probe: OriginProbe,
    timeout: float = 10.0,
) -> ProbeResult:
    """Execute one probe and capture the CORS-relevant response metadata."""
    try:
        response = await client.get(
            probe.url,
            headers={"Origin": probe.origin},
            params={"_cb": probe.cache_buster},
            timeout=timeout,
        )
    except (httpx.TimeoutException, httpx.HTTPError) as e:
        logger.debug(f"[cors-probe] {probe.label} failed: {e}")
        return ProbeResult(
            label=probe.label,
            origin_sent=probe.origin,
            error=str(e),
        )

    h = {k.lower(): v for k, v in response.headers.items()}
    return ProbeResult(
        label=probe.label,
        origin_sent=probe.origin,
        acao=h.get("access-control-allow-origin"),
        acac=h.get("access-control-allow-credentials"),
        vary=h.get("vary"),
        set_cookie=h.get("set-cookie"),
        content_type=h.get("content-type"),
        status_code=response.status_code,
        location=h.get("location"),
    )


async def run_probes(
    client: httpx.AsyncClient,
    probes: List[OriginProbe],
    timeout: float = 10.0,
    max_concurrency: int = 5,
    abort_event: Optional[asyncio.Event] = None,
) -> List[ProbeResult]:
    """
    Run all probes concurrently under a semaphore with abort support.

    If abort_event is set before or during execution, pending probes are
    cancelled and returned as ProbeResult(error='aborted').
    """
    if abort_event is None:
        abort_event = asyncio.Event()

    semaphore = asyncio.Semaphore(max_concurrency)

    async def limited(probe: OriginProbe) -> ProbeResult:
        async with semaphore:
            if abort_event.is_set():
                return ProbeResult(
                    label=probe.label,
                    origin_sent=probe.origin,
                    error="aborted",
                )
            return await run_probe(client, probe, timeout=timeout)

    tasks = [asyncio.create_task(limited(p)) for p in probes]

    async def abort_watcher():
        await abort_event.wait()
        for t in tasks:
            if not t.done():
                t.cancel()

    watcher = asyncio.create_task(abort_watcher())
    try:
        raw = await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        watcher.cancel()
        try:
            await watcher
        except (asyncio.CancelledError, Exception):
            pass

    results: List[ProbeResult] = []
    for probe, r in zip(probes, raw):
        if isinstance(r, asyncio.CancelledError):
            results.append(
                ProbeResult(
                    label=probe.label,
                    origin_sent=probe.origin,
                    error="aborted",
                )
            )
        elif isinstance(r, Exception):
            logger.warning(f"[cors-probe] {probe.label} raised: {r}")
            results.append(
                ProbeResult(
                    label=probe.label,
                    origin_sent=probe.origin,
                    error=str(r),
                )
            )
        else:
            results.append(r)
    return results
