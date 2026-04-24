"""CORS active probe infrastructure tests."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

from corsair.cors.probe import (
    ProbeResult,
    build_probes,
    run_probe,
    run_probes,
)


def _mock_response(headers: dict = None, status_code: int = 200, body: str = ""):
    resp = MagicMock()
    resp.headers = headers or {}
    resp.status_code = status_code
    resp.text = body
    return resp


class TestBuildProbes:
    def test_wave1_probe_set_includes_arbitrary_and_null(self):
        # Wave 1 probes (arbitrary + null) are present; Wave 2 probes are
        # also included as of build_probes Wave 2 extension.
        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://evil.example",
        )
        assert len(probes) >= 2
        origins = [p.origin for p in probes]
        assert "https://evil.example" in origins
        assert "null" in origins

    def test_arbitrary_origin_probe_uses_configured_evil_origin(self):
        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://attacker.test",
        )
        arbitrary = [p for p in probes if p.label == "arbitrary_origin"][0]
        assert arbitrary.origin == "https://attacker.test"

    def test_each_probe_has_unique_cache_buster(self):
        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://evil.example",
        )
        busters = [p.cache_buster for p in probes]
        assert len(set(busters)) == len(busters)


class TestRunProbe:
    def test_captures_acao_acac_vary(self):
        client = AsyncMock()
        client.get.return_value = _mock_response(
            headers={
                "Access-Control-Allow-Origin": "https://evil.example",
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
            }
        )
        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://evil.example",
        )
        probe = [p for p in probes if p.label == "arbitrary_origin"][0]

        result = asyncio.run(run_probe(client, probe, timeout=5.0))

        assert isinstance(result, ProbeResult)
        assert result.origin_sent == "https://evil.example"
        assert result.acao == "https://evil.example"
        assert result.acac == "true"
        assert result.vary == "Origin"
        assert result.status_code == 200

    def test_sends_origin_header_and_cache_buster_param(self):
        client = AsyncMock()
        client.get.return_value = _mock_response()
        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://evil.example",
        )
        probe = [p for p in probes if p.label == "arbitrary_origin"][0]

        asyncio.run(run_probe(client, probe, timeout=5.0))

        call_kwargs = client.get.call_args.kwargs
        assert call_kwargs["headers"]["Origin"] == "https://evil.example"
        # Cache buster should appear in params.
        assert "_cb" in call_kwargs["params"]
        assert call_kwargs["params"]["_cb"] == probe.cache_buster

    def test_null_origin_probe_sends_literal_null(self):
        client = AsyncMock()
        client.get.return_value = _mock_response()
        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://evil.example",
        )
        probe = [p for p in probes if p.label == "null_origin"][0]

        asyncio.run(run_probe(client, probe, timeout=5.0))
        assert client.get.call_args.kwargs["headers"]["Origin"] == "null"

    def test_5xx_response_is_returned_not_raised(self):
        client = AsyncMock()
        client.get.return_value = _mock_response(status_code=503)
        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://evil.example",
        )

        result = asyncio.run(run_probe(client, probes[0], timeout=5.0))
        assert result.status_code == 503
        assert result.error is None


class TestRunProbes:
    def test_runs_probes_concurrently_with_semaphore(self):
        client = AsyncMock()
        client.get.return_value = _mock_response(
            headers={"Access-Control-Allow-Origin": "null"}
        )
        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://evil.example",
        )

        results = asyncio.run(
            run_probes(client, probes, timeout=5.0, max_concurrency=5)
        )
        assert len(results) == len(probes)
        assert all(isinstance(r, ProbeResult) for r in results)

    def test_abort_event_cancels_pending_probes(self):
        slow_client = AsyncMock()

        async def slow_get(*args, **kwargs):
            await asyncio.sleep(3.0)
            return _mock_response()

        slow_client.get = AsyncMock(side_effect=slow_get)

        probes = build_probes(
            url="https://target.example.com",
            evil_origin="https://evil.example",
        )
        abort_event = asyncio.Event()

        async def run_and_abort():
            # Set abort immediately; run_probes should return quickly.
            abort_event.set()
            return await run_probes(
                slow_client,
                probes,
                timeout=5.0,
                max_concurrency=5,
                abort_event=abort_event,
            )

        import time

        start = time.monotonic()
        results = asyncio.run(run_and_abort())
        elapsed = time.monotonic() - start
        # 2.5s bound (same headroom as cache v0.4.1 test) with 3s sleep target.
        assert elapsed < 2.5, f"Abort did not cancel in time: {elapsed:.2f}s"
        # Cancelled probes return ProbeResult with error='aborted' or are absent.
        for r in results:
            if r is not None:
                assert r.error == "aborted" or r.status_code == 0
