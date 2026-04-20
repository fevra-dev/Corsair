"""Test canary injection protocol and CPDoS probes."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from corsair.cache.oracle import CacheOracle
from corsair.cache.probe import (
    PROBE_HEADERS,
    CanaryResult,
    classify_finding,
    probe_cpdos_oversize,
    probe_single_header,
)


def _mock_response(body: str = "", headers: dict = None, status_code: int = 200):
    resp = MagicMock()
    resp.text = body
    resp.headers = headers or {}
    resp.status_code = status_code
    return resp


class TestProbeHeaders:
    def test_probe_headers_count(self):
        assert len(PROBE_HEADERS) == 16

    def test_first_probe_is_x_forwarded_host(self):
        assert PROBE_HEADERS[0][0] == "X-Forwarded-Host"


class TestCanaryResult:
    def test_default_values(self):
        r = CanaryResult(header_name="X-Test", canary="abc123")
        assert r.reflected_in_baseline is False
        assert r.confirmed_unkeyed is False
        assert r.severity == "NONE"


class TestProbeSingleHeader:
    def test_not_reflected_exits_early(self):
        oracle = CacheOracle(url="https://example.com", is_cached=True)
        client = AsyncMock()
        client.get.return_value = _mock_response(body="<html>no canary</html>")

        result = asyncio.run(
            probe_single_header(
                client, oracle, "X-Forwarded-Host", "{canary}.corsair-canary.invalid"
            )
        )
        assert result.reflected_in_baseline is False
        assert result.confirmed_unkeyed is False
        assert client.get.call_count == 1

    def test_reflected_and_cached_confirms_unkeyed(self):
        oracle = CacheOracle(url="https://example.com", is_cached=True)
        client = AsyncMock()

        phase1_resp = _mock_response(
            body='<script src="https://testcanary.corsair-canary.invalid/x.js"></script>',
        )
        phase2_resp = _mock_response(
            body='<script src="https://testcanary.corsair-canary.invalid/x.js"></script>',
            headers={"cf-cache-status": "HIT"},
        )
        phase3_resp = _mock_response(body="<html>clean page</html>")

        client.get.side_effect = [phase1_resp, phase2_resp, phase3_resp]

        with patch("corsair.cache.probe.make_buster", return_value="testcanary"):
            result = asyncio.run(
                probe_single_header(
                    client,
                    oracle,
                    "X-Forwarded-Host",
                    "{canary}.corsair-canary.invalid",
                )
            )

        assert result.reflected_in_baseline is True
        assert result.confirmed_unkeyed is True
        assert result.reflection_context == "script_src"
        assert client.get.call_count == 3

    def test_buster_strategy_none_skips(self):
        oracle = CacheOracle(url="https://example.com", is_cached=True, buster_strategy="none")
        client = AsyncMock()

        result = asyncio.run(
            probe_single_header(
                client, oracle, "X-Forwarded-Host", "{canary}.corsair-canary.invalid"
            )
        )
        assert "Skipped" in result.detail
        assert client.get.call_count == 0

    def test_live_cache_poisoned_on_phase3(self):
        oracle = CacheOracle(url="https://example.com", is_cached=True)
        client = AsyncMock()

        canary_body = '<script src="https://testcanary.corsair-canary.invalid/x.js"></script>'
        phase1_resp = _mock_response(body=canary_body)
        phase2_resp = _mock_response(body=canary_body, headers={"cf-cache-status": "HIT"})
        phase3_resp = _mock_response(body=canary_body)

        client.get.side_effect = [phase1_resp, phase2_resp, phase3_resp]

        with patch("corsair.cache.probe.make_buster", return_value="testcanary"):
            result = asyncio.run(
                probe_single_header(
                    client,
                    oracle,
                    "X-Forwarded-Host",
                    "{canary}.corsair-canary.invalid",
                )
            )

        assert result.confirmed_unkeyed is True
        assert result.severity == "CRITICAL"
        assert result.finding_id == "WCP_LIVE_CACHE_POISONED"


class TestClassifyFinding:
    def test_script_src_is_critical(self):
        severity, finding_id = classify_finding("X-Forwarded-Host", "script_src")
        assert severity == "CRITICAL"
        assert finding_id == "WCP_UNKEYED_HEADER_CRITICAL"

    def test_csp_header_is_critical(self):
        severity, finding_id = classify_finding("X-Forwarded-Host", "csp_header")
        assert severity == "CRITICAL"
        assert finding_id == "WCP_UNKEYED_HEADER_CRITICAL"

    def test_location_header_is_high(self):
        severity, finding_id = classify_finding("X-Forwarded-Host", "location_header")
        assert severity == "HIGH"
        assert finding_id == "WCP_UNKEYED_HEADER_HIGH"

    def test_canonical_is_medium(self):
        severity, finding_id = classify_finding("X-Forwarded-Host", "canonical_href")
        assert severity == "MEDIUM"
        assert finding_id == "WCP_UNKEYED_HEADER_MEDIUM"

    def test_body_text_is_low(self):
        severity, finding_id = classify_finding("X-Forwarded-Host", "body_text")
        assert severity == "LOW"
        assert finding_id == "WCP_UNKEYED_HEADER_LOW"


class TestCPDoSOversize:
    def test_cached_error_confirms_cpdos(self):
        oracle = CacheOracle(url="https://example.com", is_cached=True)
        client = AsyncMock()

        phase1_resp = _mock_response(status_code=431, body="Request Header Fields Too Large")
        phase2_resp = _mock_response(
            status_code=431,
            body="Request Header Fields Too Large",
            headers={"cf-cache-status": "HIT"},
        )
        phase3_resp = _mock_response(status_code=200, body="<html>OK</html>")

        client.get.side_effect = [phase1_resp, phase2_resp, phase3_resp]

        result = asyncio.run(probe_cpdos_oversize(client, oracle))
        assert result.confirmed_unkeyed is True
        assert result.finding_id == "WCP_CPDOS_OVERSIZE"

    def test_no_error_response_no_cpdos(self):
        oracle = CacheOracle(url="https://example.com", is_cached=True)
        client = AsyncMock()

        client.get.return_value = _mock_response(status_code=200, body="OK")

        result = asyncio.run(probe_cpdos_oversize(client, oracle))
        assert result.confirmed_unkeyed is False


class TestContextToFinding:
    def test_alt_svc_maps_to_alt_svc_poisoning(self):
        from corsair.cache.probe import CONTEXT_TO_SEVERITY

        severity, finding_id = CONTEXT_TO_SEVERITY["alt_svc_header"]
        assert severity == "HIGH"
        assert finding_id == "WCP_ALT_SVC_POISONING"

    def test_set_cookie_maps_to_set_cookie_poisoning(self):
        from corsair.cache.probe import CONTEXT_TO_SEVERITY

        severity, finding_id = CONTEXT_TO_SEVERITY["set_cookie_header"]
        assert severity == "HIGH"
        assert finding_id == "WCP_SET_COOKIE_POISONING"
