"""End-to-end CacheAuditor scenarios for Alt-Svc hardening."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from corsair.cache.auditor import CacheAuditor


def _mock_response(headers=None, status_code=200, text="ok"):
    response = MagicMock()
    response.status_code = status_code
    response.headers = headers or {}
    response.text = text
    return response


def _audit_with_baseline_headers(url, baseline_headers):
    auditor = CacheAuditor(active=False)  # passive only

    async def fake_get(*args, **kwargs):
        return _mock_response(headers=baseline_headers)

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=fake_get)
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client_cls.return_value = mock_client
        return auditor.audit(url, {})


class TestAltSvcPassiveIntegration:
    def test_cross_domain_and_excessive_persistence_both_emit(self):
        baseline = {
            "alt-svc": 'h3="evil.net:443"; ma=3600000; persist=1',
            "cache-control": "public, max-age=60",
            "x-cache": "HIT",
        }
        findings = _audit_with_baseline_headers("https://api.example.com/v1", baseline)
        ids = [f.title for f in findings]
        assert any("different registrable domain" in t for t in ids)
        assert any("ma > 30 days" in t for t in ids)

    def test_internal_ip_emits_private_host(self):
        baseline = {
            "alt-svc": 'h3="10.0.0.5:443"; ma=86400',
            "cache-control": "public, max-age=60",
            "x-cache": "HIT",
        }
        findings = _audit_with_baseline_headers("https://api.example.com/v1", baseline)
        assert any("private or non-public" in f.title for f in findings)

    def test_missing_alt_svc_no_new_findings(self):
        baseline = {"cache-control": "public, max-age=60", "x-cache": "HIT"}
        findings = _audit_with_baseline_headers("https://api.example.com/v1", baseline)
        for f in findings:
            assert "Alt-Svc" not in f.header or f.header == "Alt-Svc" and "alt-authority" not in f.title.lower()


def _audit_with_oracle(url, baseline_headers, probe_response_headers, probe_status=200):
    """Active audit. First request returns baseline; subsequent (probe) requests
    return probe_response_headers. Caller must include CDN-status hit header
    in baseline so oracle marks is_cached=True."""
    auditor = CacheAuditor(active=True)

    call_count = {"n": 0}

    async def fake_get(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] <= 4:  # baseline + cache-key probes
            return _mock_response(headers=baseline_headers)
        return _mock_response(headers=probe_response_headers, status_code=probe_status)

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=fake_get)
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client_cls.return_value = mock_client
        return auditor.audit(url, {})


class TestAltSvcPreCheckIntegration:
    def test_cloudflare_skips_alt_svc_probe(self):
        baseline = {
            "alt-svc": 'h3=":443"; ma=86400',
            "cf-cache-status": "HIT",
            "cf-ray": "abc",
            "cache-control": "public, max-age=60",
        }
        # Even if the probe response would reflect a canary into Alt-Svc,
        # we must not emit WCP_ALT_SVC_POISONING when CDN is Cloudflare.
        probe_resp = {"cf-cache-status": "HIT", "alt-svc": 'h3="canary.invalid:443"'}
        findings = _audit_with_oracle(
            "https://api.example.com/v1", baseline, probe_resp
        )
        ids = [f.title for f in findings]
        assert not any("Alt-Svc cache poisoning" in t for t in ids)
