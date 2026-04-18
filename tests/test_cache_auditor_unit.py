"""Test CacheAuditor orchestration logic."""

from unittest.mock import AsyncMock, patch

from corsair.cache.auditor import CacheAuditor
from corsair.cache.oracle import CacheOracle
from corsair.models import Severity


def _mock_oracle(is_cached=True, cdn="cloudflare", buster_strategy="query_param"):
    return CacheOracle(
        url="https://example.com",
        is_cached=is_cached,
        cdn_fingerprint=cdn,
        buster_strategy=buster_strategy,
        cache_control="public, max-age=3600",
        vary_header="Accept-Encoding",
    )


class TestCacheAuditorPassive:
    def test_not_cached_returns_pass(self):
        auditor = CacheAuditor(active=False)
        with patch(
            "corsair.cache.auditor.establish_oracle",
            new=AsyncMock(return_value=_mock_oracle(is_cached=False)),
        ):
            findings = auditor.audit("https://example.com", {})
        pass_findings = [f for f in findings if f.severity == Severity.PASS]
        assert len(pass_findings) >= 1

    def test_cdn_detected_returns_info(self):
        auditor = CacheAuditor(active=False)
        with patch(
            "corsair.cache.auditor.establish_oracle",
            new=AsyncMock(return_value=_mock_oracle(is_cached=True, cdn="cloudflare")),
        ):
            findings = auditor.audit("https://example.com", {})
        info_findings = [f for f in findings if f.severity == Severity.INFO]
        assert any("CDN" in f.title for f in info_findings)

    def test_no_vary_origin_detected(self):
        auditor = CacheAuditor(active=False)
        oracle = _mock_oracle(is_cached=True)
        oracle.vary_header = "Accept-Encoding"
        headers = {"Access-Control-Allow-Origin": "https://example.com"}

        with patch(
            "corsair.cache.auditor.establish_oracle",
            new=AsyncMock(return_value=oracle),
        ):
            findings = auditor.audit("https://example.com", headers)
        assert any(
            f.title == "Missing Vary: Origin on CORS-enabled cached response" for f in findings
        )

    def test_cache_public_sensitive_detected(self):
        auditor = CacheAuditor(active=False)
        oracle = _mock_oracle(is_cached=True)
        oracle.cache_control = "public, max-age=3600"
        headers = {
            "Set-Cookie": "session=abc123",
            "Cache-Control": "public, max-age=3600",
        }

        with patch(
            "corsair.cache.auditor.establish_oracle",
            new=AsyncMock(return_value=oracle),
        ):
            findings = auditor.audit("https://example.com", headers)
        assert any(
            "authenticated content" in f.title.lower() or "public caching" in f.title.lower()
            for f in findings
        )


class TestCacheAuditorActiveSkip:
    def test_active_false_skips_probing(self):
        auditor = CacheAuditor(active=False)
        with patch(
            "corsair.cache.auditor.establish_oracle",
            new=AsyncMock(return_value=_mock_oracle(is_cached=True)),
        ):
            with patch("corsair.cache.auditor.probe_single_header") as mock_probe:
                auditor.audit("https://example.com", {})
                mock_probe.assert_not_called()

    def test_not_cached_skips_probing(self):
        auditor = CacheAuditor(active=True)
        with patch(
            "corsair.cache.auditor.establish_oracle",
            new=AsyncMock(return_value=_mock_oracle(is_cached=False)),
        ):
            with patch("corsair.cache.auditor.probe_single_header") as mock_probe:
                auditor.audit("https://example.com", {})
                mock_probe.assert_not_called()

    def test_no_buster_skips_probing(self):
        auditor = CacheAuditor(active=True)
        with patch(
            "corsair.cache.auditor.establish_oracle",
            new=AsyncMock(return_value=_mock_oracle(is_cached=True, buster_strategy="none")),
        ):
            with patch("corsair.cache.auditor.probe_single_header") as mock_probe:
                findings = auditor.audit("https://example.com", {})
                mock_probe.assert_not_called()
        assert any("skipped" in f.title.lower() for f in findings)
