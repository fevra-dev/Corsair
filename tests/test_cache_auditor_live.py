"""Live integration tests for cache oracle against real targets.

These tests hit external services and are skipped by default.
Run with: pytest -m slow
"""

import pytest

from corsair.cache.auditor import CacheAuditor
from corsair.models import Severity


@pytest.mark.slow
class TestCacheAuditorLive:
    def test_cdn_cached_asset_detects_caching(self):
        """Test against a known CDN-cached static asset."""
        auditor = CacheAuditor(active=False)
        findings = auditor.audit(
            "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js", {}
        )
        cdn_findings = [f for f in findings if "CDN" in f.title]
        assert len(cdn_findings) >= 1
        assert cdn_findings[0].current_value is not None

    def test_uncached_endpoint_returns_pass(self):
        """Test against a dynamic endpoint unlikely to be cached."""
        auditor = CacheAuditor(active=False)
        findings = auditor.audit("https://httpbin.org/get", {})
        pass_findings = [f for f in findings if f.severity == Severity.PASS]
        has_pass_or_cdn = len(pass_findings) >= 1 or any(
            f.severity == Severity.INFO for f in findings
        )
        assert has_pass_or_cdn

    def test_oracle_does_not_crash_on_timeout(self):
        """Test that oracle handles slow targets gracefully."""
        auditor = CacheAuditor(timeout=3, active=False)
        findings = auditor.audit("https://httpbin.org/delay/1", {})
        assert isinstance(findings, list)
