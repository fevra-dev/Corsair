"""Test cache oracle: CDN fingerprinting and cache status detection."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

from corsair.cache.oracle import (
    CacheOracle,
    CacheStatus,
    _akamai_qs_in_key,
    _resolve_buster_from_vary,
    establish_oracle,
    fingerprint_cdn,
    make_buster,
    read_cache_status,
)


def _mock_client_pair(r1_headers, r2_headers, r1_body="", r2_body=""):
    r1 = MagicMock()
    r1.headers = r1_headers
    r1.text = r1_body
    r2 = MagicMock()
    r2.headers = r2_headers
    r2.text = r2_body
    client = MagicMock()
    client.get = AsyncMock(side_effect=[r1, r2])
    return client


class TestCDNFingerprinting:
    def test_cloudflare_via_cf_ray(self):
        headers = {"cf-ray": "abc123", "content-type": "text/html"}
        assert fingerprint_cdn(headers) == "cloudflare"

    def test_cloudflare_via_cf_cache_status(self):
        headers = {"cf-cache-status": "HIT"}
        assert fingerprint_cdn(headers) == "cloudflare"

    def test_akamai_via_server(self):
        headers = {"x-cache": "TCP_HIT", "server": "AkamaiGHost"}
        assert fingerprint_cdn(headers) == "akamai"

    def test_akamai_via_check_cacheable(self):
        headers = {"x-check-cacheable": "YES"}
        assert fingerprint_cdn(headers) == "akamai"

    def test_fastly_via_served_by(self):
        headers = {"x-served-by": "cache-lax1234"}
        assert fingerprint_cdn(headers) == "fastly"

    def test_fastly_via_cache_hits(self):
        headers = {"x-cache-hits": "3"}
        assert fingerprint_cdn(headers) == "fastly"

    def test_varnish(self):
        headers = {"x-varnish": "123456 789012"}
        assert fingerprint_cdn(headers) == "varnish"

    def test_cloudfront(self):
        headers = {"x-amz-cf-id": "abc123"}
        assert fingerprint_cdn(headers) == "cloudfront"

    def test_cloudfront_via_pop(self):
        headers = {"x-amz-cf-pop": "IAD89-C1"}
        assert fingerprint_cdn(headers) == "cloudfront"

    def test_nginx(self):
        headers = {"x-cache-status": "HIT"}
        assert fingerprint_cdn(headers) == "nginx"

    def test_generic_via(self):
        headers = {"via": "1.1 proxy.example.com"}
        assert fingerprint_cdn(headers) == "generic"

    def test_no_cdn(self):
        headers = {"content-type": "text/html", "server": "Apache"}
        assert fingerprint_cdn(headers) is None


class TestCacheStatusDetection:
    def test_cloudflare_hit(self):
        headers = {"cf-cache-status": "HIT"}
        assert read_cache_status(headers, "cloudflare") == CacheStatus.HIT

    def test_cloudflare_miss(self):
        headers = {"cf-cache-status": "MISS"}
        assert read_cache_status(headers, "cloudflare") == CacheStatus.MISS

    def test_cloudflare_dynamic(self):
        headers = {"cf-cache-status": "DYNAMIC"}
        assert read_cache_status(headers, "cloudflare") == CacheStatus.MISS

    def test_xcache_tcp_hit(self):
        headers = {"x-cache": "TCP_HIT"}
        assert read_cache_status(headers, "akamai") == CacheStatus.HIT

    def test_xcache_tcp_mem_hit(self):
        headers = {"x-cache": "TCP_MEM_HIT"}
        assert read_cache_status(headers, "akamai") == CacheStatus.HIT

    def test_xcache_miss(self):
        headers = {"x-cache": "MISS"}
        assert read_cache_status(headers, "fastly") == CacheStatus.MISS

    def test_varnish_hit_two_ids(self):
        headers = {"x-varnish": "123456 789012"}
        assert read_cache_status(headers, "varnish") == CacheStatus.HIT

    def test_varnish_miss_one_id(self):
        headers = {"x-varnish": "123456"}
        assert read_cache_status(headers, "varnish") == CacheStatus.MISS

    def test_age_nonzero_is_hit(self):
        headers = {"age": "120"}
        assert read_cache_status(headers, "generic") == CacheStatus.HIT

    def test_age_zero_is_unknown(self):
        headers = {"age": "0"}
        assert read_cache_status(headers, "generic") == CacheStatus.UNKNOWN

    def test_no_cache_headers_is_unknown(self):
        headers = {"content-type": "text/html"}
        assert read_cache_status(headers, None) == CacheStatus.UNKNOWN


class TestIsCachedAgeFallback:
    def test_is_cached_via_age_increment_when_status_unknown(self):
        # DYNAMIC status (not cached per header) but Age increments 3 → 7.
        # Widening must trust age_increments as independent evidence of caching.
        r1_headers = {"cf-cache-status": "DYNAMIC", "age": "3"}
        r2_headers = {"cf-cache-status": "DYNAMIC", "age": "7"}
        client = _mock_client_pair(r1_headers, r2_headers)

        oracle = asyncio.run(establish_oracle(client, "https://example.com", timeout=5))
        assert oracle.is_cached is True
        assert oracle.age_increments is True

    def test_is_cached_false_when_age_static_and_status_miss(self):
        # Both MISS, age stable — widening must not flip False to True.
        r1_headers = {"cf-cache-status": "MISS", "age": "10"}
        r2_headers = {"cf-cache-status": "MISS", "age": "10"}
        client = _mock_client_pair(r1_headers, r2_headers)

        oracle = asyncio.run(establish_oracle(client, "https://example.com", timeout=5))
        assert oracle.is_cached is False
        assert oracle.age_increments is False


class TestAkamaiCacheKeyParser:
    def test_empty_returns_none(self):
        assert _akamai_qs_in_key("") is None

    def test_none_returns_none(self):
        assert _akamai_qs_in_key(None) is None

    def test_with_query_string_returns_true(self):
        key = "/L/3600/1234/example.com/page?id=1/_metadata"
        assert _akamai_qs_in_key(key) is True

    def test_without_query_string_returns_false(self):
        key = "/L/3600/1234/example.com/page/_metadata"
        assert _akamai_qs_in_key(key) is False

    def test_question_mark_only_after_underscore_metadata_is_false(self):
        key = "/L/3600/1234/example.com/page/_bucket?reserved=1"
        assert _akamai_qs_in_key(key) is False

    def test_question_mark_in_url_and_metadata_is_true(self):
        key = "/L/3600/1234/example.com/page?id=1/_bucket?reserved=1"
        assert _akamai_qs_in_key(key) is True


class TestResolveBusterFromVary:
    def test_accept_language_in_vary(self):
        oracle = CacheOracle(url="https://example.com", vary_header="Accept-Language, User-Agent")
        _resolve_buster_from_vary(oracle)
        assert oracle.buster_strategy == "accept_language"
        assert oracle.buster_param == "Accept-Language"

    def test_user_agent_in_vary(self):
        oracle = CacheOracle(url="https://example.com", vary_header="User-Agent")
        _resolve_buster_from_vary(oracle)
        assert oracle.buster_strategy == "user_agent"
        assert oracle.buster_param == "User-Agent"

    def test_vary_missing_sets_none(self):
        oracle = CacheOracle(url="https://example.com", vary_header=None)
        _resolve_buster_from_vary(oracle)
        assert oracle.buster_strategy == "none"

    def test_vary_unhelpful_sets_none(self):
        oracle = CacheOracle(url="https://example.com", vary_header="Accept-Encoding")
        _resolve_buster_from_vary(oracle)
        assert oracle.buster_strategy == "none"

    def test_accept_language_precedes_user_agent(self):
        oracle = CacheOracle(url="https://example.com", vary_header="User-Agent, Accept-Language")
        _resolve_buster_from_vary(oracle)
        assert oracle.buster_strategy == "accept_language"


class TestMakeBuster:
    def test_returns_string(self):
        assert isinstance(make_buster(), str)

    def test_unique_values(self):
        busters = {make_buster() for _ in range(100)}
        assert len(busters) == 100

    def test_length(self):
        assert len(make_buster()) == 16
