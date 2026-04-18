"""Test cache oracle: CDN fingerprinting and cache status detection."""

from corsair.cache.oracle import (
    CacheStatus,
    fingerprint_cdn,
    make_buster,
    read_cache_status,
)


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


class TestMakeBuster:
    def test_returns_string(self):
        assert isinstance(make_buster(), str)

    def test_unique_values(self):
        busters = {make_buster() for _ in range(100)}
        assert len(busters) == 100

    def test_length(self):
        assert len(make_buster()) == 16
