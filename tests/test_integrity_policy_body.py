"""Tests for corsair.integrity_policy.body."""

import httpx
import pytest

from corsair.integrity_policy.body import (
    ONE_MEGABYTE,
    _extract_cross_origin_scripts,
    _fetch_body,
)


# ---------------------------------------------------------------------------
# _extract_cross_origin_scripts — basic cross-origin detection
# ---------------------------------------------------------------------------

DOC_URL = "https://www.example.com/"


class TestExtractBasicCrossOrigin:
    def test_different_host_flagged(self):
        body = '<script src="https://cdn.example.com/x.js"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == [
            "https://cdn.example.com/x.js"
        ]

    def test_different_port_flagged(self):
        body = '<script src="https://www.example.com:8080/x.js"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == [
            "https://www.example.com:8080/x.js"
        ]

    def test_different_scheme_flagged(self):
        body = '<script src="http://www.example.com/x.js"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == [
            "http://www.example.com/x.js"
        ]

    def test_mixed_case_host_flagged(self):
        # Hostname compared case-insensitively per URL standard.
        body = '<script src="https://CDN.Example.com/x.js"></script>'
        result = _extract_cross_origin_scripts(body, DOC_URL)
        assert len(result) == 1

    def test_ipv4_vs_hostname(self):
        body = '<script src="https://93.184.216.34/x.js"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == [
            "https://93.184.216.34/x.js"
        ]


# ---------------------------------------------------------------------------
# _extract_cross_origin_scripts — same-origin skip
# ---------------------------------------------------------------------------

class TestExtractSameOriginSkip:
    def test_exact_match_url_skipped(self):
        body = '<script src="https://www.example.com/x.js"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_root_relative_skipped(self):
        body = '<script src="/js/app.js"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_pure_relative_skipped(self):
        body = '<script src="js/app.js"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_explicit_default_port_treated_same_origin(self):
        # https://x:443/ == https://x/
        body = '<script src="https://www.example.com:443/x.js"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []


# ---------------------------------------------------------------------------
# _extract_cross_origin_scripts — protocol-relative URLs
# ---------------------------------------------------------------------------

class TestExtractProtocolRelative:
    def test_protocol_relative_resolves_to_https_when_doc_https(self):
        body = '<script src="//cdn.com/x.js"></script>'
        result = _extract_cross_origin_scripts(body, DOC_URL)
        assert result == ["https://cdn.com/x.js"]

    def test_protocol_relative_resolves_to_http_when_doc_http(self):
        body = '<script src="//cdn.com/x.js"></script>'
        result = _extract_cross_origin_scripts(body, "http://www.example.com/")
        assert result == ["http://cdn.com/x.js"]


# ---------------------------------------------------------------------------
# _extract_cross_origin_scripts — integrity attribute present
# ---------------------------------------------------------------------------

class TestExtractIntegrityPresent:
    def test_integrity_after_src(self):
        body = (
            '<script src="https://cdn.com/x.js" '
            'integrity="sha384-abc" crossorigin="anonymous"></script>'
        )
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_integrity_before_src(self):
        body = (
            '<script integrity="sha384-abc" '
            'src="https://cdn.com/x.js" crossorigin="anonymous"></script>'
        )
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_integrity_with_whitespace_around_equals(self):
        body = '<script src="https://cdn.com/x.js" integrity = "sha384-abc"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_multiline_tag_with_integrity(self):
        body = (
            "<script\n"
            '  src="https://cdn.com/x.js"\n'
            '  integrity="sha384-abc"\n'
            "></script>"
        )
        assert _extract_cross_origin_scripts(body, DOC_URL) == []


# ---------------------------------------------------------------------------
# _extract_cross_origin_scripts — multiple scripts in body
# ---------------------------------------------------------------------------

class TestExtractMultipleScripts:
    def test_mixed_covered_and_uncovered(self):
        body = (
            '<script src="https://cdn1.com/a.js" integrity="sha384-aaa"></script>'
            '<script src="https://cdn2.com/b.js"></script>'
            '<script src="/local.js"></script>'
            '<script src="https://cdn3.com/c.js"></script>'
        )
        result = _extract_cross_origin_scripts(body, DOC_URL)
        assert result == ["https://cdn2.com/b.js", "https://cdn3.com/c.js"]

    def test_all_covered_returns_empty(self):
        body = (
            '<script src="https://cdn1.com/a.js" integrity="sha384-aaa"></script>'
            '<script src="https://cdn2.com/b.js" integrity="sha384-bbb"></script>'
        )
        assert _extract_cross_origin_scripts(body, DOC_URL) == []


# ---------------------------------------------------------------------------
# _extract_cross_origin_scripts — non-fetch schemes
# ---------------------------------------------------------------------------

class TestExtractSpecialSchemes:
    def test_data_url_skipped(self):
        body = '<script src="data:text/javascript,alert(1)"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_javascript_url_skipped(self):
        body = '<script src="javascript:void(0)"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_blob_url_skipped(self):
        body = '<script src="blob:https://www.example.com/abc"></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_empty_src_skipped(self):
        body = '<script src=""></script>'
        assert _extract_cross_origin_scripts(body, DOC_URL) == []


# ---------------------------------------------------------------------------
# _extract_cross_origin_scripts — edge bodies
# ---------------------------------------------------------------------------

class TestExtractEdgeBodies:
    def test_empty_body_returns_empty(self):
        assert _extract_cross_origin_scripts("", DOC_URL) == []

    def test_body_with_no_script_tags(self):
        body = "<html><head><title>x</title></head><body><p>hi</p></body></html>"
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_html_comment_documented_false_positive(self):
        # Documented limitation per spec §5.4: regex still matches scripts
        # inside HTML comments. Lock this behavior into the test suite so
        # any future change is intentional.
        body = '<!-- <script src="https://cdn.com/x.js"></script> -->'
        result = _extract_cross_origin_scripts(body, DOC_URL)
        assert result == ["https://cdn.com/x.js"]

    def test_noscript_subtree_documented_false_positive(self):
        body = (
            "<noscript>"
            '<script src="https://cdn.com/x.js"></script>'
            "</noscript>"
        )
        result = _extract_cross_origin_scripts(body, DOC_URL)
        assert result == ["https://cdn.com/x.js"]

    def test_inline_script_with_no_src_skipped(self):
        body = "<script>alert(1)</script>"
        assert _extract_cross_origin_scripts(body, DOC_URL) == []

    def test_self_closing_xhtml_script_matched(self):
        body = '<script src="https://cdn.com/x.js"/>'
        result = _extract_cross_origin_scripts(body, DOC_URL)
        assert result == ["https://cdn.com/x.js"]


# ---------------------------------------------------------------------------
# _fetch_body — pytest-httpx mocked HTTP
# ---------------------------------------------------------------------------

class TestFetchBody:
    def test_200_ok_returns_body_no_error(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text="<html><body>hi</body></html>",
            headers={"Content-Type": "text/html"},
        )
        body, error = _fetch_body("https://example.com/", 10, "TestUA/1.0")
        assert error is None
        assert "hi" in body

    def test_404_returns_soft_failure(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=404,
            text="not found",
        )
        body, error = _fetch_body("https://example.com/", 10, "TestUA/1.0")
        assert body == ""
        assert error == "HTTP 404"

    def test_500_returns_soft_failure(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=500,
            text="server error",
        )
        body, error = _fetch_body("https://example.com/", 10, "TestUA/1.0")
        assert body == ""
        assert error == "HTTP 500"

    def test_timeout_returns_request_timeout(self, httpx_mock):
        httpx_mock.add_exception(httpx.ReadTimeout("read timeout"))
        body, error = _fetch_body("https://example.com/", 1, "TestUA/1.0")
        assert body == ""
        assert error == "Request timeout"

    def test_body_truncated_at_one_megabyte(self, httpx_mock):
        big = "A" * (ONE_MEGABYTE + 1024)  # 1 MB + 1 KB
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text=big,
            headers={"Content-Type": "text/html"},
        )
        body, error = _fetch_body("https://example.com/", 10, "TestUA/1.0")
        assert error is None
        assert len(body) == ONE_MEGABYTE
