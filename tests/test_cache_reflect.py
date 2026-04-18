"""Test reflection detection across security-sensitive contexts."""

from unittest.mock import MagicMock

from corsair.cache.reflect import detect_reflection


def _mock_response(body: str = "", headers: dict = None) -> MagicMock:
    resp = MagicMock()
    resp.text = body
    resp.headers = headers or {}
    return resp


class TestHeaderReflection:
    def test_location_header(self):
        resp = _mock_response(headers={"Location": "https://abc123.corsair-canary.invalid/login"})
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "location_header"

    def test_csp_header(self):
        resp = _mock_response(
            headers={"Content-Security-Policy": "default-src 'self' abc123.corsair-canary.invalid"}
        )
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "csp_header"

    def test_cors_header(self):
        resp = _mock_response(
            headers={"Access-Control-Allow-Origin": "https://abc123.corsair-canary.invalid"}
        )
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "cors_header"

    def test_no_reflection_in_headers(self):
        resp = _mock_response(headers={"Content-Type": "text/html", "Server": "nginx"})
        found, ctx = detect_reflection(resp, "abc123")
        assert found is False
        assert ctx is None


class TestBodyReflection:
    def test_script_src(self):
        body = '<html><script src="https://abc123.corsair-canary.invalid/app.js"></script></html>'
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "script_src"

    def test_link_href(self):
        body = '<link rel="stylesheet" href="https://abc123.corsair-canary.invalid/style.css">'
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "link_href"

    def test_canonical_href(self):
        body = '<link rel="canonical" href="https://abc123.corsair-canary.invalid/page">'
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "canonical_href"

    def test_meta_refresh(self):
        body = '<meta http-equiv="refresh" content="0;url=https://abc123.corsair-canary.invalid">'
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "meta_refresh"

    def test_img_src(self):
        body = '<img src="https://abc123.corsair-canary.invalid/image.png">'
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "img_src"

    def test_js_variable(self):
        body = '<script>var baseUrl = "https://abc123.corsair-canary.invalid";</script>'
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "js_variable"

    def test_body_text_fallback(self):
        body = "<html><body>Your IP is 1.2.3.abc123</body></html>"
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "body_text"

    def test_no_reflection(self):
        body = "<html><body>Hello World</body></html>"
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is False
        assert ctx is None

    def test_partial_canary_no_match(self):
        body = "<html><body>abc12 is not abc123</body></html>"
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123xyz")
        assert found is False
        assert ctx is None


class TestSeverityPriority:
    def test_script_src_beats_body_text(self):
        body = '<html><script src="https://abc123.corsair-canary.invalid/x.js"></script><body>abc123</body></html>'
        resp = _mock_response(body=body)
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "script_src"

    def test_csp_header_beats_body(self):
        body = "<html><body>abc123 appears here</body></html>"
        resp = _mock_response(
            body=body,
            headers={"Content-Security-Policy": "script-src abc123.example.com"},
        )
        found, ctx = detect_reflection(resp, "abc123")
        assert found is True
        assert ctx == "csp_header"
