"""End-to-end CORSAuditor tests for Wave 2 findings."""

from unittest.mock import AsyncMock, MagicMock, patch

from corsair.cors.auditor import CORSAuditor
from corsair.models import Severity


def _mock_response(headers=None, status_code=200):
    resp = MagicMock()
    resp.headers = headers or {}
    resp.status_code = status_code
    resp.text = ""
    return resp


def _audit_with_reflection(reflect_for_origin: str, headers_extra=None):
    """Helper: run auditor where ACAO reflects `reflect_for_origin` exactly.

    All other probes return a non-reflecting response so only the intended
    verdict fires.
    """
    headers_extra = headers_extra or {}
    auditor = CORSAuditor(active=True, evil_origin="https://evil.example")

    async def fake_get(*args, **kwargs):
        origin = kwargs.get("headers", {}).get("Origin")
        if origin == reflect_for_origin:
            hdrs = {
                "Access-Control-Allow-Origin": reflect_for_origin,
                **headers_extra,
            }
            return _mock_response(headers=hdrs)
        return _mock_response()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=fake_get)
        mock_client.__aenter__.return_value = mock_client
        mock_client_cls.return_value = mock_client

        return auditor.audit("https://api.example.com/v1", {})


class TestSubdomainBypassEndToEnd:
    def test_evil_prefix_fires(self):
        findings = _audit_with_reflection(
            "https://evil.api.example.com",
            headers_extra={"Set-Cookie": "sess=1"},
        )
        titles = [f.title for f in findings]
        assert "Subdomain or regex bypass reflected" in titles

    def test_subdomain_bypass_without_signals_downgrades_to_medium(self):
        findings = _audit_with_reflection("https://evil.api.example.com")
        bypass = [
            f for f in findings
            if f.title == "Subdomain or regex bypass reflected"
        ]
        assert len(bypass) == 1
        assert bypass[0].severity == Severity.MEDIUM
        assert "downgraded" in bypass[0].description.lower()


class TestProtocolDowngradeEndToEnd:
    def test_http_origin_reflected_fires(self):
        findings = _audit_with_reflection("http://api.example.com")
        titles = [f.title for f in findings]
        assert "HTTP origin trusted on HTTPS target" in titles

    def test_protocol_downgrade_stays_high_without_signals(self):
        findings = _audit_with_reflection("http://api.example.com")
        pd = [
            f for f in findings
            if f.title == "HTTP origin trusted on HTTPS target"
        ]
        assert len(pd) == 1
        assert pd[0].severity == Severity.HIGH


class TestInternalOriginEndToEnd:
    def test_loopback_reflected_fires(self):
        findings = _audit_with_reflection("http://127.0.0.1")
        titles = [f.title for f in findings]
        assert "Internal or private-network origin trusted" in titles

    def test_rfc1918_reflected_fires(self):
        findings = _audit_with_reflection("http://10.0.0.1")
        titles = [f.title for f in findings]
        assert "Internal or private-network origin trusted" in titles


class TestWave2CurrentValueIsPopulated:
    def test_current_value_includes_origin_and_acao(self):
        findings = _audit_with_reflection("http://127.0.0.1")
        f = [
            x for x in findings
            if x.title == "Internal or private-network origin trusted"
        ][0]
        assert "http://127.0.0.1" in (f.current_value or "")
        assert "ACAO" in (f.current_value or "")
