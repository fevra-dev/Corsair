"""Integration tests for FetchMetadataAuditor with mocked httpx.AsyncClient."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from corsair.fetch_metadata import FetchMetadataAuditor
from corsair.models import Severity


def _mock_response(status_code=200, headers=None, body=b"baseline body"):
    response = MagicMock()
    response.status_code = status_code
    response.headers = headers or {}
    response.content = body
    return response


def _audit_with_responses(url, baseline_headers, response_sequence):
    """response_sequence: list of (status, headers_dict, body_bytes) tuples
    delivered in the order probes are issued (B, S, A, C — order-independent
    because the auditor classifies on the labelled result, but the mock simply
    returns whatever AsyncMock yields next)."""
    auditor = FetchMetadataAuditor(active=True)
    responses = [_mock_response(s, h, b) for (s, h, b) in response_sequence]
    call_log = {"n": 0}

    async def fake_get(*args, **kwargs):
        n = call_log["n"]
        call_log["n"] = n + 1
        return responses[n]

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=fake_get)
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client_cls.return_value = mock_client
        return auditor.audit(url, baseline_headers)


class TestEnforcedEmitsPassFinding:
    def test_strict_4xx_emits_pass(self):
        # B=200, S=200, A=403, C=403 → ENFORCED.
        findings = _audit_with_responses(
            "https://api.example.com/v1",
            baseline_headers={},
            response_sequence=[
                (200, {}, b"baseline"),
                (200, {}, b"safe"),
                (403, {}, b"forbidden"),
                (403, {}, b"forbidden"),
            ],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS
        assert "Enforced" in findings[0].title or "enforced" in findings[0].title.lower()


class TestNotEnforcedNoCdnHigh:
    def test_no_cookies_no_cdn_high_severity(self):
        # All probes 200, no Set-Cookie, no CDN headers → HIGH.
        findings = _audit_with_responses(
            "https://api.example.com/v1",
            baseline_headers={},
            response_sequence=[
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
            ],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


class TestNotEnforcedWithCdnDowngrades:
    def test_cloudflare_downgrades_to_medium(self):
        # All probes 200, baseline CF headers → MEDIUM.
        findings = _audit_with_responses(
            "https://api.example.com/v1",
            baseline_headers={"cf-ray": "abc-123", "cf-cache-status": "DYNAMIC"},
            response_sequence=[
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
            ],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM


class TestInconclusiveWhenSafeRejects:
    def test_safe_rejected_emits_info(self):
        findings = _audit_with_responses(
            "https://api.example.com/v1",
            baseline_headers={},
            response_sequence=[
                (200, {}, b"baseline"),
                (403, {}, b"forbidden-by-blanket-rule"),
                (403, {}, b"forbidden"),
                (403, {}, b"forbidden"),
            ],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "Inconclusive" in findings[0].title


class TestSeverityMatrixViaCookies:
    def test_strict_session_and_csrf_token_low(self):
        baseline_headers = {
            "set-cookie": "sessionid=abc; SameSite=Strict; Secure; HttpOnly",
        }
        # Two cookies require two Set-Cookie headers via httpx multi-value.
        # Simulate that by stuffing both into a single header value separated
        # by the standard delimiter that the auditor must split on.
        findings = _audit_with_responses(
            "https://api.example.com/v1",
            baseline_headers={
                "set-cookie": "sessionid=abc; SameSite=Strict; Secure; HttpOnly, csrftoken=xyz; Secure",
            },
            response_sequence=[
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
            ],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_lax_session_only_medium(self):
        findings = _audit_with_responses(
            "https://api.example.com/v1",
            baseline_headers={
                "set-cookie": "sessionid=abc; SameSite=Lax; Secure; HttpOnly",
            },
            response_sequence=[
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
                (200, {}, b"baseline"),
            ],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM


class TestDisabledWhenActiveFalse:
    def test_active_false_returns_empty(self):
        auditor = FetchMetadataAuditor(active=False)
        result = auditor.audit("https://api.example.com/v1", {})
        assert result == []


class TestNetworkErrorEmitsInconclusive:
    def test_httpx_request_error_emits_inconclusive(self):
        import httpx

        auditor = FetchMetadataAuditor(active=True)

        async def fake_get(*args, **kwargs):
            raise httpx.RequestError("simulated network failure")

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=fake_get)
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_cls.return_value = mock_client

            findings = auditor.audit("https://api.example.com/v1", {})
            assert len(findings) == 1
            assert findings[0].severity == Severity.INFO
            assert "Network error" in findings[0].description or "network" in findings[0].description.lower()
