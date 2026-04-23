"""CORSAuditor orchestration tests (Wave 1)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from corsair.cors.auditor import CORSAuditor
from corsair.cors.probe import ProbeResult
from corsair.models import Severity


def _mock_response(headers: dict = None, status_code: int = 200):
    resp = MagicMock()
    resp.headers = headers or {}
    resp.status_code = status_code
    resp.text = ""
    return resp


class TestCORSAuditorPassive:
    def test_passive_only_when_active_disabled(self):
        auditor = CORSAuditor(active=False)
        findings = auditor.audit(
            "https://example.com",
            {"Access-Control-Allow-Origin": "*"},
        )
        # Passive wildcard emits CORS_WILDCARD_CRED (if creds) or wildcard
        # finding; no probes fire.
        assert len(findings) >= 1
        assert all(f.category.value == "cors" for f in findings)

    def test_passive_no_cors_emits_pass(self):
        auditor = CORSAuditor(active=False)
        findings = auditor.audit("https://example.com", {})
        assert any(f.severity == Severity.PASS for f in findings)


class TestCORSAuditorActiveReflection:
    def test_arbitrary_origin_cred_fires_critical(self):
        auditor = CORSAuditor(active=True, evil_origin="https://evil.example")

        async def fake_get(*args, **kwargs):
            origin = kwargs.get("headers", {}).get("Origin")
            if origin == "https://evil.example":
                return _mock_response(
                    headers={
                        "Access-Control-Allow-Origin": "https://evil.example",
                        "Access-Control-Allow-Credentials": "true",
                        "Set-Cookie": "sess=abc",
                    }
                )
            return _mock_response()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=fake_get)
            mock_client.__aenter__.return_value = mock_client
            mock_client_cls.return_value = mock_client

            findings = auditor.audit("https://api.example.com", {})

        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert any("arbitrary origin" in f.title.lower() for f in critical)

    def test_null_origin_trusted_fires(self):
        auditor = CORSAuditor(active=True, evil_origin="https://evil.example")

        async def fake_get(*args, **kwargs):
            origin = kwargs.get("headers", {}).get("Origin")
            if origin == "null":
                return _mock_response(
                    headers={
                        "Access-Control-Allow-Origin": "null",
                        "Access-Control-Allow-Credentials": "true",
                    }
                )
            return _mock_response()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=fake_get)
            mock_client.__aenter__.return_value = mock_client
            mock_client_cls.return_value = mock_client

            findings = auditor.audit("https://api.example.com", {})

        assert any(f.title == "Null origin trusted with credentials" for f in findings)

    def test_no_reflection_no_active_findings(self):
        auditor = CORSAuditor(active=True, evil_origin="https://evil.example")

        async def fake_get(*args, **kwargs):
            return _mock_response(
                headers={"Access-Control-Allow-Origin": "https://trusted.example.com"}
            )

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=fake_get)
            mock_client.__aenter__.return_value = mock_client
            mock_client_cls.return_value = mock_client

            findings = auditor.audit("https://api.example.com", {})

        # Only passive PASS from initial header set (empty headers) — no
        # reflection findings.
        active_findings = [
            f for f in findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
        ]
        assert len(active_findings) == 0


class TestCORSAuditorAbortPath:
    def test_critical_finding_sets_abort_event(self):
        """When CORS_ARBITRARY_ORIGIN_CRED fires, the abort event is set."""
        auditor = CORSAuditor(active=True, evil_origin="https://evil.example")

        # Fast arbitrary probe triggers CRITICAL; null probe would be slow.
        async def fake_get(*args, **kwargs):
            origin = kwargs.get("headers", {}).get("Origin")
            if origin == "https://evil.example":
                return _mock_response(
                    headers={
                        "Access-Control-Allow-Origin": "https://evil.example",
                        "Access-Control-Allow-Credentials": "true",
                        "Set-Cookie": "x=1",
                    }
                )
            # null probe sleeps — should be cancelled via abort_event.
            await asyncio.sleep(3.0)
            return _mock_response()

        import time

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=fake_get)
            mock_client.__aenter__.return_value = mock_client
            mock_client_cls.return_value = mock_client

            start = time.monotonic()
            findings = auditor.audit("https://api.example.com", {})
            elapsed = time.monotonic() - start

        # Abort should keep total wall-clock well under the 3s null-probe sleep.
        assert elapsed < 2.5, f"Abort did not short-circuit: {elapsed:.2f}s"
        assert any(f.severity == Severity.CRITICAL for f in findings)


class TestCORSAuditorMetaFindings:
    def test_all_probes_auth_gated_emits_inconclusive(self):
        auditor = CORSAuditor(active=True, evil_origin="https://evil.example")

        async def fake_get(*args, **kwargs):
            return _mock_response(status_code=401)

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=fake_get)
            mock_client.__aenter__.return_value = mock_client
            mock_client_cls.return_value = mock_client

            findings = auditor.audit("https://api.example.com", {})

        assert any(
            f.title == "CORS probing inconclusive" for f in findings
        ), f"Expected CORS_PROBE_INCONCLUSIVE, got: {[f.title for f in findings]}"
