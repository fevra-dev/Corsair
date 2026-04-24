"""Classifier tests for Wave 2 bypass reflections."""

from corsair.cors.analyzers import classify_reflection
from corsair.cors.probe import ProbeResult


def _result(label, origin, acao, acac=None, **kwargs):
    kwargs.setdefault("status_code", 200)
    return ProbeResult(
        label=label,
        origin_sent=origin,
        acao=acao,
        acac=acac,
        **kwargs,
    )


class TestSubdomainBypass:
    def test_evil_prefix_reflected_is_subdomain_bypass(self):
        r = _result(
            label="subdomain_evil_prefix",
            origin="https://evil.api.example.com",
            acao="https://evil.api.example.com",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is not None
        assert verdict.finding_id == "CORS_SUBDOMAIN_BYPASS"
        assert verdict.default_severity.value == "HIGH"

    def test_attacker_suffix_reflected(self):
        r = _result(
            label="subdomain_attacker_suffix",
            origin="https://api.example.com.evil.com",
            acao="https://api.example.com.evil.com",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_SUBDOMAIN_BYPASS"

    def test_dot_confusion_reflected(self):
        r = _result(
            label="subdomain_dot_confusion",
            origin="https://apiXexampleXcom.evil.com",
            acao="https://apiXexampleXcom.evil.com",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_SUBDOMAIN_BYPASS"

    def test_subdomain_bypass_without_signals_downgrades(self):
        # No Set-Cookie, no Auth header, no JSON, no login redirect → MEDIUM.
        r = _result(
            label="subdomain_evil_prefix",
            origin="https://evil.api.example.com",
            acao="https://evil.api.example.com",
        )
        verdict = classify_reflection(
            r,
            evil_origin="https://evil.example",
            request_headers={},
        )
        assert verdict.downgraded is True
        assert verdict.effective_severity.value == "MEDIUM"

    def test_subdomain_bypass_with_set_cookie_stays_high(self):
        r = _result(
            label="subdomain_evil_prefix",
            origin="https://evil.api.example.com",
            acao="https://evil.api.example.com",
            set_cookie="sess=abc",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.downgraded is False
        assert verdict.effective_severity.value == "HIGH"

    def test_no_reflection_returns_none(self):
        r = _result(
            label="subdomain_evil_prefix",
            origin="https://evil.api.example.com",
            acao="https://trusted.example.com",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None


class TestProtocolDowngrade:
    def test_http_origin_reflected_is_protocol_downgrade(self):
        r = _result(
            label="protocol_downgrade",
            origin="http://api.example.com",
            acao="http://api.example.com",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is not None
        assert verdict.finding_id == "CORS_PROTOCOL_DOWNGRADE"
        assert verdict.effective_severity.value == "HIGH"

    def test_protocol_downgrade_does_not_downgrade_severity(self):
        # Spec §5: only CORS_ARBITRARY_* and CORS_SUBDOMAIN_BYPASS downgrade.
        r = _result(
            label="protocol_downgrade",
            origin="http://api.example.com",
            acao="http://api.example.com",
        )
        verdict = classify_reflection(
            r,
            evil_origin="https://evil.example",
            request_headers={},
        )
        assert verdict.downgraded is False
        assert verdict.effective_severity.value == "HIGH"

    def test_no_match_when_acao_differs(self):
        r = _result(
            label="protocol_downgrade",
            origin="http://api.example.com",
            acao="https://api.example.com",  # server upgraded scheme — not a bypass
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None


class TestInternalOrigin:
    def test_loopback_ip_reflected(self):
        r = _result(
            label="internal_loopback_ip",
            origin="http://127.0.0.1",
            acao="http://127.0.0.1",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_INTERNAL_ORIGIN"

    def test_loopback_name_reflected(self):
        r = _result(
            label="internal_loopback_name",
            origin="http://localhost",
            acao="http://localhost",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_INTERNAL_ORIGIN"

    def test_rfc1918_10_reflected(self):
        r = _result(
            label="internal_rfc1918_10",
            origin="http://10.0.0.1",
            acao="http://10.0.0.1",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_INTERNAL_ORIGIN"

    def test_rfc1918_192_reflected(self):
        r = _result(
            label="internal_rfc1918_192",
            origin="http://192.168.0.1",
            acao="http://192.168.0.1",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_INTERNAL_ORIGIN"

    def test_internal_origin_does_not_downgrade(self):
        r = _result(
            label="internal_loopback_ip",
            origin="http://127.0.0.1",
            acao="http://127.0.0.1",
        )
        verdict = classify_reflection(
            r,
            evil_origin="https://evil.example",
            request_headers={},
        )
        assert verdict.downgraded is False
        assert verdict.effective_severity.value == "HIGH"


class TestWave1Unaffected:
    """Regression: Wave 1 classifier paths must still return the same verdicts."""

    def test_arbitrary_origin_still_fires(self):
        r = _result(
            label="arbitrary_origin",
            origin="https://evil.example",
            acao="https://evil.example",
            acac="true",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_ARBITRARY_ORIGIN_CRED"

    def test_null_origin_still_fires(self):
        r = _result(
            label="null_origin",
            origin="null",
            acao="null",
            acac="true",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_NULL_ORIGIN_CRED"

    def test_wildcard_still_skipped(self):
        r = _result(
            label="arbitrary_origin",
            origin="https://evil.example",
            acao="*",
            acac="true",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None

    def test_auth_gate_still_skipped(self):
        r = _result(
            label="subdomain_evil_prefix",
            origin="https://evil.api.example.com",
            acao="https://evil.api.example.com",
            status_code=401,
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None
