"""Reflection classifier and sensitivity heuristic tests."""

from corsair.cors.analyzers import (
    SensitivitySignal,
    classify_reflection,
    classify_sensitivity,
)
from corsair.cors.probe import ProbeResult


def _result(label="arbitrary_origin", origin="https://evil.example", **kwargs):
    kwargs.setdefault("status_code", 200)
    return ProbeResult(label=label, origin_sent=origin, **kwargs)


class TestClassifyReflection:
    def test_arbitrary_origin_reflected_with_creds_is_critical(self):
        r = _result(
            acao="https://evil.example",
            acac="true",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_ARBITRARY_ORIGIN_CRED"

    def test_arbitrary_origin_reflected_without_creds_is_high(self):
        r = _result(acao="https://evil.example")
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_ARBITRARY_ORIGIN"

    def test_null_origin_trusted_with_creds(self):
        r = _result(
            label="null_origin",
            origin="null",
            acao="null",
            acac="true",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_NULL_ORIGIN_CRED"

    def test_null_origin_trusted_without_creds(self):
        r = _result(label="null_origin", origin="null", acao="null")
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict.finding_id == "CORS_NULL_ORIGIN"

    def test_no_reflection_returns_none(self):
        r = _result(acao="https://trusted.example.com")
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None

    def test_acao_wildcard_is_not_a_reflection(self):
        # Wildcard is handled by the passive phase (CORS_WILDCARD_CRED),
        # not the reflection classifier.
        r = _result(acao="*", acac="true")
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None

    def test_no_acao_at_all_returns_none(self):
        r = _result(acao=None)
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None

    def test_error_probe_returns_none(self):
        r = ProbeResult(
            label="arbitrary_origin",
            origin_sent="https://evil.example",
            error="timeout",
        )
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None

    def test_auth_gate_status_returns_none(self):
        # 401/403 on the probe signals the endpoint is authenticated and our
        # anonymous probe cannot verdict it. Caller will emit
        # CORS_PROBE_INCONCLUSIVE based on the meta-aggregation.
        r = _result(acao="https://evil.example", acac="true", status_code=401)
        verdict = classify_reflection(r, evil_origin="https://evil.example")
        assert verdict is None


class TestSensitivityHeuristic:
    """4x2 truth table: 4 signals x (present, absent)."""

    # --- Signal 1: Set-Cookie on response
    def test_set_cookie_present_is_sensitive(self):
        r = _result(set_cookie="sessionid=abc123")
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.SENSITIVE

    def test_set_cookie_absent_is_unknown(self):
        r = _result()
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.UNKNOWN

    # --- Signal 2: Authorization header in request
    def test_authorization_header_present_is_sensitive(self):
        r = _result()
        signal = classify_sensitivity(r, request_headers={"Authorization": "Bearer xyz"})
        assert signal == SensitivitySignal.SENSITIVE

    def test_authorization_header_absent_is_unknown(self):
        r = _result()
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.UNKNOWN

    # --- Signal 3: JSON Content-Type
    def test_json_content_type_is_sensitive(self):
        r = _result(content_type="application/json; charset=utf-8")
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.SENSITIVE

    def test_vendor_json_content_type_is_sensitive(self):
        r = _result(content_type="application/vnd.api+json")
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.SENSITIVE

    def test_html_content_type_absent_json_is_unknown(self):
        r = _result(content_type="text/html; charset=utf-8")
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.UNKNOWN

    # --- Signal 4: Login redirect
    def test_login_redirect_is_sensitive(self):
        r = _result(status_code=302, location="https://target.example.com/login?next=/")
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.SENSITIVE

    def test_signin_redirect_is_sensitive(self):
        r = _result(status_code=303, location="/auth/signin")
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.SENSITIVE

    def test_sso_redirect_is_sensitive(self):
        r = _result(status_code=302, location="/sso/start")
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.SENSITIVE

    def test_non_auth_redirect_is_unknown(self):
        r = _result(status_code=302, location="/dashboard")
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.UNKNOWN

    # --- Combination: any signal present wins
    def test_multiple_signals_all_sensitive(self):
        r = _result(
            set_cookie="x=1",
            content_type="application/json",
        )
        signal = classify_sensitivity(
            r,
            request_headers={"Authorization": "Bearer z"},
        )
        assert signal == SensitivitySignal.SENSITIVE

    def test_no_signals_is_unknown(self):
        r = _result()
        signal = classify_sensitivity(r, request_headers={})
        assert signal == SensitivitySignal.UNKNOWN


class TestSeverityDowngradeIntegration:
    """classify_reflection should return the severity-adjusted finding ID."""

    def test_arbitrary_origin_cred_with_signals_stays_critical(self):
        r = _result(
            acao="https://evil.example",
            acac="true",
            set_cookie="sess=1",  # signal present
        )
        verdict = classify_reflection(
            r,
            evil_origin="https://evil.example",
            request_headers={},
        )
        assert verdict.finding_id == "CORS_ARBITRARY_ORIGIN_CRED"
        assert verdict.downgraded is False

    def test_arbitrary_origin_cred_without_signals_downgrades_to_high(self):
        # No Set-Cookie, no Authorization, no JSON, no login redirect
        # → downgrade CRITICAL → HIGH per spec §5.1.
        r = _result(acao="https://evil.example", acac="true")
        verdict = classify_reflection(
            r,
            evil_origin="https://evil.example",
            request_headers={},
        )
        assert verdict.finding_id == "CORS_ARBITRARY_ORIGIN_CRED"
        assert verdict.downgraded is True
        assert verdict.effective_severity.value == "HIGH"

    def test_arbitrary_origin_without_creds_downgrades_to_medium(self):
        # HIGH → MEDIUM when no signals.
        r = _result(acao="https://evil.example")
        verdict = classify_reflection(
            r,
            evil_origin="https://evil.example",
            request_headers={},
        )
        assert verdict.finding_id == "CORS_ARBITRARY_ORIGIN"
        assert verdict.downgraded is True
        assert verdict.effective_severity.value == "MEDIUM"
