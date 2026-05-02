"""Unit tests for corsair.fetch_metadata.probe."""

import hashlib

import pytest

from corsair.fetch_metadata.probe import (
    ADVERSARIAL_PROBE_HEADERS,
    AUTH_STATUS_CODES,
    CANARY_PROBE_HEADERS,
    ENFORCEMENT_STATUS_CODES,
    EnforcementResult,
    REDIRECT_STATUS_CODES,
    SAFE_PROBE_HEADERS,
    _body_hash,
    classify_enforcement,
)


# Reusable body hashes for clarity in tests.
BASELINE_BODY = _body_hash(b"baseline body content")
ADVERSARIAL_BODY = _body_hash(b"adversarial body content")
SAME_AS_BASELINE = BASELINE_BODY


class TestEnforcementStatusSet:
    def test_canonical_codes_present(self):
        assert {400, 403, 405, 451} <= ENFORCEMENT_STATUS_CODES

    def test_non_enforcement_codes_absent(self):
        for code in (200, 418, 429, 503):
            assert code not in ENFORCEMENT_STATUS_CODES

    def test_redirect_set(self):
        assert {301, 302, 303, 307, 308} <= REDIRECT_STATUS_CODES

    def test_auth_set(self):
        assert AUTH_STATUS_CODES == {401}


class TestProbeHeaderSets:
    def test_safe_keys_exact(self):
        assert set(SAFE_PROBE_HEADERS.keys()) == {
            "Sec-Fetch-Site",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Dest",
        }

    def test_safe_values(self):
        assert SAFE_PROBE_HEADERS["Sec-Fetch-Site"] == "same-origin"
        assert SAFE_PROBE_HEADERS["Sec-Fetch-Mode"] == "cors"
        assert SAFE_PROBE_HEADERS["Sec-Fetch-Dest"] == "empty"

    def test_adversarial_values(self):
        assert ADVERSARIAL_PROBE_HEADERS["Sec-Fetch-Site"] == "cross-site"
        assert ADVERSARIAL_PROBE_HEADERS["Sec-Fetch-Mode"] == "cors"
        assert ADVERSARIAL_PROBE_HEADERS["Sec-Fetch-Dest"] == "empty"

    def test_canary_value_literal(self):
        assert CANARY_PROBE_HEADERS["Sec-Fetch-Site"] == "corsair-canary-invalid"

    def test_no_origin_header_in_any_probe(self):
        for probe in (SAFE_PROBE_HEADERS, ADVERSARIAL_PROBE_HEADERS, CANARY_PROBE_HEADERS):
            assert "Origin" not in probe
            assert "origin" not in probe

    def test_no_referer_header_in_any_probe(self):
        for probe in (SAFE_PROBE_HEADERS, ADVERSARIAL_PROBE_HEADERS, CANARY_PROBE_HEADERS):
            assert "Referer" not in probe
            assert "referer" not in probe


class TestBodyHash:
    def test_identical_first_4kb_hash_match_despite_tail_difference(self):
        prefix = b"A" * 4096
        a = prefix + b"tail-one"
        b = prefix + b"tail-two-different-length"
        assert _body_hash(a) == _body_hash(b)

    def test_one_byte_difference_in_first_4kb_diverges(self):
        a = b"A" * 4096
        b = b"A" * 4095 + b"B"
        assert _body_hash(a) != _body_hash(b)

    def test_returns_sha256_hex_64_chars(self):
        h = _body_hash(b"hello")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


class TestClassifyEnforcement:
    """Each rule from spec §4.3, applied in order."""

    def test_rule1_safe_rejected_is_inconclusive(self):
        # Rule 1: safe blanket-rejects → INCONCLUSIVE regardless of A/C.
        result = classify_enforcement(
            baseline_status=200,
            safe_status=403,
            adversarial_status=403,
            canary_status=403,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=BASELINE_BODY,
        )
        assert result == EnforcementResult.INCONCLUSIVE

    def test_rule2_baseline_5xx_inconclusive(self):
        result = classify_enforcement(
            baseline_status=500,
            safe_status=200,
            adversarial_status=403,
            canary_status=403,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=ADVERSARIAL_BODY,
        )
        assert result == EnforcementResult.INCONCLUSIVE

    def test_rule2_baseline_401_inconclusive(self):
        result = classify_enforcement(
            baseline_status=401,
            safe_status=200,
            adversarial_status=403,
            canary_status=403,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=BASELINE_BODY,
        )
        assert result == EnforcementResult.INCONCLUSIVE

    def test_rule3_strict_enforcement(self):
        # Both A and C rejected → ENFORCED (strongest signal).
        result = classify_enforcement(
            baseline_status=200,
            safe_status=200,
            adversarial_status=403,
            canary_status=400,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=ADVERSARIAL_BODY,
        )
        assert result == EnforcementResult.ENFORCED

    def test_rule4_allowlist_enforcement_canary_2xx_body_match(self):
        # A=4xx, C=200 matching baseline body → ENFORCED (allowlist pattern).
        result = classify_enforcement(
            baseline_status=200,
            safe_status=200,
            adversarial_status=403,
            canary_status=200,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=ADVERSARIAL_BODY,
        )
        assert result == EnforcementResult.ENFORCED

    def test_rule5_redirect_on_adversarial_inconclusive(self):
        # A=302 with baseline=200 → likely auth, not FM.
        result = classify_enforcement(
            baseline_status=200,
            safe_status=200,
            adversarial_status=302,
            canary_status=200,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=BASELINE_BODY,
        )
        assert result == EnforcementResult.INCONCLUSIVE

    def test_rule6_soft_enforcement_2xx_body_differs(self):
        # A=2xx but body differs from baseline → SOFT_ENFORCED.
        result = classify_enforcement(
            baseline_status=200,
            safe_status=200,
            adversarial_status=200,
            canary_status=200,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=ADVERSARIAL_BODY,
        )
        assert result == EnforcementResult.SOFT_ENFORCED

    def test_rule7_clean_not_enforced(self):
        # A=B, C=B, body matches → NOT_ENFORCED.
        result = classify_enforcement(
            baseline_status=200,
            safe_status=200,
            adversarial_status=200,
            canary_status=200,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=BASELINE_BODY,
        )
        assert result == EnforcementResult.NOT_ENFORCED

    def test_rule8_unclassified_status_inconclusive(self):
        # A=418 (a teapot), nothing else applies → INCONCLUSIVE.
        result = classify_enforcement(
            baseline_status=200,
            safe_status=200,
            adversarial_status=418,
            canary_status=200,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=BASELINE_BODY,
        )
        assert result == EnforcementResult.INCONCLUSIVE

    def test_rule3_takes_precedence_over_rule6(self):
        # Even if A body differs, A=4xx and C=4xx wins as ENFORCED.
        result = classify_enforcement(
            baseline_status=200,
            safe_status=200,
            adversarial_status=403,
            canary_status=400,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=ADVERSARIAL_BODY,
        )
        assert result == EnforcementResult.ENFORCED

    def test_rule1_takes_precedence_over_rule2(self):
        # Safe rejection wins even if baseline is also 500.
        result = classify_enforcement(
            baseline_status=500,
            safe_status=403,
            adversarial_status=403,
            canary_status=403,
            baseline_body_hash=BASELINE_BODY,
            adversarial_body_hash=BASELINE_BODY,
        )
        assert result == EnforcementResult.INCONCLUSIVE
