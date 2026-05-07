"""Tests for corsair.h3.diff."""

import pytest

from corsair.h3.diff import (
    HeaderDiffResult,
    SECURITY_HEADER_ALLOWLIST,
    diff_security_headers,
)


# ---------------------------------------------------------------------------
# Allowlist sanity
# ---------------------------------------------------------------------------

class TestAllowlist:
    def test_allowlist_contains_critical_headers(self):
        for h in (
            "strict-transport-security",
            "content-security-policy",
            "cross-origin-opener-policy",
            "cross-origin-embedder-policy",
            "x-frame-options",
            "x-content-type-options",
            "permissions-policy",
            "integrity-policy",
            "reporting-endpoints",
            "document-isolation-policy",
        ):
            assert h in SECURITY_HEADER_ALLOWLIST, f"missing: {h}"

    def test_allowlist_keys_all_lowercase(self):
        for h in SECURITY_HEADER_ALLOWLIST:
            assert h == h.lower(), f"non-lowercase: {h}"


# ---------------------------------------------------------------------------
# diff_security_headers
# ---------------------------------------------------------------------------

class TestDiffSecurityHeaders:
    def test_identical_headers_return_empty_result(self):
        h1 = {"Strict-Transport-Security": "max-age=31536000"}
        h3 = {"Strict-Transport-Security": "max-age=31536000"}
        result = diff_security_headers(h1, h3)
        assert result.missing_in_h3 == []
        assert result.missing_in_h1 == []
        assert result.value_drift == []

    def test_missing_in_h3(self):
        h1 = {"Strict-Transport-Security": "max-age=31536000"}
        h3 = {}
        result = diff_security_headers(h1, h3)
        assert result.missing_in_h3 == ["Strict-Transport-Security"]
        assert result.missing_in_h1 == []
        assert result.value_drift == []

    def test_missing_in_h1(self):
        h1 = {}
        h3 = {"Strict-Transport-Security": "max-age=31536000"}
        result = diff_security_headers(h1, h3)
        assert result.missing_in_h3 == []
        assert result.missing_in_h1 == ["Strict-Transport-Security"]
        assert result.value_drift == []

    def test_value_drift(self):
        h1 = {"Strict-Transport-Security": "max-age=31536000"}
        h3 = {"Strict-Transport-Security": "max-age=0"}
        result = diff_security_headers(h1, h3)
        assert result.missing_in_h3 == []
        assert result.missing_in_h1 == []
        assert result.value_drift == [
            ("Strict-Transport-Security", "max-age=31536000", "max-age=0"),
        ]

    def test_multiple_missing_sorted(self):
        h1 = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
        }
        h3 = {}
        result = diff_security_headers(h1, h3)
        # Output is sorted for deterministic finding text
        assert result.missing_in_h3 == sorted([
            "Strict-Transport-Security",
            "X-Frame-Options",
            "Content-Security-Policy",
        ])

    def test_case_insensitive_header_keys(self):
        # Headers may come back with different casing on each protocol.
        # Lowercased internally for comparison; output preserves H1 casing.
        h1 = {"strict-transport-security": "max-age=31536000"}
        h3 = {"STRICT-TRANSPORT-SECURITY": "max-age=31536000"}
        result = diff_security_headers(h1, h3)
        assert result.missing_in_h3 == []
        assert result.missing_in_h1 == []
        assert result.value_drift == []

    def test_value_comparison_is_case_sensitive(self):
        # "max-age=0" vs "MAX-AGE=0" is a real misconfig shape worth flagging
        h1 = {"Strict-Transport-Security": "max-age=0"}
        h3 = {"Strict-Transport-Security": "MAX-AGE=0"}
        result = diff_security_headers(h1, h3)
        assert len(result.value_drift) == 1

    def test_non_allowlist_headers_ignored(self):
        # Server, Date, Content-Length etc. legitimately differ — not flagged.
        h1 = {"Date": "Wed, 07 May 2026 12:00:00 GMT", "Server": "nginx"}
        h3 = {"Date": "Wed, 07 May 2026 12:00:01 GMT", "Server": "nginx-quic"}
        result = diff_security_headers(h1, h3)
        assert result.missing_in_h3 == []
        assert result.missing_in_h1 == []
        assert result.value_drift == []

    def test_combined_drift_modes(self):
        h1 = {
            "Strict-Transport-Security": "max-age=31536000",  # value drift
            "X-Frame-Options": "DENY",                         # missing in h3
        }
        h3 = {
            "Strict-Transport-Security": "max-age=0",
            "Cross-Origin-Opener-Policy": "same-origin",       # missing in h1
        }
        result = diff_security_headers(h1, h3)
        assert result.missing_in_h3 == ["X-Frame-Options"]
        assert result.missing_in_h1 == ["Cross-Origin-Opener-Policy"]
        assert result.value_drift == [
            ("Strict-Transport-Security", "max-age=31536000", "max-age=0"),
        ]

    def test_value_drift_output_sorted_by_header_name(self):
        h1 = {
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
        }
        h3 = {
            "X-Frame-Options": "SAMEORIGIN",
            "Strict-Transport-Security": "max-age=0",
        }
        result = diff_security_headers(h1, h3)
        names = [t[0] for t in result.value_drift]
        assert names == sorted(names)
