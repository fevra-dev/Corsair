"""Tests for corsair.h3.probe."""

import pytest

from corsair.h3.probe import derive_h3_target, is_lsquic_fingerprint


# ---------------------------------------------------------------------------
# derive_h3_target
# ---------------------------------------------------------------------------

class TestDeriveH3Target:
    def test_no_alt_svc_returns_none(self):
        assert derive_h3_target({}, "example.com") is None

    def test_empty_alt_svc_returns_none(self):
        assert derive_h3_target({"Alt-Svc": ""}, "example.com") is None

    def test_clear_alt_svc_returns_none(self):
        assert derive_h3_target({"Alt-Svc": "clear"}, "example.com") is None

    def test_h3_explicit_host_and_port(self):
        headers = {"Alt-Svc": 'h3="alt.example.com:8443"; ma=86400'}
        assert derive_h3_target(headers, "example.com") == ("alt.example.com", 8443)

    def test_h3_omitted_host_falls_back_to_request_host(self):
        # ":443" with no host means "same host as request, port 443"
        headers = {"Alt-Svc": 'h3=":443"; ma=86400'}
        assert derive_h3_target(headers, "example.com") == ("example.com", 443)

    def test_h3_29_draft_protocol_id(self):
        headers = {"Alt-Svc": 'h3-29=":443"; ma=86400'}
        assert derive_h3_target(headers, "example.com") == ("example.com", 443)

    def test_h3_with_other_protocols_picks_h3_first(self):
        # Even if h2 appears earlier, we want the h3 entry
        headers = {"Alt-Svc": 'h2=":443"; ma=86400, h3=":8443"; ma=86400'}
        assert derive_h3_target(headers, "example.com") == ("example.com", 8443)

    def test_no_h3_returns_none(self):
        headers = {"Alt-Svc": 'h2=":443"; ma=86400'}
        assert derive_h3_target(headers, "example.com") is None

    def test_malformed_alt_svc_returns_none(self):
        headers = {"Alt-Svc": "this is not valid alt-svc"}
        assert derive_h3_target(headers, "example.com") is None

    def test_case_insensitive_header_lookup(self):
        # Real-world headers can come back with various casing
        headers = {"alt-svc": 'h3=":443"; ma=86400'}
        assert derive_h3_target(headers, "example.com") == ("example.com", 443)

    def test_picks_first_h3_entry_when_multiple(self):
        headers = {
            "Alt-Svc": 'h3=":443", h3=":8443"',
        }
        assert derive_h3_target(headers, "example.com") == ("example.com", 443)


# ---------------------------------------------------------------------------
# is_lsquic_fingerprint
# ---------------------------------------------------------------------------

class TestLSQUICFingerprint:
    def test_litespeed_with_h3_advertisement(self):
        headers = {"Server": "LiteSpeed/6.0"}
        assert is_lsquic_fingerprint(headers, has_h3_advertisement=True) is True

    def test_openlitespeed_with_h3_advertisement(self):
        headers = {"Server": "OpenLiteSpeed/1.7.18"}
        assert is_lsquic_fingerprint(headers, has_h3_advertisement=True) is True

    def test_litespeed_case_insensitive(self):
        headers = {"Server": "litespeed"}
        assert is_lsquic_fingerprint(headers, has_h3_advertisement=True) is True

    def test_no_h3_advertisement_means_false(self):
        # Even if Server matches, no h3 means we don't have evidence the
        # vulnerable QUIC stack is actually serving HTTP/3 here.
        headers = {"Server": "LiteSpeed/6.0"}
        assert is_lsquic_fingerprint(headers, has_h3_advertisement=False) is False

    def test_word_boundary_prevents_false_positive(self):
        # "LiteSpeedAdapter" is a real Apache module — must NOT match
        headers = {"Server": "Apache/2.4 (LiteSpeedAdapter)"}
        assert is_lsquic_fingerprint(headers, has_h3_advertisement=True) is False

    def test_lsws_alone_does_not_match(self):
        # LSWS abbreviation is not the regex target
        headers = {"Server": "LSWS"}
        assert is_lsquic_fingerprint(headers, has_h3_advertisement=True) is False

    def test_other_servers_do_not_match(self):
        for s in ("nginx/1.27", "Cloudflare", "Caddy/2.7", "Apache/2.4", "Microsoft-IIS/10.0"):
            headers = {"Server": s}
            assert is_lsquic_fingerprint(headers, has_h3_advertisement=True) is False

    def test_missing_server_header(self):
        assert is_lsquic_fingerprint({}, has_h3_advertisement=True) is False

    def test_empty_server_header(self):
        assert is_lsquic_fingerprint({"Server": ""}, has_h3_advertisement=True) is False

    def test_case_insensitive_header_lookup(self):
        headers = {"server": "LiteSpeed/6.0"}
        assert is_lsquic_fingerprint(headers, has_h3_advertisement=True) is True
