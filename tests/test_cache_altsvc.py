"""Unit tests for corsair.cache.altsvc."""

from corsair.cache.altsvc import (
    AltSvcEntry,
    analyze_alt_svc_suspicious,
    detect_alt_svc_canary,
    parse_alt_svc,
)


class TestParseAltSvc:
    def test_port_only_authority(self):
        entries = parse_alt_svc('h3=":443"; ma=86400')
        assert entries == [AltSvcEntry(protocol_id="h3", host=None, port=443, ma=86400, persist=False)]

    def test_host_port_ma_persist(self):
        entries = parse_alt_svc('h3="cdn.example.com:443"; ma=3600; persist=1')
        assert entries == [
            AltSvcEntry(protocol_id="h3", host="cdn.example.com", port=443, ma=3600, persist=True)
        ]

    def test_multi_value_order_preserved(self):
        entries = parse_alt_svc('h2="a:443", h3="b.example.com:443"; ma=60')
        assert len(entries) == 2
        assert entries[0].protocol_id == "h2"
        assert entries[0].host == "a"
        assert entries[1].protocol_id == "h3"
        assert entries[1].host == "b.example.com"

    def test_draft_protocol_id(self):
        entries = parse_alt_svc('h3-29=":443"')
        assert entries[0].protocol_id == "h3-29"

    def test_clear_directive(self):
        assert parse_alt_svc("clear") == []

    def test_empty_and_whitespace(self):
        assert parse_alt_svc("") == []
        assert parse_alt_svc("   ") == []

    def test_malformed_no_exception(self):
        # Unclosed quote, missing equals — must return [], not raise.
        assert parse_alt_svc('h3="foo:443') == []
        assert parse_alt_svc('h3 ":443"') == []

    def test_unknown_parameters_ignored(self):
        entries = parse_alt_svc('h3=":443"; ma=60; foo=bar; persist=1')
        assert entries == [AltSvcEntry(protocol_id="h3", host=None, port=443, ma=60, persist=True)]


class TestDetectAltSvcCanary:
    CANARY = "x9k3p7q1.invalid"

    def test_canary_in_single_entry_host(self):
        value = f'h3="{self.CANARY}:443"; ma=60'
        assert detect_alt_svc_canary(value, self.CANARY) is True

    def test_canary_in_second_entry_of_multi_value(self):
        value = f'h2="origin:443", h3="{self.CANARY}:443"'
        assert detect_alt_svc_canary(value, self.CANARY) is True

    def test_clear_directive_returns_false(self):
        assert detect_alt_svc_canary("clear", self.CANARY) is False

    def test_empty_returns_false(self):
        assert detect_alt_svc_canary("", self.CANARY) is False
        assert detect_alt_svc_canary("   ", self.CANARY) is False

    def test_canary_absent_returns_false(self):
        assert detect_alt_svc_canary('h3="cdn.example.com:443"', self.CANARY) is False


class TestCrossDomain:
    def test_different_registrable_domain_emits(self):
        ids = analyze_alt_svc_suspicious('h3="evil.net:443"', "api.example.com")
        assert "WCP_ALT_SVC_CROSS_DOMAIN" in ids

    def test_same_registrable_domain_no_emit(self):
        ids = analyze_alt_svc_suspicious('h3="h3.example.com:443"', "api.example.com")
        assert "WCP_ALT_SVC_CROSS_DOMAIN" not in ids

    def test_psl_multilabel_tld_no_emit(self):
        ids = analyze_alt_svc_suspicious('h3="cdn.example.co.uk:443"', "api.example.co.uk")
        assert "WCP_ALT_SVC_CROSS_DOMAIN" not in ids

    def test_psl_multilabel_tld_cross_domain_emits(self):
        ids = analyze_alt_svc_suspicious('h3="example.co.uk:443"', "api.example.com")
        assert "WCP_ALT_SVC_CROSS_DOMAIN" in ids

    def test_port_only_authority_no_emit(self):
        ids = analyze_alt_svc_suspicious('h3=":443"', "api.example.com")
        assert "WCP_ALT_SVC_CROSS_DOMAIN" not in ids


class TestPrivateHost:
    def test_loopback_ipv4_emits(self):
        ids = analyze_alt_svc_suspicious('h3="127.0.0.1:443"', "api.example.com")
        assert "WCP_ALT_SVC_PRIVATE_HOST" in ids

    def test_rfc1918_emits(self):
        for host in ("10.0.0.1", "192.168.1.1", "172.16.0.1"):
            ids = analyze_alt_svc_suspicious(f'h3="{host}:443"', "api.example.com")
            assert "WCP_ALT_SVC_PRIVATE_HOST" in ids, host

    def test_ipv6_loopback_and_linklocal_emit(self):
        for host in ("[::1]", "[fe80::1]"):
            ids = analyze_alt_svc_suspicious(f'h3="{host}:443"', "api.example.com")
            assert "WCP_ALT_SVC_PRIVATE_HOST" in ids, host

    def test_reserved_tlds_emit(self):
        for host in ("server.local", "db.internal", "x.invalid", "x.localhost", "x.test", "x.example"):
            ids = analyze_alt_svc_suspicious(f'h3="{host}:443"', "api.example.com")
            assert "WCP_ALT_SVC_PRIVATE_HOST" in ids, host

    def test_bare_hostname_emits(self):
        ids = analyze_alt_svc_suspicious('h3="corp-server:443"', "api.example.com")
        assert "WCP_ALT_SVC_PRIVATE_HOST" in ids

    def test_public_hostname_no_emit(self):
        ids = analyze_alt_svc_suspicious('h3="cdn.example.com:443"', "api.example.com")
        assert "WCP_ALT_SVC_PRIVATE_HOST" not in ids


class TestExcessivePersistence:
    def test_above_30d_with_persist_emits(self):
        ids = analyze_alt_svc_suspicious('h3=":443"; ma=2592001; persist=1', "api.example.com")
        assert "WCP_ALT_SVC_EXCESSIVE_PERSISTENCE" in ids

    def test_exactly_30d_with_persist_no_emit(self):
        ids = analyze_alt_svc_suspicious('h3=":443"; ma=2592000; persist=1', "api.example.com")
        assert "WCP_ALT_SVC_EXCESSIVE_PERSISTENCE" not in ids

    def test_long_ma_without_persist_no_emit(self):
        ids = analyze_alt_svc_suspicious('h3=":443"; ma=31536000', "api.example.com")
        assert "WCP_ALT_SVC_EXCESSIVE_PERSISTENCE" not in ids

    def test_persist_with_default_ma_no_emit(self):
        ids = analyze_alt_svc_suspicious('h3=":443"; persist=1', "api.example.com")
        assert "WCP_ALT_SVC_EXCESSIVE_PERSISTENCE" not in ids
