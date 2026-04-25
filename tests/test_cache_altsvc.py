"""Unit tests for corsair.cache.altsvc."""

from corsair.cache.altsvc import AltSvcEntry, detect_alt_svc_canary, parse_alt_svc


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
