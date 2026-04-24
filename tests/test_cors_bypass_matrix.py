"""Golden-file tests for the Wave 2 bypass matrix."""

from corsair.cors.probe import build_bypass_matrix, build_probes


class TestBuildBypassMatrix:
    def test_matrix_for_host_api_example_com(self):
        """Golden: exact payload set for api.example.com."""
        probes = build_bypass_matrix(
            url="https://api.example.com/v1/data",
            host="api.example.com",
        )
        origins_and_labels = [(p.origin, p.label) for p in probes]

        expected = [
            # Subdomain/regex bypass patterns
            ("https://evil.api.example.com", "subdomain_evil_prefix"),
            ("https://api.example.com.evil.com", "subdomain_attacker_suffix"),
            ("https://apiXexampleXcom.evil.com", "subdomain_dot_confusion"),
            ("https://api.example.com.evil", "subdomain_tld_confusion"),
            ("https://anysub.api.example.com", "subdomain_wildcard"),
            ("https://api-evil.example.com", "subdomain_contains_match"),
            # Protocol downgrade (HTTPS target → http:// origin)
            ("http://api.example.com", "protocol_downgrade"),
            # Internal/private origins
            ("http://127.0.0.1", "internal_loopback_ip"),
            ("http://localhost", "internal_loopback_name"),
            ("http://10.0.0.1", "internal_rfc1918_10"),
            ("http://192.168.0.1", "internal_rfc1918_192"),
        ]
        assert origins_and_labels == expected, (
            f"Matrix drift. got={origins_and_labels} expected={expected}"
        )

    def test_each_probe_has_unique_cache_buster(self):
        probes = build_bypass_matrix(
            url="https://api.example.com/",
            host="api.example.com",
        )
        busters = [p.cache_buster for p in probes]
        assert len(set(busters)) == len(busters)
        assert all(len(b) == 16 for b in busters)

    def test_all_probes_target_same_url(self):
        url = "https://api.example.com/v1/data?x=1"
        probes = build_bypass_matrix(url=url, host="api.example.com")
        assert all(p.url == url for p in probes)


class TestBuildProbesIncludesMatrix:
    def test_http_target_omits_protocol_downgrade(self):
        """Protocol-downgrade only makes sense when target is HTTPS."""
        probes = build_probes(
            url="http://plain.example.com/",
            evil_origin="https://evil.example",
        )
        labels = [p.label for p in probes]
        assert "protocol_downgrade" not in labels

    def test_https_target_includes_protocol_downgrade(self):
        probes = build_probes(
            url="https://secure.example.com/",
            evil_origin="https://evil.example",
        )
        labels = [p.label for p in probes]
        assert "protocol_downgrade" in labels

    def test_build_probes_includes_wave1_plus_wave2(self):
        probes = build_probes(
            url="https://api.example.com/",
            evil_origin="https://evil.example",
        )
        labels = set(p.label for p in probes)
        # Wave 1
        assert "arbitrary_origin" in labels
        assert "null_origin" in labels
        # Wave 2 (a representative sample — full list locked in
        # TestBuildBypassMatrix.test_matrix_for_host_api_example_com).
        assert "subdomain_evil_prefix" in labels
        assert "internal_loopback_ip" in labels
