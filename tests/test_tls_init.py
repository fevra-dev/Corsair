"""Test TLS module availability check."""

from corsair.tls import TLS_AVAILABLE, tls_available


class TestTLSAvailability:
    def test_tls_available_returns_bool(self):
        result = tls_available()
        assert isinstance(result, bool)

    def test_tls_available_matches_flag(self):
        assert tls_available() == TLS_AVAILABLE

    def test_tls_available_true_when_sslyze_installed(self):
        # sslyze is in dev deps, so it should be available in test env
        assert tls_available() is True
