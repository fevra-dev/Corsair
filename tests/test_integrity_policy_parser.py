"""Tests for corsair.integrity_policy.parser."""

import pytest

from corsair.integrity_policy.parser import (
    _is_html_response,
    _parse_integrity_policy,
)


# ---------------------------------------------------------------------------
# _parse_integrity_policy — empty / whitespace inputs
# ---------------------------------------------------------------------------

class TestParseEmptyInputs:
    def test_empty_string_returns_parse_error(self):
        result = _parse_integrity_policy("")
        assert result["parse_error"] is True
        assert result["blocked_destinations"] == []
        assert result["sources"] == ["inline"]
        assert result["endpoints"] == []

    def test_whitespace_only_returns_parse_error(self):
        result = _parse_integrity_policy("   ")
        assert result["parse_error"] is True
        assert result["blocked_destinations"] == []

    def test_garbage_input_returns_parse_error(self):
        result = _parse_integrity_policy("not_valid_sf!!!")
        assert result["parse_error"] is True


class TestParseValidGrammars:
    def test_blocked_destinations_only(self):
        result = _parse_integrity_policy("blocked-destinations=(script)")
        assert result["parse_error"] is False
        assert result["blocked_destinations"] == ["script"]
        assert result["sources"] == ["inline"]
        assert result["endpoints"] == []

    def test_blocked_destinations_two_tokens(self):
        result = _parse_integrity_policy("blocked-destinations=(script style)")
        assert result["blocked_destinations"] == ["script", "style"]

    def test_blocked_destinations_with_endpoints(self):
        result = _parse_integrity_policy(
            "blocked-destinations=(script), endpoints=(sri)"
        )
        assert result["blocked_destinations"] == ["script"]
        assert result["endpoints"] == ["sri"]

    def test_explicit_sources_inline(self):
        result = _parse_integrity_policy(
            "blocked-destinations=(script), sources=(inline)"
        )
        assert result["sources"] == ["inline"]

    def test_all_three_keys_present(self):
        result = _parse_integrity_policy(
            "blocked-destinations=(script style), sources=(inline), endpoints=(sri main)"
        )
        assert result["blocked_destinations"] == ["script", "style"]
        assert result["sources"] == ["inline"]
        assert result["endpoints"] == ["sri", "main"]

    def test_multiple_endpoint_tokens(self):
        result = _parse_integrity_policy(
            "blocked-destinations=(script), endpoints=(ep1 ep2 ep3)"
        )
        assert result["endpoints"] == ["ep1", "ep2", "ep3"]

    def test_keys_in_any_order(self):
        result = _parse_integrity_policy(
            "endpoints=(sri), blocked-destinations=(script)"
        )
        assert result["blocked_destinations"] == ["script"]
        assert result["endpoints"] == ["sri"]

    def test_trailing_comma_does_not_break_parse(self):
        result = _parse_integrity_policy("blocked-destinations=(script),")
        assert result["parse_error"] is False
        assert result["blocked_destinations"] == ["script"]


class TestParseWhitespace:
    def test_inner_whitespace_around_token(self):
        result = _parse_integrity_policy("blocked-destinations=( script )")
        assert result["blocked_destinations"] == ["script"]

    def test_whitespace_around_equals(self):
        result = _parse_integrity_policy("blocked-destinations =(script)")
        assert result["blocked_destinations"] == ["script"]

    def test_leading_trailing_whitespace_on_value(self):
        result = _parse_integrity_policy("   blocked-destinations=(script)   ")
        assert result["blocked_destinations"] == ["script"]


class TestParseEmptyDestinations:
    def test_empty_inner_list(self):
        result = _parse_integrity_policy("blocked-destinations=()")
        assert result["parse_error"] is False
        assert result["blocked_destinations"] == []

    def test_missing_blocked_destinations_key(self):
        result = _parse_integrity_policy("sources=(inline)")
        assert result["parse_error"] is False
        assert result["blocked_destinations"] == []
        assert result["sources"] == ["inline"]


class TestParseUnknownTokens:
    def test_all_unknown_tokens(self):
        result = _parse_integrity_policy("blocked-destinations=(scripts foo)")
        assert result["parse_error"] is False
        assert result["blocked_destinations"] == ["scripts", "foo"]

    def test_recognized_plus_unknown_tokens(self):
        result = _parse_integrity_policy(
            "blocked-destinations=(script futureKind)"
        )
        assert result["parse_error"] is False
        assert "script" in result["blocked_destinations"]
        assert "futurekind" in result["blocked_destinations"]


class TestParseMalformed:
    def test_unmatched_open_paren(self):
        result = _parse_integrity_policy("blocked-destinations=(script")
        assert result["parse_error"] is True

    def test_no_sf_dict_members_at_all(self):
        result = _parse_integrity_policy("totally_random_content_no_equals_no_parens")
        assert result["parse_error"] is True


class TestParseCaseNormalization:
    def test_uppercase_tokens_lowercased(self):
        result = _parse_integrity_policy("BLOCKED-DESTINATIONS=(SCRIPT)")
        assert result["blocked_destinations"] == ["script"]

    def test_mixed_case_keys_normalized(self):
        result = _parse_integrity_policy(
            "Blocked-Destinations=(Script), Endpoints=(SRI)"
        )
        assert result["blocked_destinations"] == ["script"]
        assert result["endpoints"] == ["sri"]


class TestSourcesDefault:
    def test_sources_omitted_defaults_to_inline(self):
        result = _parse_integrity_policy("blocked-destinations=(script)")
        assert result["sources"] == ["inline"]

    def test_sources_explicit_inline_returns_inline(self):
        result = _parse_integrity_policy(
            "blocked-destinations=(script), sources=(inline)"
        )
        assert result["sources"] == ["inline"]


class TestIsHtmlResponse:
    def test_text_html(self):
        assert _is_html_response({"Content-Type": "text/html"}) is True

    def test_xhtml_xml(self):
        assert _is_html_response({"Content-Type": "application/xhtml+xml"}) is True

    def test_application_xml(self):
        assert _is_html_response({"Content-Type": "application/xml"}) is True

    def test_text_xml(self):
        assert _is_html_response({"Content-Type": "text/xml"}) is True

    def test_text_html_with_charset(self):
        assert _is_html_response({"Content-Type": "text/html; charset=utf-8"}) is True

    def test_application_json_returns_false(self):
        assert _is_html_response({"Content-Type": "application/json"}) is False

    def test_missing_content_type_returns_false(self):
        assert _is_html_response({}) is False

    def test_empty_content_type_returns_false(self):
        assert _is_html_response({"Content-Type": ""}) is False

    def test_lowercase_header_key(self):
        assert _is_html_response({"content-type": "text/html"}) is True
