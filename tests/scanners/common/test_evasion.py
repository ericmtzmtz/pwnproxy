"""Tests for WAF evasion techniques."""
import pytest

from pwnproxy.scanners.common.evasion import (
    EvasionLevel,
    apply_evasion,
    apply_technique,
    double_url_encode,
    html_entity_encode,
    unicode_escape,
    case_variation,
    whitespace_inject,
)


class TestDoubleUrlEncode:
    def test_single_quote(self):
        """Test double URL encoding of single quote."""
        result = double_url_encode("'")
        assert result == "%2527"
    
    def test_script_tag(self):
        """Test double URL encoding of script tag."""
        result = double_url_encode("<script>")
        assert "%253C" in result or "%253c" in result  # < encoded twice (case insensitive)
        assert "%253E" in result or "%253e" in result  # > encoded twice


class TestUnicodeEscape:
    def test_single_quote(self):
        """Test Unicode escape of single quote."""
        result = unicode_escape("'")
        assert result == "\\u0027"
    
    def test_angle_brackets(self):
        """Test Unicode escape of angle brackets."""
        result = unicode_escape("<>")
        assert "\\u003c" in result
        assert "\\u003e" in result


class TestHtmlEntityEncode:
    def test_single_quote(self):
        """Test HTML entity encoding of single quote."""
        result = html_entity_encode("'")
        assert result == "&#39;"
    
    def test_angle_brackets(self):
        """Test HTML entity encoding of angle brackets."""
        result = html_entity_encode("<>")
        assert "&lt;" in result
        assert "&gt;" in result


class TestCaseVariation:
    def test_case_variation(self):
        """Test case variation produces mixed case."""
        result = case_variation("script")
        assert len(result) == 6
        assert result.lower() == "script"
        # At least some characters should be different case
        # (statistically very unlikely all same)


class TestWhitespaceInject:
    def test_whitespace_injection(self):
        """Test whitespace injection."""
        result = whitespace_inject("<script>")
        assert "\t" in result or "\n" in result


class TestApplyEvasion:
    def test_none_level(self):
        """Test no evasion."""
        payload = "<script>alert(1)</script>"
        result = apply_evasion(payload, EvasionLevel.NONE)
        assert result == payload
    
    def test_light_level(self):
        """Test light evasion (double URL)."""
        payload = "'"
        result = apply_evasion(payload, EvasionLevel.LIGHT)
        assert result == "%2527"
    
    def test_aggressive_level(self):
        """Test aggressive evasion (multiple layers)."""
        payload = "'"
        result = apply_evasion(payload, EvasionLevel.AGGRESSIVE)
        # Should have both unicode and double URL encoding
        assert "\\u0027" in result or "%25" in result


class TestApplyTechnique:
    def test_double_url_technique(self):
        """Test applying double_url technique."""
        result = apply_technique("'", "double_url")
        assert result == "%2527"
    
    def test_unicode_technique(self):
        """Test applying unicode technique."""
        result = apply_technique("'", "unicode")
        assert result == "\\u0027"
    
    def test_unknown_technique(self):
        """Test applying unknown technique returns original."""
        payload = "test"
        result = apply_technique(payload, "unknown_technique")
        assert result == payload
