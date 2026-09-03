"""Unit tests for WAF/proxy block detection helpers (pwnproxy/shared/scan/waf.py)."""
from pwnproxy.shared.scan.waf import (
    is_rate_limit_status,
    looks_like_block_page,
)


class TestLooksLikeBlockPage:
    def test_block_page_by_body(self):
        assert looks_like_block_page(403, "The request was blocked by Mod_Security", {}) is True
        assert looks_like_block_page(500, "<html>Access Denied — Incapsula</html>", {}) is True

    def test_block_page_by_headers_without_body_text(self):
        headers = {"server": "cloudflare", "cf-ray": "abc123"}
        assert looks_like_block_page(500, "<html>application error</html>", headers) is True

    def test_legit_application_error_no_waf_markers(self):
        assert looks_like_block_page(500, "<html>Internal Server Error</html>", {}) is False

    def test_200_with_blocked_word_is_not_block(self):
        # UI copy mentioning "blocked" on a normal 200 must not count.
        assert looks_like_block_page(200, "Your account was blocked. Contact support.", {}) is False

    def test_none_status_is_not_block(self):
        assert looks_like_block_page(None, "anything", {}) is False

    def test_header_marker_only_counts_on_error(self):
        headers = {"server": "cloudflare"}
        assert looks_like_block_page(200, "<html>homepage</html>", headers) is False

    def test_case_insensitive_body_pattern(self):
        assert looks_like_block_page(403, "REQUEST REJECTED BY WAF", {}) is True


class TestIsRateLimitStatus:
    def test_429_and_503_are_rate_limit(self):
        assert is_rate_limit_status(429) is True
        assert is_rate_limit_status(503) is True

    def test_500_not_rate_limit(self):
        assert is_rate_limit_status(500) is False

    def test_none_not_rate_limit(self):
        assert is_rate_limit_status(None) is False
