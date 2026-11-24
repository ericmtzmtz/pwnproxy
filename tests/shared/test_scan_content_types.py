"""Unit tests for the scan content-type helpers (``pwnproxy.shared.scan.content_types``)."""

import httpx

from pwnproxy.shared.scan.content_types import (
    header_value,
    is_decodable_text,
    is_known_binary,
    is_textual,
    is_textual_mime_type,
    mime_type,
    response_is_textual,
)


class TestMimeType:
    def test_parameters_and_case_are_stripped(self):
        assert mime_type("Text/HTML; charset=UTF-8") == "text/html"

    def test_missing_header(self):
        assert mime_type(None) == ""
        assert mime_type("") == ""


class TestKnownBinary:
    def test_pdf_and_archives(self):
        assert is_known_binary("application/pdf") is True
        assert is_known_binary("application/octet-stream") is True
        assert is_known_binary("application/zip") is True

    def test_binary_families(self):
        assert is_known_binary("image/png") is True
        assert is_known_binary("audio/mpeg") is True
        assert is_known_binary("font/woff2") is True

    def test_textual_types_inside_binary_families(self):
        # SVG is XML text, not a bitmap.
        assert is_known_binary("image/svg+xml") is False

    def test_text_and_unknown_are_not_binary(self):
        assert is_known_binary("text/html; charset=utf-8") is False
        assert is_known_binary("application/json") is False
        assert is_known_binary("") is False
        assert is_known_binary("application/x-exotic") is False


class TestTextualMimeType:
    def test_text_family(self):
        assert is_textual_mime_type("text/plain") is True
        assert is_textual_mime_type("text/html; charset=utf-8") is True

    def test_structured_types(self):
        assert is_textual_mime_type("application/json") is True
        assert is_textual_mime_type("application/problem+json") is True
        assert is_textual_mime_type("image/svg+xml") is True
        assert is_textual_mime_type("application/javascript") is True

    def test_binary_is_not_textual(self):
        assert is_textual_mime_type("application/pdf") is False
        assert is_textual_mime_type("") is False


class TestDecodableText:
    def test_utf8_and_ascii(self):
        assert is_decodable_text(b"uid=0(root)\n") is True
        assert is_decodable_text("hola") is True

    def test_binary_rejected(self):
        assert is_decodable_text(b"\x89PNG\r\n") is False
        assert is_decodable_text(b"ab\x00cd") is False
        assert is_decodable_text(None) is False


class TestIsTextual:
    def test_declared_binary_wins_over_ascii_body(self):
        assert is_textual("application/pdf", b"%PDF-1.4\nendobj\n") is False

    def test_declared_text_wins(self):
        assert is_textual("text/html; charset=utf-8", b"<html></html>") is True

    def test_missing_type_sniffs_the_body(self):
        assert is_textual("", b"uid=0(root)\n") is True
        assert is_textual("", b"\x89PNG\r\n\x1a\n") is False
        assert is_textual("", None) is False

    def test_unknown_type_sniffs_the_body(self):
        assert is_textual("application/x-exotic", b"plain words") is True


class TestResponseHelpers:
    def test_header_value_is_case_insensitive(self):
        assert header_value({"Content-Type": "text/html"}, "content-type") == "text/html"
        assert header_value({}, "content-type") == ""
        assert header_value(None, "content-type") == ""

    def test_httpx_response_with_pdf_is_not_textual(self):
        response = httpx.Response(
            200, content=b"%PDF-1.4\nendobj\n", headers={"content-type": "application/pdf"}
        )
        assert response_is_textual(response) is False

    def test_httpx_response_with_text_is_textual(self):
        response = httpx.Response(
            200, text="uid=0(root) gid=0(root)", headers={"content-type": "text/plain"}
        )
        assert response_is_textual(response) is True

    def test_response_without_headers_sniffs_the_body(self):
        response = httpx.Response(200, content=b"plain text, no header")
        assert response_is_textual(response) is True
