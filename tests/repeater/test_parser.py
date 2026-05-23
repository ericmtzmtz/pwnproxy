import pytest

from pwnproxy.repeater.parser import parse_raw_request


class TestParseRawRequest:
    def test_simple_get(self):
        raw = "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = parse_raw_request(raw)
        assert result["method"] == "GET"
        assert result["path"] == "/api"
        assert result["http_version"] == "HTTP/1.1"
        assert result["headers"] == {"Host": "example.com"}
        assert result["body"] == ""

    def test_post_with_body(self):
        raw = "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"key\":\"val\"}"
        result = parse_raw_request(raw)
        assert result["method"] == "POST"
        assert result["path"] == "/submit"
        assert result["body"] == '{"key":"val"}'

    def test_multiple_headers(self):
        raw = "GET / HTTP/1.1\r\nHost: a.com\r\nUser-Agent: curl/8\r\nAccept: */*\r\n\r\n"
        result = parse_raw_request(raw)
        assert result["headers"] == {"Host": "a.com", "User-Agent": "curl/8", "Accept": "*/*"}

    def test_malformed_no_host(self):
        raw = "GET / HTTP/1.1\r\n\r\n"
        result = parse_raw_request(raw)
        assert result["method"] == "GET"
        assert result["headers"] == {}

    def test_empty_request_raises(self):
        with pytest.raises(ValueError, match="Empty"):
            parse_raw_request("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError):
            parse_raw_request("   \n  ")

    def test_invalid_request_line(self):
        with pytest.raises(ValueError, match="Invalid request line"):
            parse_raw_request("INVALID\n\r\n")

    def test_crlf_variants(self):
        raw = "PUT /resource HTTP/1.1\nHost: x.com\n\nbody"
        result = parse_raw_request(raw)
        assert result["method"] == "PUT"
        assert result["path"] == "/resource"
        assert result["body"] == "body"

    def test_no_http_version_defaults(self):
        raw = "DELETE /item\nHost: x.com\n\n"
        result = parse_raw_request(raw)
        assert result["http_version"] == "HTTP/1.1"
