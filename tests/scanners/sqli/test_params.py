import pytest

from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import extract, InjectionPoint


def _flow(**overrides) -> Flow:
    return Flow(
        id=overrides.get("id", "f1"),
        method=overrides.get("method", "GET"),
        url=overrides.get("url", "http://target.com/page?q=hello"),
        request_headers=overrides.get("request_headers", {"Host": "target.com"}),
        request_body=overrides.get("request_body", None),
    )


class TestQueryExtraction:
    def test_single_query_param(self):
        flow = _flow(url="http://target.com/search?q=hello")
        points = extract(flow)
        q_params = [p for p in points if p.location == "query"]
        assert len(q_params) == 1
        assert q_params[0].name == "q"
        assert q_params[0].value == "hello"

    def test_multiple_query_params(self):
        flow = _flow(url="http://target.com/search?q=hello&page=2")
        points = extract(flow)
        q_params = {p.name: p.value for p in points if p.location == "query"}
        assert q_params.get("q") == "hello"
        assert q_params.get("page") == "2"


class TestBodyExtraction:
    def test_form_body(self):
        flow = _flow(
            method="POST",
            url="http://target.com/login",
            request_headers={"content-type": "application/x-www-form-urlencoded"},
            request_body=b"user=admin&pass=secret",
        )
        points = extract(flow)
        body_params = {p.name: p.value for p in points if p.location == "body"}
        assert body_params.get("user") == "admin"
        assert body_params.get("pass") == "secret"

    def test_json_body(self):
        flow = _flow(
            method="POST",
            url="http://target.com/api",
            request_headers={"content-type": "application/json"},
            request_body=b'{"name": "admin", "id": 5}',
        )
        points = extract(flow)
        body_params = {p.name: p.value for p in points if p.location == "body"}
        assert body_params.get("name") == "admin"
        assert body_params.get("id") == "5"

    def test_nested_json_keys(self):
        flow = _flow(
            method="POST",
            url="http://target.com/api",
            request_headers={"content-type": "application/json"},
            request_body=b'{"user": {"name": "admin", "id": 5}}',
        )
        points = extract(flow)
        body_params = {p.name: p.value for p in points if p.location == "body"}
        assert body_params.get("user.name") == "admin"
        assert body_params.get("user.id") == "5"

    def test_skip_binary_content_type(self):
        flow = _flow(
            method="POST",
            url="http://target.com/upload",
            request_headers={"content-type": "application/octet-stream"},
            request_body=b"\x00\x01\x02",
        )
        points = extract(flow)
        body_params = [p for p in points if p.location == "body"]
        assert len(body_params) == 0


class TestCookieExtraction:
    def test_cookie_params(self):
        flow = _flow(
            url="http://target.com/",
            request_headers={"cookie": "session=abc123; lang=en"},
        )
        points = extract(flow)
        cookie_params = {p.name: p.value for p in points if p.location == "cookie"}
        assert cookie_params.get("session") == "abc123"
        assert cookie_params.get("lang") == "en"


class TestHeaderExtraction:
    def test_injectable_headers(self):
        flow = _flow(
            url="http://target.com/",
            request_headers={
                "Referer": "http://other.com",
                "X-Forwarded-For": "127.0.0.1",
                "User-Agent": "Mozilla/5.0",
                "Accept": "text/html",
            },
        )
        points = extract(flow)
        header_params = {p.name: p.value for p in points if p.location == "header"}
        assert "Referer" in header_params
        assert "X-Forwarded-For" in header_params
        assert "User-Agent" in header_params
        assert "Accept" not in header_params
