from urllib.parse import quote_plus

from pwnproxy.scanners.sqli.replayer import (
    _inject_cookie,
    _inject_form_body,
    _inject_json_body,
    _inject_query,
)


class TestInjectQuery:
    def test_replace_param(self):
        url = "http://target.com/page?q=hello&page=2"
        result = _inject_query(url, "q", "' OR 1=1--")
        expected = quote_plus("' OR 1=1--", safe="")
        assert expected in result
        assert "page=2" in result


class TestInjectFormBody:
    def test_replace_param(self):
        body = "user=admin&pass=secret"
        result = _inject_form_body(body, "user", "' OR 1=1--")
        expected = quote_plus("' OR 1=1--", safe="")
        assert expected.encode() in result
        assert b"pass=secret" in result


class TestInjectJsonBody:
    def test_replace_flat_key(self):
        body = '{"name": "admin", "id": 5}'
        result = _inject_json_body(body, "name", "' OR 1=1--")
        assert b"' OR 1=1--" in result
        assert b'"id": 5' in result

    def test_replace_nested_key(self):
        body = '{"user": {"name": "admin", "id": 5}}'
        result = _inject_json_body(body, "user.name", "' OR 1=1--")
        assert b"' OR 1=1--" in result
        assert b'"id": 5' in result


class TestInjectCookie:
    def test_replace_param(self):
        cookie = "session=abc123; lang=en"
        result = _inject_cookie(cookie, "session", "' OR 1=1--")
        assert "' OR 1=1--" in result
        assert "lang=en" in result
