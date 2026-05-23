import pytest

from pwnproxy.core.models import Flow
from pwnproxy.modules.session_manager.extractors import cookies, csrf, jwt


class TestJwtExtractor:
    def test_from_authorization_header(self):
        flow = Flow(
            id="f1", method="GET", url="http://target.com/api",
            request_headers={"authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.a1b2c3"},
            request_body=None, response_headers={}, response_body=None,
            status_code=200,
        )
        candidates = jwt.extract(flow)
        assert len(candidates) == 1
        assert candidates[0].token_type == "jwt"
        assert candidates[0].label == "Bearer"

    def test_non_bearer_ignored(self):
        flow = Flow(
            id="f1", method="GET", url="http://target.com/api",
            request_headers={"authorization": "Basic dXNlcjpwYXNz"},
            request_body=None, response_headers={}, response_body=None,
            status_code=200,
        )
        candidates = jwt.extract(flow)
        assert len(candidates) == 0

    def test_from_json_body(self):
        flow = Flow(
            id="f1", method="POST", url="http://target.com/login",
            request_headers={"content-type": "application/json"},
            request_body=b'{"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.a1b2c3"}',
            response_headers={}, response_body=None,
            status_code=200,
        )
        candidates = jwt.extract(flow)
        assert len(candidates) == 1
        assert candidates[0].label == "token"


class TestCookieExtractor:
    def test_session_cookie_from_request(self):
        flow = Flow(
            id="f1", method="GET", url="http://target.com/",
            request_headers={"cookie": "sessionid=abc123; utm_source=google"},
            request_body=None, response_headers={}, response_body=None,
            status_code=200,
        )
        candidates = cookies.extract(flow)
        assert len(candidates) == 1
        assert candidates[0].label == "sessionid"
        assert candidates[0].token_value == "abc123"

    def test_session_cookie_from_response(self):
        flow = Flow(
            id="f1", method="GET", url="http://target.com/",
            request_headers={}, request_body=None,
            response_headers={"set-cookie": "connect.sid=xyz; Path=/"},
            response_body=None, status_code=200,
        )
        candidates = cookies.extract(flow)
        assert len(candidates) == 1
        assert candidates[0].label == "connect.sid"
        assert candidates[0].token_value == "xyz"

    def test_non_session_cookie_skipped(self):
        flow = Flow(
            id="f1", method="GET", url="http://target.com/",
            request_headers={"cookie": "utm_source=google"},
            request_body=None, response_headers={}, response_body=None,
            status_code=200,
        )
        candidates = cookies.extract(flow)
        assert len(candidates) == 0


class TestCsrfExtractor:
    def test_from_headers(self):
        flow = Flow(
            id="f1", method="POST", url="http://target.com/action",
            request_headers={"x-csrf-token": "csrf123"},
            request_body=None, response_headers={}, response_body=None,
            status_code=200,
        )
        candidates = csrf.extract(flow)
        assert len(candidates) == 1
        assert candidates[0].token_value == "csrf123"

    def test_from_form_body(self):
        flow = Flow(
            id="f1", method="POST", url="http://target.com/action",
            request_headers={"content-type": "application/x-www-form-urlencoded"},
            request_body=b"csrf_token=abc123&username=admin",
            response_headers={}, response_body=None,
            status_code=200,
        )
        candidates = csrf.extract(flow)
        assert len(candidates) >= 1
        assert candidates[0].token_value == "abc123"

    def test_from_json_body(self):
        flow = Flow(
            id="f1", method="POST", url="http://target.com/action",
            request_headers={"content-type": "application/json"},
            request_body=b'{"_csrf": "abc123"}',
            response_headers={}, response_body=None,
            status_code=200,
        )
        candidates = csrf.extract(flow)
        assert len(candidates) == 1
        assert candidates[0].token_value == "abc123"
