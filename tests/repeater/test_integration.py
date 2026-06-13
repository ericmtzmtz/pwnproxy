from pwnproxy.shared.models import Flow
from pwnproxy.services.repeater.integration import format_flow_as_raw_request


class TestFlowFormatting:
    def test_simple_request(self):
        flow = Flow(
            id="f1", method="GET", url="http://example.com/api",
            request_headers={"Host": "example.com", "User-Agent": "test"},
            request_body=None, response_headers={}, response_body=None,
            status_code=200,
        )
        raw = format_flow_as_raw_request(flow)
        assert raw.startswith("GET /api HTTP/1.1\r\n")
        assert "Host: example.com" in raw
        assert "User-Agent: test" in raw
        assert raw.endswith("\r\n\r\n")

    def test_post_with_body(self):
        flow = Flow(
            id="f1", method="POST", url="http://example.com/submit",
            request_headers={"Host": "example.com"},
            request_body=b'{"key":"val"}',
            response_headers={}, response_body=None,
            status_code=200,
        )
        raw = format_flow_as_raw_request(flow)
        assert "POST /submit HTTP/1.1" in raw
        assert '{"key":"val"}' in raw

    def test_adds_host_if_missing(self):
        flow = Flow(
            id="f1", method="GET", url="https://example.com/path",
            request_headers={},
            request_body=None, response_headers={}, response_body=None,
            status_code=200,
        )
        raw = format_flow_as_raw_request(flow)
        assert "Host: example.com" in raw

    def test_handles_url_with_port(self):
        flow = Flow(
            id="f1", method="GET", url="http://localhost:8080/test",
            request_headers={},
            request_body=None, response_headers={}, response_body=None,
            status_code=200,
        )
        raw = format_flow_as_raw_request(flow)
        assert "Host: localhost:8080" in raw

    def test_handles_root_path(self):
        flow = Flow(
            id="f1", method="GET", url="http://example.com/",
            request_headers={"Host": "example.com"},
            request_body=None, response_headers={}, response_body=None,
            status_code=200,
        )
        raw = format_flow_as_raw_request(flow)
        assert raw.startswith("GET / HTTP/1.1\r\n")
