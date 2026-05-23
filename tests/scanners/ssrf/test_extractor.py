from pwnproxy.core.models import Flow
from pwnproxy.scanners.ssrf.extractor import SsrfExtractor


class TestSsrfExtractor:
    def setup_method(self):
        self.extractor = SsrfExtractor()

    def test_url_like_param_is_targeted(self):
        flow = Flow(
            id="f1", method="GET",
            url="http://target.com/page?url=http://example.com",
            request_headers={"Host": "target.com"},
            request_body=None, response_headers={}, response_body=None,
            status_code=200,
        )
        points = self.extractor.extract_url_params(flow)
        assert len(points) == 1
        assert points[0].name == "url"

    def test_non_url_param_is_skipped(self):
        flow = Flow(
            id="f1", method="GET",
            url="http://target.com/page?username=admin",
            request_headers={"Host": "target.com"},
            request_body=None, response_headers={}, response_body=None,
            status_code=200,
        )
        points = self.extractor.extract_url_params(flow)
        assert len(points) == 0

    def test_redirect_param_detected(self):
        flow = Flow(
            id="f1", method="GET",
            url="http://target.com/login?goto=/dashboard",
            request_headers={"Host": "target.com"},
            request_body=None,
            response_headers={"location": "/dashboard"},
            response_body=None,
            status_code=302,
        )
        points = self.extractor.extract_redirect_params(flow)
        assert len(points) == 1
        assert points[0].name == "goto"

    def test_no_redirect_returns_empty(self):
        flow = Flow(
            id="f1", method="GET",
            url="http://target.com/page",
            request_headers={"Host": "target.com"},
            request_body=None, response_headers={}, response_body=None,
            status_code=200,
        )
        points = self.extractor.extract_redirect_params(flow)
        assert len(points) == 0

    def test_mixed_params(self):
        flow = Flow(
            id="f1", method="GET",
            url="http://target.com/api?url=http://x.com&username=admin&redirect=http://y.com",
            request_headers={"Host": "target.com"},
            request_body=None, response_headers={}, response_body=None,
            status_code=200,
        )
        points = self.extractor.extract_url_params(flow)
        assert len(points) == 2
        names = {p.name for p in points}
        assert names == {"url", "redirect"}
