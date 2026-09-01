"""SSRF accuracy tests: SsrfSimpleStage must require OOB confirmation.

Regression: previously any response with status < 400 produced a
``ssrf-error-based`` finding (huge false-positive flood on the auto-scan).
Now only a confirmed canary callback emits a finding.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pwnproxy.shared.scan.params import InjectionPoint, is_url_like_param
from pwnproxy.shared.scan.stages.ssrf_stages import SsrfSimpleStage
from pwnproxy.shared.models import Flow


class FakeServer:
    def __init__(self, running=True):
        self._running = running
        self.host = "127.0.0.1"
        self.port = 18081

    @property
    def is_running(self):
        return self._running

    def get_callback_url(self, token):
        return f"http://127.0.0.1:18081/{token}"


class FakeRegistry:
    def __init__(self, confirmed=False, ip="10.0.0.1"):
        self._confirmed = confirmed
        self._ip = ip
        self._canaries = {}

    def create(self, scan_id):
        from pwnproxy.shared.canary import CanaryToken
        tok = CanaryToken(token="deadbeefcafe1234", scan_id=scan_id)
        if self._confirmed:
            tok.callback_received = True
            tok.callback_ip = self._ip
        self._canaries[tok.token] = tok
        return tok

    def get(self, token):
        return self._canaries.get(token)

    def cleanup_expired(self):
        return 0


class FakeReplayer:
    """Replayer that returns a scripted response and records payloads sent."""

    def __init__(self, status=200, body="<html>ok</html>"):
        self.sent_payloads = []
        self.status = status
        self.body = body

    async def replay(self, point, payload, timeout=5.0, evasion_level="none"):
        self.sent_payloads.append(payload)
        resp = MagicMock()
        resp.status_code = self.status
        resp.text = self.body
        resp.headers = {}
        return resp

    def build_payload_request(self, point, payload, evasion_level="none"):
        return MagicMock()


def _point(name="url", location="query") -> InjectionPoint:
    return InjectionPoint(
        name=name, value="http://example.com", location=location,
        flow_id="f1", method="GET", url="http://target.com/page?url=http://example.com",
        host="target.com", path="/page",
        original_headers={"Host": "target.com"}, original_body=None,
    )


def _flow() -> Flow:
    return Flow(id="f1", method="GET", url="http://target.com/page?url=http://example.com", request_headers={"Host": "target.com"})


@pytest.mark.asyncio
@patch("pwnproxy.shared.scan.stages.ssrf_stages.get_server")
@patch("pwnproxy.shared.scan.stages.ssrf_stages.get_registry")
async def test_response_200_without_callback_no_finding(mock_reg, mock_server):
    mock_server.return_value = FakeServer(running=True)
    mock_reg.return_value = FakeRegistry(confirmed=False)
    stage = SsrfSimpleStage(FakeReplayer(status=200))
    result = await stage.execute(_flow(), [_point()])
    assert result.findings == []


@pytest.mark.asyncio
@patch("pwnproxy.shared.scan.stages.ssrf_stages.get_server")
@patch("pwnproxy.shared.scan.stages.ssrf_stages.get_registry")
async def test_response_302_without_callback_no_finding(mock_reg, mock_server):
    mock_server.return_value = FakeServer(running=True)
    mock_reg.return_value = FakeRegistry(confirmed=False)
    stage = SsrfSimpleStage(FakeReplayer(status=302))
    result = await stage.execute(_flow(), [_point()])
    assert result.findings == []


@pytest.mark.asyncio
@patch("pwnproxy.shared.scan.stages.ssrf_stages.get_server")
@patch("pwnproxy.shared.scan.stages.ssrf_stages.get_registry")
async def test_callback_received_confirms_finding(mock_reg, mock_server):
    mock_server.return_value = FakeServer(running=True)
    mock_reg.return_value = FakeRegistry(confirmed=True, ip="10.0.0.1")
    stage = SsrfSimpleStage(FakeReplayer(status=200))
    result = await stage.execute(_flow(), [_point()])
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.technique == "ssrf-oob"
    assert f.confidence == "confirmed"
    assert f.severity == "high"
    assert f.payload.startswith("http://127.0.0.1:18081/")
    assert "10.0.0.1" in f.evidence


@pytest.mark.asyncio
@patch("pwnproxy.shared.scan.stages.ssrf_stages.get_server")
@patch("pwnproxy.shared.scan.stages.ssrf_stages.get_registry")
async def test_callback_server_down_fail_closed(mock_reg, mock_server):
    mock_server.return_value = FakeServer(running=False)
    mock_reg.return_value = FakeRegistry(confirmed=True)
    stage = SsrfSimpleStage(FakeReplayer(status=200))
    result = await stage.execute(_flow(), [_point()])
    assert result.findings == []


def test_is_url_like_param():
    assert is_url_like_param("redirect_uri")
    assert is_url_like_param("callback")
    assert is_url_like_param("next_url")
    assert is_url_like_param("url")
    assert not is_url_like_param("name")
    assert not is_url_like_param("default")
    assert not is_url_like_param("username")
    assert not is_url_like_param("id")
