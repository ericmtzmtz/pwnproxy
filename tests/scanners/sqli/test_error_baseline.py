"""Tests for the error-based baseline check (skip points with pre-existing SQL errors)."""
from unittest.mock import MagicMock

import pytest

from pwnproxy.plugins.scanners.sqli.payloads import get_error_payloads
from pwnproxy.plugins.scanners.sqli.signatures import ERROR_SIGNATURES
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.stages.sqli_stages import ErrorBasedStage

MYSQL_ERR = "You have an error in your SQL syntax"


class FakeReplayer:
    """Scripted replayer: clean response separate from payload responses."""

    def __init__(self, clean_text: str, payload_text: str):
        self._clean_text = clean_text
        self._payload_text = payload_text
        self.clean_calls = 0
        self.payload_calls = 0

    async def send_clean(self, point, timeout=10.0):
        self.clean_calls += 1
        resp = MagicMock()
        resp.status_code = 200
        resp.text = self._clean_text
        resp.headers = {}
        return resp

    async def replay(self, point, payload, timeout=3.0, evasion_level="none"):
        self.payload_calls += 1
        resp = MagicMock()
        resp.status_code = 200
        resp.text = self._payload_text
        resp.headers = {}
        return resp

    def build_payload_request(self, point, payload, evasion_level="none"):
        return MagicMock()


def _point(name="id", location="query") -> InjectionPoint:
    return InjectionPoint(
        name=name, value="1", location=location,
        flow_id="f1", method="GET", url="http://target.com/sqli/?id=1",
        host="target.com", path="/sqli/",
        original_headers={"Host": "target.com"}, original_body=None,
    )


def _flow():
    from pwnproxy.shared.models import Flow
    return Flow(id="f1", method="GET", url="http://target.com/sqli/?id=1", request_headers={"Host": "target.com"})


@pytest.mark.asyncio
async def test_baseline_with_error_skips_point():
    """Regression: session poisoned with SQLi -> clean response has error -> skip."""
    replayer = FakeReplayer(clean_text=f"<html>Error: {MYSQL_ERR}</html>", payload_text=f"<html>{MYSQL_ERR}</html>")
    stage = ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads())
    result = await stage.execute(_flow(), [_point()])
    assert result.findings == []
    assert replayer.clean_calls == 1
    assert replayer.payload_calls == 0  # never tested payloads


@pytest.mark.asyncio
async def test_clean_baseline_and_payload_error_confirms():
    replayer = FakeReplayer(clean_text="<html>normal page</html>", payload_text=f"<html>{MYSQL_ERR}</html>")
    stage = ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads())
    result = await stage.execute(_flow(), [_point()])
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.technique == "error-based"
    assert f.confidence == "confirmed"
    assert f.extra["dbms"] == "mysql"
    assert replayer.payload_calls >= 1


@pytest.mark.asyncio
async def test_baseline_fails_skips_fail_closed():
    class FailingReplayer(FakeReplayer):
        async def send_clean(self, point, timeout=10.0):
            self.clean_calls += 1
            return None

    replayer = FailingReplayer("", "")
    stage = ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads())
    result = await stage.execute(_flow(), [_point()])
    assert result.findings == []
    assert replayer.payload_calls == 0


@pytest.mark.asyncio
async def test_clean_baseline_and_payload_no_error_no_finding():
    replayer = FakeReplayer(clean_text="<html>normal</html>", payload_text="<html>still normal</html>")
    stage = ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads())
    result = await stage.execute(_flow(), [_point()])
    assert result.findings == []
