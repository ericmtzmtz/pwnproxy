"""Tests for the error-based status differential (muted SQL error → 5xx signal)."""
from unittest.mock import MagicMock

import pytest

from pwnproxy.plugins.scanners.sqli.payloads import get_error_payloads
from pwnproxy.plugins.scanners.sqli.signatures import ERROR_SIGNATURES
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.stages.sqli_stages import ErrorBasedStage

MYSQL_ERR = "You have an error in your SQL syntax"


class ScriptedReplayer:
    """Replayer whose response status depends on the payload value."""

    def __init__(self, clean_status=200, payload_map=None):
        self._clean_status = clean_status
        # payload_map: {payload_value: (status, text)}. Default → (200, "ok").
        self._payload_map = payload_map or {}
        self.clean_calls = 0
        self.payload_calls = 0

    async def send_clean(self, point, timeout=10.0):
        self.clean_calls += 1
        resp = MagicMock()
        resp.status_code = self._clean_status
        resp.text = "<html>normal page</html>"
        resp.headers = {}
        return resp

    async def replay(self, point, payload, timeout=3.0, evasion_level="none"):
        self.payload_calls += 1
        status, text = self._payload_map.get(payload, (200, "<html>ok</html>"))
        resp = MagicMock()
        resp.status_code = status
        resp.text = text
        resp.headers = {}
        return resp

    def build_payload_request(self, point, payload, evasion_level="none"):
        return MagicMock()


def _point(name="title", location="query") -> InjectionPoint:
    return InjectionPoint(
        name=name, value="test", location=location,
        flow_id="f1", method="GET", url="http://target.com/sqli_1.php?title=test&action=search",
        host="target.com", path="/sqli_1.php",
        original_headers={"Host": "target.com"}, original_body=None,
    )


def _flow():
    from pwnproxy.shared.models import Flow
    return Flow(id="f1", method="GET", url="http://target.com/sqli_1.php?title=test&action=search", request_headers={"Host": "target.com"})


@pytest.mark.asyncio
async def test_two_error_payloads_induce_5xx_inferred():
    """bWAPP-style: ' and ' UNION SELECT 1,2,3-- induce 500 -> error-based inferred high."""
    replayer = ScriptedReplayer(clean_status=200, payload_map={
        "'": (500, "<html>bWAPP - SQL Injection</html>"),
        "' UNION SELECT 1,2,3-- ": (500, "<html>bWAPP</html>"),
    })
    stage = ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads())
    result = await stage.execute(_flow(), [_point()])
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.technique == "error-based"
    assert f.confidence == "inferred"
    assert f.severity == "high"
    assert f.payload == "'"
    assert "5xx" in f.evidence or "HTTP 5xx" in f.evidence


@pytest.mark.asyncio
async def test_single_error_payload_5xx_tentative():
    replayer = ScriptedReplayer(clean_status=200, payload_map={"'": (500, "<html>err</html>")})
    stage = ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads())
    result = await stage.execute(_flow(), [_point()])
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.confidence == "tentative"
    assert f.severity == "medium"


@pytest.mark.asyncio
async def test_sql_valid_payload_no_5xx_no_finding():
    # ' OR 1=1-- gives 200 (valid SQL, no error) -> no status-differential finding
    replayer = ScriptedReplayer(clean_status=200, payload_map={
        "' OR 1=1-- ": (200, "<html>result</html>"),
        "' OR 1=1": (200, "<html>result</html>"),
    })
    stage = ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads())
    result = await stage.execute(_flow(), [_point()])
    assert result.findings == []


@pytest.mark.asyncio
async def test_baseline_5xx_skips_point():
    replayer = ScriptedReplayer(clean_status=500, payload_map={"'": (500, "<html>err</html>")})
    stage = ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads())
    result = await stage.execute(_flow(), [_point()])
    assert result.findings == []
    assert replayer.payload_calls == 0


@pytest.mark.asyncio
async def test_textual_signature_still_confirms():
    """Regression: a body signature still yields confirmed (signature dominates)."""
    replayer = ScriptedReplayer(clean_status=200, payload_map={
        "'": (200, f"<html>{MYSQL_ERR}</html>"),
    })
    stage = ErrorBasedStage(replayer, ERROR_SIGNATURES, get_error_payloads())
    result = await stage.execute(_flow(), [_point()])
    assert len(result.findings) == 1
    assert result.findings[0].confidence == "confirmed"
    assert result.findings[0].extra["dbms"] == "mysql"
