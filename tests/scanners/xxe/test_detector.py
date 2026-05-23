import pytest
from unittest.mock import AsyncMock, MagicMock

from pwnproxy.scanners.common.params import InjectionPoint
from pwnproxy.scanners.xxe.detector import XxeDetector


@pytest.mark.asyncio
async def test_unix_error_based_detected():
    point = InjectionPoint(
        name="q", value="test", location="query",
        flow_id="f1", method="GET",
        url="http://target.com/api",
        host="target.com", path="/api",
        original_headers={"Host": "target.com"},
        original_body=None,
    )

    replayer = MagicMock()
    resp = MagicMock()
    resp.text = "root:x:0:0:root:/root:/bin/bash"
    resp.status_code = 200
    replayer.replay_raw_body = AsyncMock(return_value=resp)

    detector = XxeDetector(replayer)
    finding = await detector.check_error_based(point)

    assert finding is not None
    assert finding.technique == "error"
    assert finding.severity == "high"
    assert "root:x:0:0:" in finding.evidence


@pytest.mark.asyncio
async def test_no_match_returns_none():
    point = InjectionPoint(
        name="q", value="test", location="query",
        flow_id="f1", method="GET",
        url="http://target.com/api",
        host="target.com", path="/api",
        original_headers={"Host": "target.com"},
        original_body=None,
    )

    replayer = MagicMock()
    resp = MagicMock()
    resp.text = "<html><body>Hello</body></html>"
    resp.status_code = 200
    replayer.replay_raw_body = AsyncMock(return_value=resp)

    detector = XxeDetector(replayer)
    finding = await detector.check_error_based(point)

    assert finding is None


@pytest.mark.asyncio
async def test_oob_creates_tentative_finding():
    point = InjectionPoint(
        name="q", value="test", location="query",
        flow_id="f1", method="GET",
        url="http://target.com/api",
        host="target.com", path="/api",
        original_headers={"Host": "target.com"},
        original_body=None,
    )

    replayer = MagicMock()
    resp = MagicMock()
    resp.text = ""
    resp.status_code = 200
    replayer.replay_raw_body = AsyncMock(return_value=resp)

    detector = XxeDetector(replayer)
    finding = await detector.check_oob(point, "test.oob.com")

    assert finding is not None
    assert finding.technique == "oob"
    assert finding.oob_domain == "test.oob.com"
    assert finding.confidence == "low"


@pytest.mark.asyncio
async def test_json_mutated_detection():
    point = InjectionPoint(
        name="user", value="admin", location="body",
        flow_id="f1", method="POST",
        url="http://target.com/api",
        host="target.com", path="/api",
        original_headers={"Host": "target.com", "content-type": "application/json"},
        original_body='{"user": "admin"}',
    )

    replayer = MagicMock()
    resp = MagicMock()
    resp.text = "root:x:0:0:root:/root:/bin/bash"
    resp.status_code = 200
    replayer.replay_json_mutated = AsyncMock(return_value=resp)

    detector = XxeDetector(replayer)
    finding = await detector.check_json_mutated(point)

    assert finding is not None
    assert finding.mutation == "json-to-xml"
    assert finding.severity == "high"
