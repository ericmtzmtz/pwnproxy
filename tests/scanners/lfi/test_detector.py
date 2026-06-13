import pytest
from unittest.mock import AsyncMock, MagicMock

from pwnproxy.services.scan.params import InjectionPoint
from pwnproxy.services.scanners.lfi.detector import LfiDetector


@pytest.mark.asyncio
async def test_unix_detected():
    point = InjectionPoint(
        name="file", value="test", location="query",
        flow_id="f1", method="GET", url="http://target.com/page?file=test",
        host="target.com", path="/page",
        original_headers={"Host": "target.com"},
        original_body=None,
    )

    replayer = MagicMock()
    unix_resp = MagicMock()
    unix_resp.text = "root:x:0:0:root:/root:/bin/bash"
    unix_resp.status_code = 200
    replayer.replay_methods = AsyncMock(return_value=[("GET", unix_resp)])

    detector = LfiDetector(replayer)
    finding = await detector.check(point)

    assert finding is not None
    assert finding.os == "unix"
    assert finding.severity == "high"
    assert finding.successful_method == "GET"
    assert finding.original_method == "GET"
    assert finding.url == "http://target.com/page?file=test"


@pytest.mark.asyncio
async def test_windows_detected():
    point = InjectionPoint(
        name="file", value="test", location="query",
        flow_id="f1", method="POST", url="http://target.com/page?file=test",
        host="target.com", path="/page",
        original_headers={"Host": "target.com"},
        original_body=None,
    )

    replayer = MagicMock()
    win_resp = MagicMock()
    win_resp.text = "[extensions]\r\nmru=1"
    win_resp.status_code = 200
    replayer.replay_methods = AsyncMock(return_value=[("PUT", win_resp)])

    detector = LfiDetector(replayer)
    finding = await detector.check(point)

    assert finding is not None
    assert finding.os == "windows"
    assert finding.successful_method == "PUT"


@pytest.mark.asyncio
async def test_no_match_returns_none():
    point = InjectionPoint(
        name="q", value="test", location="query",
        flow_id="f1", method="GET", url="http://target.com/page?q=test",
        host="target.com", path="/page",
        original_headers={"Host": "target.com"},
        original_body=None,
    )

    replayer = MagicMock()
    clean_resp = MagicMock()
    clean_resp.text = "<html><body>Hello</body></html>"
    clean_resp.status_code = 200
    replayer.replay_methods = AsyncMock(return_value=[("GET", clean_resp)])

    detector = LfiDetector(replayer)
    finding = await detector.check(point)

    assert finding is None
