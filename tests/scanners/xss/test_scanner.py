from unittest.mock import AsyncMock, MagicMock

import pytest

from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.models import Flow
from pwnproxy.services.scanners.xss.scanner import XSSScanner


@pytest.mark.asyncio
async def test_scanner_lifecycle():
    bus = HookBus()
    scanner = XSSScanner(bus)
    assert not scanner.is_running

    await scanner.start()
    assert scanner.is_running

    await scanner.stop()
    assert not scanner.is_running


@pytest.mark.asyncio
async def test_scanner_status():
    bus = HookBus()
    scanner = XSSScanner(bus)
    s = scanner.status()
    assert "running" in s
    assert "flows_processed" in s
    assert "params_scanned" in s
    assert "findings" in s
    assert "active_canaries" in s


@pytest.mark.asyncio
async def test_scanner_dedup():
    bus = HookBus()
    scanner = XSSScanner(bus)
    flow = Flow(
        id="f1", method="GET", url="http://target.com/page?q=hello",
        request_headers={"Host": "target.com"},
        request_body=None,
    )
    from pwnproxy.services.scan.params import extract as extract_params
    points = extract_params(flow)
    assert len(points) == 1
    key = (points[0].method, points[0].host + points[0].path, points[0].name, points[0].location)
    scanner._dedup.add(key)
    assert key in scanner._dedup
    same_key = ("GET", "target.com/page", "q", "query")
    assert same_key in scanner._dedup
