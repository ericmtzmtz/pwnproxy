import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from pwnproxy.core.hooks import HookBus
from pwnproxy.core.models import Flow
from pwnproxy.scanners.sqli.scanner import SQLiScanner


@pytest.mark.asyncio
async def test_scanner_lifecycle():
    bus = HookBus()
    scanner = SQLiScanner(bus)
    assert not scanner.is_running

    await scanner.start()
    assert scanner.is_running

    await scanner.stop()
    assert not scanner.is_running


@pytest.mark.asyncio
async def test_scanner_status():
    bus = HookBus()
    scanner = SQLiScanner(bus)
    s = scanner.status()
    assert "running" in s
    assert "flows_processed" in s
    assert "params_scanned" in s
    assert "findings" in s


@pytest.mark.asyncio
async def test_scanner_dedup():
    bus = HookBus()
    scanner = SQLiScanner(bus)
    flow = Flow(
        id="f1", method="GET", url="http://target.com/page?q=hello",
        request_headers={"Host": "target.com"},
        request_body=None,
    )
    from pwnproxy.scanners.common.params import extract as extract_params
    points = extract_params(flow)
    assert len(points) == 1
    key = (points[0].method, points[0].host + points[0].path, points[0].name, points[0].location)
    scanner._dedup.add(key)
    assert key in scanner._dedup
    same_key = ("GET", "target.com/page", "q", "query")
    assert same_key in scanner._dedup
