from unittest.mock import MagicMock

import pytest

from pwnproxy.plugins.core.chain import DetectionChain
from pwnproxy.plugins.scanners.sqli.scanner import SQLiScanner


@pytest.fixture
def scanner():
    chain = MagicMock(spec=DetectionChain)
    return SQLiScanner(chain)


@pytest.mark.asyncio
async def test_scanner_init(scanner):
    assert hasattr(scanner, "_chain")


@pytest.mark.asyncio
async def test_scanner_has_scan_point(scanner):
    assert hasattr(scanner, "_scan_point")


@pytest.mark.asyncio
async def test_scanner_scan_point_is_async_gen(scanner):
    point = MagicMock()
    point.flow_id = "f1"
    point.method = "GET"
    point.url = "http://target.com/page?q=hello"
    point.host = "target.com"
    point.path = "/page"
    point.name = "q"
    point.location = "query"
    point.key = ("GET", "target.com/page", "q", "query")
    point.original_headers = {"Host": "target.com"}
    point.original_body = None
    gen = scanner._scan_point(point)
    assert hasattr(gen, "__aiter__")
