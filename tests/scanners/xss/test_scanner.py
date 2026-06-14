from unittest.mock import MagicMock

import pytest

from pwnproxy.shared.scan.replayer import RequestReplayer
from pwnproxy.plugins.scanners.xss.scanner import XSSScanner


@pytest.fixture
def scanner():
    replayer = MagicMock(spec=RequestReplayer)
    return XSSScanner(replayer, depth="fast", evasion="none")


@pytest.mark.asyncio
async def test_scanner_init(scanner):
    assert scanner._depth == "fast"
    assert scanner._evasion == "none"


@pytest.mark.asyncio
async def test_scanner_has_scan_point(scanner):
    assert hasattr(scanner, "_scan_point")
