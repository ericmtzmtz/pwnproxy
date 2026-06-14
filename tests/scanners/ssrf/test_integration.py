import socket
from unittest.mock import MagicMock

import pytest

from pwnproxy.shared.scan.replayer import RequestReplayer
from pwnproxy.plugins.scanners.ssrf.scanner import SSRFScanner


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def scanner():
    replayer = MagicMock(spec=RequestReplayer)
    return SSRFScanner(
        replayer,
        depth="fast",
        evasion="none",
        callback_host="127.0.0.1",
        callback_port=_free_port(),
    )


@pytest.mark.asyncio
async def test_scanner_init(scanner):
    assert scanner._depth == "fast"
    assert scanner._evasion == "none"
    assert scanner._callback_host == "127.0.0.1"


@pytest.mark.asyncio
async def test_scanner_has_scan_point(scanner):
    assert hasattr(scanner, "_scan_point")


@pytest.mark.asyncio
async def test_scanner_config(scanner):
    assert isinstance(scanner._callback_port, int)
