import asyncio
import socket
from unittest.mock import AsyncMock, MagicMock

import pytest

from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.models import Flow
from pwnproxy.services.scanners.ssrf.scanner import SSRFScanner


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.asyncio
async def test_scanner_lifecycle():
    hook_bus = HookBus()
    port = _free_port()

    storage = MagicMock()
    storage.create_tables = AsyncMock()
    storage.save_finding = AsyncMock()
    storage.get_findings = AsyncMock(return_value=[])

    scanner = SSRFScanner(hook_bus, storage=storage)
    scanner.configure(listen_port=port)

    assert not scanner.is_running
    status = scanner.status()
    assert status["findings"] == 0

    await scanner.start()
    assert scanner.is_running
    assert scanner.callback_server.is_running

    await scanner.stop()
    assert not scanner.is_running


@pytest.mark.asyncio
async def test_scanner_configure():
    hook_bus = HookBus()
    scanner = SSRFScanner(hook_bus)

    scanner.configure(callback_host="192.168.1.100", listen_port=9090)
    assert scanner._payload_gen.callback_host == "192.168.1.100"
    assert scanner._payload_gen.callback_port == 9090


@pytest.mark.asyncio
async def test_extract_and_scan():
    hook_bus = HookBus()
    port = _free_port()

    storage = MagicMock()
    storage.create_tables = AsyncMock()
    storage.save_finding = AsyncMock()
    storage.get_findings = AsyncMock(return_value=[])

    scanner = SSRFScanner(hook_bus, storage=storage)
    scanner.configure(listen_port=port)
    scanner._replayer.inject = AsyncMock()

    await scanner.start()

    flow = Flow(
        id="f1", method="GET",
        url="http://target.com/page?url=http://example.com",
        request_headers={"Host": "target.com"},
        request_body=None, response_headers={}, response_body=None,
        status_code=200,
    )
    hook_bus.publish("done", flow)
    await asyncio.sleep(0.3)

    assert scanner.flows_processed >= 1
    assert len(scanner._pending_canaries) >= 1

    await scanner.stop()
