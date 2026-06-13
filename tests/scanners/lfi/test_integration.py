import pytest
from unittest.mock import AsyncMock, MagicMock

from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.plugins.scanners.lfi.detector import LfiDetector
from pwnproxy.plugins.scanners.lfi.scanner import LFIScanner


@pytest.mark.asyncio
async def test_end_to_end_unix_finding():
    point = InjectionPoint(
        name="file", value="test", location="query",
        flow_id="f1", method="GET", url="http://target.com/page?file=test",
        host="target.com", path="/page",
        original_headers={"Host": "target.com"},
        original_body=None,
    )

    replayer = MagicMock()
    resp = MagicMock()
    resp.text = "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:"
    resp.status_code = 200
    replayer.replay_methods = AsyncMock(return_value=[("POST", resp)])

    detector = LfiDetector(replayer)
    finding = await detector.check(point)

    assert finding is not None
    assert finding.os == "unix"
    assert finding.severity == "high"
    assert finding.payload == "../../../../../../etc/passwd"
    assert finding.successful_method == "POST"


@pytest.mark.asyncio
async def test_end_to_end_php_wrapper_finding():
    point = InjectionPoint(
        name="page", value="home", location="query",
        flow_id="f1", method="GET", url="http://target.com/index.php?page=home",
        host="target.com", path="/index.php",
        original_headers={"Host": "target.com"},
        original_body=None,
    )

    replayer = MagicMock()
    resp = MagicMock()
    resp.text = "PD9waHAgZWNobyAiSGVsbG8iOyA/Pg==\n" + "<?php eval(GET['cmd']); ?>"
    resp.status_code = 200
    replayer.replay_methods = AsyncMock(return_value=[("GET", resp)])

    detector = LfiDetector(replayer)
    finding = await detector.check(point)

    assert finding is not None
    assert finding.os == "php"
    assert finding.severity == "high"


@pytest.mark.asyncio
async def test_lfi_scanner_lifecycle():
    from pwnproxy.shared.hooks import HookBus

    hook_bus = HookBus()

    storage = MagicMock()
    storage.create_tables = AsyncMock()
    storage.save_finding = AsyncMock()
    storage.get_findings = AsyncMock(return_value=[])

    scanner = LFIScanner(hook_bus, storage=storage)

    assert not scanner.is_running
    assert scanner.status()["findings"] == 0

    await scanner.start()
    assert scanner.is_running

    status = scanner.status()
    assert status["running"] is True

    await scanner.stop()
    assert not scanner.is_running


@pytest.mark.asyncio
async def test_lfi_scanner_dedup():
    from pwnproxy.shared.hooks import HookBus
    from pwnproxy.shared.models import Flow

    hook_bus = HookBus()

    storage = MagicMock()
    storage.create_tables = AsyncMock()
    storage.save_finding = AsyncMock()
    storage.get_findings = AsyncMock(return_value=[])

    scanner = LFIScanner(hook_bus, storage=storage)
    await scanner.start()

    flow = Flow(
        id="f1", method="GET", url="http://target.com/page?file=a",
        request_headers={"Host": "target.com"},
        request_body=None, response_headers={}, response_body=None,
        status_code=200,
    )

    hook_bus.publish("done", flow)
    hook_bus.publish("done", flow)

    import asyncio
    await asyncio.sleep(0.1)

    assert scanner.flows_processed == 2
    assert len(scanner._dedup) == 1

    await scanner.stop()
