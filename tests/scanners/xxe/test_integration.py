import pytest
from unittest.mock import AsyncMock, MagicMock

from pwnproxy.scanners.common.params import InjectionPoint
from pwnproxy.scanners.xxe.detector import XxeDetector
from pwnproxy.scanners.xxe.scanner import XXEScanner


@pytest.mark.asyncio
async def test_end_to_end_unix_finding():
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
    resp.text = "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:"
    resp.status_code = 200
    replayer.replay_raw_body = AsyncMock(return_value=resp)

    detector = XxeDetector(replayer)
    finding = await detector.check_error_based(point)

    assert finding is not None
    assert finding.technique == "error"
    assert finding.severity == "high"
    assert finding.evidence is not None
    assert "root:x:0:0:" in finding.evidence


@pytest.mark.asyncio
async def test_xxe_scanner_lifecycle():
    from pwnproxy.core.hooks import HookBus

    hook_bus = HookBus()

    storage = MagicMock()
    storage.create_tables = AsyncMock()
    storage.save_finding = AsyncMock()
    storage.get_findings = AsyncMock(return_value=[])

    scanner = XXEScanner(hook_bus, storage=storage)

    assert not scanner.is_running
    assert scanner.status()["findings"] == 0

    await scanner.start()
    assert scanner.is_running

    status = scanner.status()
    assert status["running"] is True

    await scanner.stop()
    assert not scanner.is_running


@pytest.mark.asyncio
async def test_scanner_filters_non_xml_json():
    from pwnproxy.core.hooks import HookBus
    from pwnproxy.core.models import Flow

    hook_bus = HookBus()

    storage = MagicMock()
    storage.create_tables = AsyncMock()
    storage.save_finding = AsyncMock()
    storage.get_findings = AsyncMock(return_value=[])

    scanner = XXEScanner(hook_bus, storage=storage)
    await scanner.start()

    flow = Flow(
        id="f1", method="GET",
        url="http://target.com/image.png",
        request_headers={"content-type": "image/png"},
        request_body=None,
        response_headers={},
        response_body=None,
        status_code=200,
    )

    assert scanner._is_scannable(flow) is False

    xml_flow = Flow(
        id="f2", method="POST",
        url="http://target.com/api",
        request_headers={"content-type": "application/xml"},
        request_body=b"<root>test</root>",
        response_headers={},
        response_body=None,
        status_code=200,
    )

    assert scanner._is_scannable(xml_flow) is True

    await scanner.stop()


@pytest.mark.asyncio
async def test_scanner_dedup():
    from pwnproxy.core.hooks import HookBus
    from pwnproxy.core.models import Flow

    hook_bus = HookBus()

    storage = MagicMock()
    storage.create_tables = AsyncMock()
    storage.save_finding = AsyncMock()
    storage.get_findings = AsyncMock(return_value=[])

    scanner = XXEScanner(hook_bus, storage=storage)
    await scanner.start()

    flow = Flow(
        id="f1", method="POST",
        url="http://target.com/api?xml=<root>test</root>",
        request_headers={"content-type": "application/xml"},
        request_body=b"<root>test</root>",
        response_headers={},
        response_body=None,
        status_code=200,
    )

    hook_bus.publish("done", flow)
    hook_bus.publish("done", flow)

    import asyncio
    await asyncio.sleep(0.1)

    assert scanner.flows_processed == 2
    assert len(scanner._dedup) == 1

    await scanner.stop()
