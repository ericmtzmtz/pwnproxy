"""E2E-style test: LFI SimpleStage produces a finding with request_data populated."""

import asyncio
import uuid
from unittest.mock import AsyncMock

import httpx

from pwnproxy.plugins.core.chain import DetectionDepth
from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.shared.scan.stages.lfi_stages import SimpleStage
from pwnproxy.plugins.scanners.lfi.signatures import OsSignatureMatcher
from pwnproxy.plugins.scanners.lfi.payloads import UNIX_PAYLOADS


class _FakeReplayer:
    """Replay returns a /etc/passwd response; build_payload_request returns the request."""

    def __init__(self):
        self._resp = httpx.Response(
            200,
            text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            request=httpx.Request("GET", "http://example.com/page.php?page=../../../../../../etc/passwd"),
        )

    async def replay(self, point, payload, timeout=5.0, evasion_level="none"):
        return self._resp

    def build_payload_request(self, point, payload, evasion_level="none"):
        from urllib.parse import urlencode, urlparse, urlunparse

        parsed = urlparse(point.url)
        from urllib.parse import parse_qs

        params = parse_qs(parsed.query, keep_blank_values=True)
        params[point.name] = [payload]
        from urllib.parse import urlencode as ue

        url = urlunparse(parsed._replace(query=ue(params, doseq=True)))
        return httpx.Request("GET", url, headers={"host": "example.com"})


def _point():
    return InjectionPoint(
        name="page",
        value="x",
        location="query",
        flow_id=str(uuid.uuid4()),
        method="GET",
        url="http://example.com/page.php?page=x",
        host="example.com",
        path="/page.php",
        original_headers={"host": "example.com"},
        original_body=None,
    )


def test_simple_stage_sets_request_data():
    replayer = _FakeReplayer()
    stage = SimpleStage(replayer, UNIX_PAYLOADS, OsSignatureMatcher(), evasion_level="none")

    flow = Flow(
        id=str(uuid.uuid4()),
        method="GET",
        url="http://example.com/page.php?page=x",
        request_headers={"host": "example.com"},
        request_body=None,
        status_code=200,
        response_headers={},
        response_body=b"root:x:0:0:",
        duration_ms=1,
        tls=False,
    )

    result = asyncio.run(stage.execute(flow, [_point()]))
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.scanner == "lfi"
    assert finding.request_data is not None
    # Payload injected into URL (slashes percent-encoded by urlencode, like real replayer)
    assert "../../../../../../etc/passwd" in finding.request_data["url"].replace("%2F", "/")
    assert finding.request_data["method"] == "GET"
    assert finding.request_data["headers"]["host"] == "example.com"

