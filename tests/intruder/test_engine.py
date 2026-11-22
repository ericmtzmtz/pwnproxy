from unittest.mock import AsyncMock, patch

import pytest

from pwnproxy.services.intruder.engine import IntruderEngine
from pwnproxy.services.intruder.generator import SniperGenerator
from pwnproxy.services.intruder.parser import parse_markers


class AsyncIterator:
    def __init__(self, items):
        self._items = items

    def __aiter__(self):
        return self._iterate()

    async def _iterate(self):
        for item in self._items:
            yield item


@pytest.mark.asyncio
async def test_engine_respects_concurrency():
    engine = IntruderEngine(concurrency=2)

    mock_client = AsyncMock()
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.content = b"ok"
    mock_response.headers = {}
    mock_client.request.return_value = mock_response

    with patch.object(engine, "_get_client", return_value=mock_client):
        gen = AsyncIterator([
            ("p1", "GET / HTTP/1.1\r\nHost: x.com\r\n\r\n"),
            ("p2", "GET / HTTP/1.1\r\nHost: x.com\r\n\r\n"),
            ("p3", "GET / HTTP/1.1\r\nHost: x.com\r\n\r\n"),
            ("p4", "GET / HTTP/1.1\r\nHost: x.com\r\n\r\n"),
        ])
        results = [r async for r in engine.execute(gen, 4)]

    assert len(results) == 4
    for r in results:
        assert r.status_code == 200
        assert r.response_length == 2

    await engine.close()


@pytest.mark.asyncio
async def test_engine_handles_errors():
    engine = IntruderEngine(concurrency=1)

    mock_client = AsyncMock()
    mock_client.request.side_effect = Exception("Connection refused")

    with patch.object(engine, "_get_client", return_value=mock_client):
        gen = AsyncIterator([
            ("p1", "GET / HTTP/1.1\r\nHost: x.com\r\n\r\n"),
        ])
        results = [r async for r in engine.execute(gen, 1)]

    assert len(results) == 1
    assert results[0].error == "Connection refused"
    assert results[0].status_code == 0


@pytest.mark.asyncio
async def test_results_expose_the_verbatim_request_that_was_sent():
    """Sniper with two markers: each result carries the request sent for it.

    The payload lands in the marker being fuzzed; the other marker keeps its
    base value. The raw request must be §-free so the Repeater can resend it.
    """
    engine = IntruderEngine(concurrency=1)

    mock_client = AsyncMock()
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.content = b"ok"
    mock_response.headers = {}
    mock_client.request.return_value = mock_response

    template, markers = parse_markers(
        "GET /?user=§admin§&pass=§secret§ HTTP/1.1\r\nHost: x.com\r\n\r\n"
    )
    gen = SniperGenerator(template, markers, ["root"])

    with patch.object(engine, "_get_client", return_value=mock_client):
        results = [r async for r in engine.execute(gen, 2)]

    assert [(r.request_id, r.payload, r.raw_request) for r in sorted(results, key=lambda r: r.request_id)] == [
        (1, "root", "GET /?user=root&pass=secret HTTP/1.1\r\nHost: x.com\r\n\r\n"),
        (2, "root", "GET /?user=admin&pass=root HTTP/1.1\r\nHost: x.com\r\n\r\n"),
    ]

    # The exposed request is the one the engine actually sent, not a re-render.
    assert [c.kwargs["url"] for c in mock_client.request.await_args_list] == [
        "https://x.com/?user=root&pass=secret",
        "https://x.com/?user=admin&pass=root",
    ]

    await engine.close()
