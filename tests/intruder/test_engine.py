import pytest
from unittest.mock import AsyncMock, patch

from pwnproxy.intruder.engine import IntruderEngine


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
