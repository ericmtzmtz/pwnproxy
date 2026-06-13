import asyncio
from unittest.mock import MagicMock

import pytest

from pwnproxy.services.proxy.interceptor.addon import InterceptorAddon


def _make_mock_httpflow(flow_id: str = "test1") -> MagicMock:
    req = MagicMock()
    req.method = "GET"
    req.url = "http://example.com/"
    req.headers.items.return_value = [(b"Host", b"example.com")]
    req.content = b"hello"
    req.scheme = "http"
    req.timestamp_start = 1000.0

    res = MagicMock()
    res.status_code = 200
    res.headers.items.return_value = [(b"content-type", b"text/plain")]
    res.content = b"world"
    res.timestamp_end = 1001.0

    flow = MagicMock()
    flow.id = flow_id
    flow.request = req
    flow.response = res
    flow.error = None
    return flow


@pytest.mark.asyncio
async def test_default_enabled():
    q: asyncio.Queue = asyncio.Queue()
    addon = InterceptorAddon(q)
    assert addon.enabled is False


@pytest.mark.asyncio
async def test_intercept_resume_lifecycle():
    q: asyncio.Queue = asyncio.Queue()
    addon = InterceptorAddon(q)
    addon.set_enabled(True)

    mflow = _make_mock_httpflow("f1")
    addon.request(mflow)
    mflow.intercept.assert_called_once()

    addon.resume("f1")
    mflow.resume.assert_called_once()

    assert addon.pending_count() == 0


@pytest.mark.asyncio
async def test_intercept_kill():
    q: asyncio.Queue = asyncio.Queue()
    addon = InterceptorAddon(q)
    addon.set_enabled(True)

    mflow = _make_mock_httpflow("f2")
    addon.request(mflow)

    addon.kill("f2")
    mflow.kill.assert_called_once()

    assert addon.pending_count() == 0


@pytest.mark.asyncio
async def test_intercept_response_hook():
    q: asyncio.Queue = asyncio.Queue()
    addon = InterceptorAddon(q)
    addon.set_enabled(True)

    mflow = _make_mock_httpflow("f3")
    addon.response(mflow)
    mflow.intercept.assert_called_once()

    assert addon.pending_count() == 1


@pytest.mark.asyncio
async def test_disabled_does_not_intercept():
    q: asyncio.Queue = asyncio.Queue()
    addon = InterceptorAddon(q)
    addon.set_enabled(False)

    mflow = _make_mock_httpflow("f4")
    addon.request(mflow)
    mflow.intercept.assert_not_called()

    assert addon.pending_count() == 0


@pytest.mark.asyncio
async def test_resume_all():
    q: asyncio.Queue = asyncio.Queue()
    addon = InterceptorAddon(q)
    addon.set_enabled(True)

    f1 = _make_mock_httpflow("f1")
    f2 = _make_mock_httpflow("f2")
    addon.request(f1)
    addon.response(f2)

    assert addon.pending_count() == 2

    addon.resume_all()
    f1.resume.assert_called_once()
    f2.resume.assert_called_once()
    assert addon.pending_count() == 0


@pytest.mark.asyncio
async def test_resume_unknown_flow_no_error():
    q: asyncio.Queue = asyncio.Queue()
    addon = InterceptorAddon(q)

    result = addon.resume("nonexistent")
    assert result is None


@pytest.mark.asyncio
async def test_kill_unknown_flow_no_error():
    q: asyncio.Queue = asyncio.Queue()
    addon = InterceptorAddon(q)

    result = addon.kill("nonexistent")
    assert result is None


@pytest.mark.asyncio
async def test_queue_receives_flow_on_intercept():
    q: asyncio.Queue = asyncio.Queue()
    addon = InterceptorAddon(q)
    addon.set_enabled(True)

    mflow = _make_mock_httpflow("f-queue")
    addon.request(mflow)

    received = await asyncio.wait_for(q.get(), timeout=1.0)
    assert received.id == "f-queue"
    assert received.method == "GET"
