import asyncio
from unittest.mock import MagicMock

import pytest

from pwnproxy.shared.models import Flow
from pwnproxy.services.proxy.interceptor.addon import InterceptorAddon
from pwnproxy.services.proxy.interceptor.controller import (
    InterceptorController,
    FlowSnapshot,
)


class _MockHeaders(dict):
    """Mimics mitmproxy's multi-dict headers.items(multi=True)."""
    def items(self, multi=False):
        return list(super().items())


@pytest.fixture
def addon_and_queue():
    q: asyncio.Queue = asyncio.Queue()
    addon = InterceptorAddon(q)
    return addon, q


@pytest.mark.asyncio
async def test_controller_consume_loop(addon_and_queue):
    addon, q = addon_and_queue
    intercepted_flows = []

    def on_intercepted(flow):
        intercepted_flows.append(flow)

    controller = InterceptorController(addon, on_intercepted)
    controller.start()

    flow = Flow(
        id="f1", method="GET", url="http://example.com/",
        request_headers={"Host": "example.com"}, request_body=None,
    )
    q.put_nowait(flow)
    await asyncio.sleep(0.05)

    assert len(intercepted_flows) == 1
    assert intercepted_flows[0].id == "f1"
    assert controller.pending_count == 1

    controller.stop()


@pytest.mark.asyncio
async def test_forward_removes_from_pending(addon_and_queue):
    addon, q = addon_and_queue
    controller = InterceptorController(addon, lambda f: None)

    mflow = MagicMock()
    mflow.id = "f2"
    req = MagicMock()
    req.method = "GET"
    req.url = "http://example.com/"
    req.headers.items.return_value = []
    req.content = None
    req.scheme = "http"
    mflow.request = req
    mflow.response = None
    mflow.error = None

    addon.request(mflow)

    flow = Flow(id="f2", method="GET", url="http://example.com/",
                request_headers={}, request_body=None)
    controller._pending["f2"] = flow
    controller._snapshots["f2"] = FlowSnapshot.from_flow(flow)

    assert controller.pending_count == 1
    controller.forward("f2")
    assert controller.pending_count == 0


@pytest.mark.asyncio
async def test_drop_removes_from_pending(addon_and_queue):
    addon, q = addon_and_queue
    controller = InterceptorController(addon, lambda f: None)

    mflow = MagicMock()
    mflow.id = "f3"
    req = MagicMock()
    req.method = "GET"
    req.url = "http://example.com/"
    req.headers.items.return_value = []
    req.content = None
    req.scheme = "http"
    mflow.request = req
    mflow.response = None
    mflow.error = None

    addon.request(mflow)

    flow = Flow(id="f3", method="GET", url="http://example.com/",
                request_headers={}, request_body=None)
    controller._pending["f3"] = flow
    controller._snapshots["f3"] = FlowSnapshot.from_flow(flow)

    controller.drop("f3")
    assert controller.pending_count == 0


@pytest.mark.asyncio
async def test_toggle_disable_resumes_all(addon_and_queue):
    addon, q = addon_and_queue
    controller = InterceptorController(addon, lambda f: None)
    addon.set_enabled(True)

    mflow = MagicMock()
    mflow.id = "f4"
    req = MagicMock()
    req.method = "GET"
    req.url = "http://example.com/"
    req.headers.items.return_value = []
    req.content = None
    req.scheme = "http"
    mflow.request = req
    mflow.response = None
    mflow.error = None
    addon.request(mflow)

    flow = Flow(id="f4", method="GET", url="http://example.com/",
                request_headers={}, request_body=None)
    controller._pending["f4"] = flow
    controller._snapshots["f4"] = FlowSnapshot.from_flow(flow)

    assert controller.enabled is True
    controller.toggle()
    assert controller.enabled is False
    assert controller.pending_count == 0


@pytest.mark.asyncio
async def test_forward_with_edits_applies_mutations(addon_and_queue):
    addon, q = addon_and_queue
    addon.set_enabled(True)

    mflow = MagicMock()
    mflow.id = "f5"
    req = MagicMock()
    req.method = "GET"
    req.url = "http://old.com/"
    req.headers = _MockHeaders({b"Host": b"old.com"})
    req.content = b"old body"
    req.scheme = "http"
    mflow.request = req
    mflow.response = None
    mflow.error = None
    addon.request(mflow)

    controller = InterceptorController(addon, lambda f: None)
    flow = Flow(
        id="f5", method="GET", url="http://old.com/",
        request_headers={}, request_body=b"old body",
    )
    controller._pending["f5"] = flow
    controller._snapshots["f5"] = FlowSnapshot.from_flow(flow)

    edited = Flow(
        id="f5",
        method="POST",
        url="http://new.com/",
        request_headers={"X-Edited": "true"},
        request_body=b"new body",
    )

    controller.forward_with_edits("f5", edited)

    assert req.method == "POST"
    assert req.url == "http://new.com/"
    assert req.content == b"new body"
    assert controller.pending_count == 0


@pytest.mark.asyncio
async def test_pending_count_tracking(addon_and_queue):
    addon, q = addon_and_queue
    controller = InterceptorController(addon, lambda f: None)

    def add_pending(fid: str):
        flow = Flow(id=fid, method="GET", url="http://x.com/",
                    request_headers={}, request_body=None)
        controller._pending[fid] = flow
        controller._snapshots[fid] = FlowSnapshot.from_flow(flow)

    add_pending("a")
    add_pending("b")
    assert controller.pending_count == 2

    controller.forward("a")
    assert controller.pending_count == 1

    controller.forward("b")
    assert controller.pending_count == 0
