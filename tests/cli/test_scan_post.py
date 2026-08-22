"""Tests for POST/body support in the scan CLI (_scan_target)."""

import asyncio

import httpx
import pytest

from apps.terminal.cli import scan as scan_mod
from apps.terminal.cli.scan import _scan_target


class _NullLoader:
    """PluginLoader stand-in: records the flow it was handed."""

    def __init__(self):
        self.seen_flow = None

    async def run_scan(self, flow, depth="fast", evasion_level="none"):
        self.seen_flow = flow
        return []


def test_get_flow_defaults():
    """GET without body produces a GET Flow with request_body None."""
    loader = _NullLoader()
    asyncio.run(_scan_target(loader, "http://example.com/x", 10))
    assert loader.seen_flow.method == "GET"
    assert loader.seen_flow.request_body is None


def test_post_flow_carries_method_body_content_type(monkeypatch):
    """POST + body + content-type must produce a Flow with all three."""
    captured = {}

    class T(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            captured["request"] = request
            return httpx.Response(200, text="<ok/>", request=request)

    RealAsyncClient = httpx.AsyncClient

    def fake_client(*args, **kwargs):
        kwargs["transport"] = T()
        return RealAsyncClient(*args, **kwargs)

    monkeypatch.setattr(scan_mod.httpx, "AsyncClient", fake_client)

    loader = _NullLoader()
    asyncio.run(
        _scan_target(
            loader,
            "http://example.com/xxe",
            10,
            method="POST",
            body="<reset><login>bee</login></reset>",
            extra_headers={"Content-Type": "text/xml"},
        )
    )

    assert captured["request"].method == "POST"
    assert captured["request"].headers.get("content-type") == "text/xml"
    assert captured["request"].content == b"<reset><login>bee</login></reset>"

    flow = loader.seen_flow
    assert flow.method == "POST"
    assert flow.request_body == b"<reset><login>bee</login></reset>"
    assert flow.request_headers.get("Content-Type") == "text/xml"
