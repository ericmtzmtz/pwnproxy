"""A captured flow reaches a plugin only when the scope allows active scanning.

These are the delivery-path tests the rule needs: a fake plugin that counts what
it receives, driven through the proxy worker relay and the embedded proxy addons.
In every case the negative case is the one that matters — with the scope off the
flow is still captured and stored, and the plugin sees nothing. The crawler's
``scan_while_crawl`` has its own file (``tests/crawler/test_crawl_scan_gate.py``).
"""

import asyncio
import tempfile
from pathlib import Path

import mitmproxy.connection as conn
import pytest
from mitmproxy import http
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from pwnproxy.plugins.core.base import PluginMetadata, ScannerPlugin
from pwnproxy.plugins.core.loader import PluginLoader
from pwnproxy.services.proxy.addons.hook_relay import HookRelayAddon
from pwnproxy.services.proxy.addons.storage import StorageAddon
from pwnproxy.services.proxy.relay import relay_worker_event
from pwnproxy.services.session.manager import ScopeConfig
from pwnproxy.shared.bus.transports.inprocess import InProcessBus
from pwnproxy.shared.db import Base, FlowRecord
from pwnproxy.shared.flow_filter import FlowFilter
from pwnproxy.shared.hooks import HookBus

IN_SCOPE_URL = "http://localhost:3000/rest/user/login"
NOISE_URL = "https://content-autofill.googleapis.com/v1/pages"
SCOPE_ON = {"enabled": True, "in_scope": ["localhost:3000"]}


class CountingFlowScanner(ScannerPlugin):
    """Fake scanner that records every flow handed to it."""

    metadata = PluginMetadata(
        name="counting-flow",
        version="1.0.0",
        author="tests",
        consumes=["flow"],
        produces=["finding"],
    )

    def __init__(self):
        super().__init__()
        self.seen: list[str] = []

    async def on_flow(self, flow):
        self.seen.append(flow.url)
        if False:  # pragma: no cover - makes this an async generator
            yield None


class CountingDoneScanner(CountingFlowScanner):
    """Same, on the ``done`` channel the proxy worker also publishes to."""

    metadata = PluginMetadata(
        name="counting-done",
        version="1.0.0",
        author="tests",
        consumes=["done"],
        produces=["finding"],
    )


def _flow_payload(url: str) -> dict:
    return {
        "id": "f-1",
        "method": "GET",
        "url": url,
        "request_headers": {"host": "localhost:3000"},
        "status_code": 200,
    }


async def _wait_for(predicate, timeout: float = 2.0) -> None:
    """Wait until ``predicate()`` is true, failing instead of hanging."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        assert loop.time() < deadline, "the expected event never arrived"
        await asyncio.sleep(0.01)


class RelayHarness:
    """PluginLoader on a real bus, fed by ``relay_worker_event``."""

    def __init__(self, scope: ScopeConfig):
        self.hook_bus = HookBus()
        self.bus = InProcessBus()
        self.loader = PluginLoader(hook_bus=self.hook_bus, bus=self.bus)
        self.flow_scanner = CountingFlowScanner()
        self.done_scanner = CountingDoneScanner()
        self.flow_filter = FlowFilter(scope)

    async def start(self) -> None:
        await self.loader.load(self.flow_scanner)
        await self.loader.load(self.done_scanner)
        await self.loader.activate(self.flow_scanner.metadata.name)
        await self.loader.activate(self.done_scanner.metadata.name)
        # The consumer tasks subscribe when they start; publishing before that
        # would drop the event and the test would race itself.
        await _wait_for(
            lambda: self.bus.subscriber_count("flow") == 1
            and self.bus.subscriber_count("done") == 1
        )

    async def stop(self) -> None:
        await self.loader.shutdown()

    def deliver(self, url: str, *, topic: str = "proxy.flow") -> None:
        relay_worker_event(
            topic,
            _flow_payload(url),
            hook_bus=self.hook_bus,
            bus=self.bus,
            flow_filter=self.flow_filter,
            session_name="JuiceShop",
        )

    def deliver_stored(self, url: str) -> None:
        """The worker's StorageAddon announces the row it already wrote."""
        relay_worker_event(
            "proxy.flow_stored",
            {"id": 7, "method": "GET", "url": url, "status_code": 200},
            hook_bus=self.hook_bus,
            bus=self.bus,
            flow_filter=self.flow_filter,
            session_name="JuiceShop",
        )


class TestWorkerRelayGate:
    @pytest.mark.asyncio
    async def test_scope_off_stores_the_flow_but_the_plugins_get_nothing(self):
        harness = RelayHarness(ScopeConfig({"enabled": False, "in_scope": ["localhost:3000"]}))
        stored = harness.hook_bus.register("flow_stored")
        await harness.start()
        try:
            harness.deliver(IN_SCOPE_URL)
            harness.deliver_stored(IN_SCOPE_URL)
            await asyncio.sleep(0.2)

            # Capture kept working: the stored-flow event is relayed as always.
            assert stored.get_nowait()["url"] == IN_SCOPE_URL
            assert (harness.flow_scanner.seen, harness.done_scanner.seen) == ([], [])
        finally:
            await harness.stop()

    @pytest.mark.asyncio
    async def test_in_scope_flow_reaches_the_plugin(self):
        harness = RelayHarness(ScopeConfig(SCOPE_ON))
        await harness.start()
        try:
            harness.deliver(IN_SCOPE_URL)
            await _wait_for(lambda: len(harness.flow_scanner.seen) == 1)

            assert harness.flow_scanner.seen == [IN_SCOPE_URL]
        finally:
            await harness.stop()

    @pytest.mark.asyncio
    async def test_scope_on_but_out_of_scope_url_reaches_no_plugin(self):
        harness = RelayHarness(ScopeConfig(SCOPE_ON))
        await harness.start()
        try:
            harness.deliver(NOISE_URL)
            await asyncio.sleep(0.2)

            assert harness.flow_scanner.seen == []
        finally:
            await harness.stop()

    @pytest.mark.asyncio
    async def test_scope_on_without_include_rules_reaches_no_plugin(self):
        harness = RelayHarness(ScopeConfig({"enabled": True, "in_scope": []}))
        await harness.start()
        try:
            harness.deliver(IN_SCOPE_URL)
            await asyncio.sleep(0.2)

            assert harness.flow_scanner.seen == []
        finally:
            await harness.stop()

    @pytest.mark.asyncio
    async def test_done_channel_is_gated_as_well(self):
        """The worker also publishes ``proxy.done``: same rule, no exception."""
        harness = RelayHarness(ScopeConfig({"enabled": False, "in_scope": []}))
        await harness.start()
        try:
            harness.deliver(IN_SCOPE_URL, topic="proxy.done")
            await asyncio.sleep(0.2)

            assert harness.done_scanner.seen == []
        finally:
            await harness.stop()

    @pytest.mark.asyncio
    async def test_turning_the_scope_on_hot_delivers_the_next_flow(self):
        harness = RelayHarness(ScopeConfig({"enabled": False, "in_scope": []}))
        await harness.start()
        try:
            harness.deliver(IN_SCOPE_URL)
            await asyncio.sleep(0.2)
            assert harness.flow_scanner.seen == []

            # Same loader, same filter: the apply path a scope change takes.
            harness.flow_filter.set_scope(ScopeConfig(SCOPE_ON))
            harness.deliver(IN_SCOPE_URL)
            await _wait_for(lambda: len(harness.flow_scanner.seen) == 1)

            assert harness.flow_scanner.seen == [IN_SCOPE_URL]
        finally:
            await harness.stop()


# ── Embedded proxy addons (HookRelayAddon + StorageAddon) ────────────────────


def _mitm_flow(url: str) -> http.HTTPFlow:
    client = conn.Client(peername=("127.0.0.1", 1234), sockname=("1.2.3.4", 5678))
    server = conn.Server(peername=("93.184.216.34", 443), address=("93.184.216.34", 443))
    flow = http.HTTPFlow(client, server)
    flow.request = http.Request.make("GET", url)
    flow.response = http.Response.make(200, b"ok", {"content-type": "text/plain"})
    return flow


class RecordingHookBus:
    def __init__(self):
        self.events: list[tuple[str, object]] = []

    def publish(self, channel, data):
        self.events.append((channel, data))

    def channels(self) -> list[str]:
        return [channel for channel, _ in self.events]


class TestEmbeddedAddonGate:
    def test_scope_off_publishes_response_but_not_the_scan_channels(self):
        bus = RecordingHookBus()
        relay = HookRelayAddon(
            bus, flow_filter=FlowFilter(ScopeConfig({"enabled": False, "in_scope": []}))
        )

        relay.response(_mitm_flow(NOISE_URL))

        assert bus.channels() == ["response"]

    def test_in_scope_flow_publishes_the_scan_channels(self):
        bus = RecordingHookBus()
        relay = HookRelayAddon(bus, flow_filter=FlowFilter(ScopeConfig(SCOPE_ON)))

        relay.response(_mitm_flow(IN_SCOPE_URL))

        assert bus.channels() == ["response", "done", "flow"]

    @pytest.mark.asyncio
    async def test_scope_off_stores_the_flow_without_the_done_event(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            engine = create_async_engine(f"sqlite+aiosqlite:///{Path(tmp) / 'traffic.db'}")
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            addon = StorageAddon(
                engine,
                hook_bus=RecordingHookBus(),
                flow_filter=FlowFilter(ScopeConfig({"enabled": False, "in_scope": []})),
            )
            try:
                addon.response(_mitm_flow(NOISE_URL))
                await asyncio.gather(*list(addon._background_tasks))

                factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
                async with factory() as session:
                    rows = (await session.execute(select(FlowRecord))).scalars().all()

                assert ([row.url for row in rows], addon.hook_bus.channels()) == (
                    [NOISE_URL],
                    ["flow_stored"],
                )
            finally:
                await engine.dispose()

