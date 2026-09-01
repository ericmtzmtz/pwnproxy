import asyncio
import tempfile
from pathlib import Path

import mitmproxy.connection as conn
import pytest
from mitmproxy import http
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from pwnproxy.services.proxy.addons.storage import StorageAddon
from pwnproxy.services.session.manager import ScopeConfig
from pwnproxy.shared.db import Base, FlowRecord
from pwnproxy.shared.flow_filter import FlowFilter


def _flow(url: str) -> http.HTTPFlow:
    client = conn.Client(peername=("127.0.0.1", 1234), sockname=("1.2.3.4", 5678))
    server = conn.Server(peername=("93.184.216.34", 443), address=("93.184.216.34", 443))
    f = http.HTTPFlow(client, server)
    f.request = http.Request.make("GET", url)
    return f


class FakeHookBus:
    def __init__(self):
        self.events = []

    def publish(self, channel, data):
        self.events.append((channel, data))


@pytest.fixture
def engine_factory():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = str(Path(tmp) / "traffic.db")
        engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")

        async def _init():
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

        asyncio.run(_init())
        yield engine
        asyncio.run(engine.dispose())


async def _count(engine) -> int:
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        return (await session.execute(select(FlowRecord))).scalars().all()


async def _drain(addon: StorageAddon) -> None:
    tasks = list(addon._background_tasks)
    if tasks:
        await asyncio.gather(*tasks)


class TestStorageAddonScope:
    @pytest.mark.asyncio
    async def test_out_of_scope_flow_not_persisted_or_emitted(self, engine_factory):
        bus = FakeHookBus()
        scope = ScopeConfig({"enabled": True, "in_scope": ["localhost:4280"]})
        addon = StorageAddon(engine_factory, hook_bus=bus, flow_filter=FlowFilter(scope))

        addon.response(_flow("https://gj.mmstat.com/collect"))
        await _drain(addon)

        rows = await _count(engine_factory)
        assert rows == []
        assert all(ch != "done" for ch, _ in bus.events)
        assert all(ch != "flow_stored" for ch, _ in bus.events)

    @pytest.mark.asyncio
    async def test_in_scope_flow_persisted(self, engine_factory):
        bus = FakeHookBus()
        scope = ScopeConfig({"enabled": True, "in_scope": ["localhost:4280"]})
        addon = StorageAddon(engine_factory, hook_bus=bus, flow_filter=FlowFilter(scope))

        addon.response(_flow("http://localhost:4280/vulnerabilities/sqli/?id=1"))
        await _drain(addon)

        rows = await _count(engine_factory)
        assert len(rows) == 1
        assert rows[0].url == "http://localhost:4280/vulnerabilities/sqli/?id=1"

    @pytest.mark.asyncio
    async def test_no_filter_keeps_legacy_behavior(self, engine_factory):
        bus = FakeHookBus()
        addon = StorageAddon(engine_factory, hook_bus=bus)

        addon.response(_flow("https://gj.mmstat.com/collect"))
        addon.response(_flow("http://localhost:4280/x"))
        await _drain(addon)

        rows = await _count(engine_factory)
        assert len(rows) == 2

    @pytest.mark.asyncio
    async def test_dvwa_in_scope_mmstat_out(self, engine_factory):
        """E2E semantics: with scope localhost:4280, DVWA traffic persists and
        emits done; mmstat.com is neither persisted nor auto-scanned."""
        bus = FakeHookBus()
        scope = ScopeConfig({"enabled": True, "in_scope": ["localhost:4280"]})
        addon = StorageAddon(engine_factory, hook_bus=bus, flow_filter=FlowFilter(scope))

        addon.response(_flow("http://localhost:4280/vulnerabilities/sqli/?id=1"))
        addon.response(_flow("https://gj.mmstat.com/collect"))
        await _drain(addon)

        rows = await _count(engine_factory)
        assert len(rows) == 1
        assert rows[0].url == "http://localhost:4280/vulnerabilities/sqli/?id=1"

        done_urls = [d["url"] for ch, d in bus.events if ch == "done"]
        assert done_urls == ["http://localhost:4280/vulnerabilities/sqli/?id=1"]
