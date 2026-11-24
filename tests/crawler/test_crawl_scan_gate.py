"""``scan_while_crawl`` delivers a crawled flow only when the scope authorises it.

The crawl always stores (History and the live UI depend on it); what the scope
gates is the ``done`` event the auto-scan consumers read. A caller that forgets
the gate must deliver nothing (fail-closed), never scan an unauthorised host.
"""

import tempfile
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from pwnproxy.services.crawler.republish import persist_crawl_flow
from pwnproxy.services.session.manager import ScopeConfig
from pwnproxy.shared.db import Base, FlowRecord
from pwnproxy.shared.flow_filter import FlowFilter

IN_SCOPE_URL = "http://localhost:3000/rest/user/login"
NOISE_URL = "https://content-autofill.googleapis.com/v1/pages"
SCOPE_ON = {"enabled": True, "in_scope": ["localhost:3000"]}


class RecordingHookBus:
    def __init__(self):
        self.events: list[tuple[str, object]] = []

    def publish(self, channel, data):
        self.events.append((channel, data))

    def channels(self) -> list[str]:
        return [channel for channel, _ in self.events]


class TestCrawlRepublishGate:
    def _payload(self, url: str = IN_SCOPE_URL) -> dict:
        return {
            "method": "GET",
            "url": url,
            "request_headers": {},
            "response_headers": {"content-type": "text/html"},
            "response_body": "<html>hi</html>",
            "status_code": 200,
            "_scan_while_crawl": True,
        }

    async def _persist(self, url: str, scan_gate) -> list[str]:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            engine = create_async_engine(f"sqlite+aiosqlite:///{Path(tmp) / 'traffic.db'}")
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            bus = RecordingHookBus()
            try:
                await persist_crawl_flow(engine, bus, self._payload(url), scan_gate=scan_gate)
                factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
                async with factory() as session:
                    rows = (await session.execute(select(FlowRecord))).scalars().all()
                assert [row.url for row in rows] == [url], "storage is never gated"
                return bus.channels()
            finally:
                await engine.dispose()

    @pytest.mark.asyncio
    async def test_scope_off_stores_the_crawl_flow_without_done(self):
        channels = await self._persist(
            IN_SCOPE_URL, FlowFilter(ScopeConfig({"enabled": False, "in_scope": []}))
        )

        assert channels == ["flow_stored"]

    @pytest.mark.asyncio
    async def test_in_scope_crawl_flow_is_delivered(self):
        channels = await self._persist(IN_SCOPE_URL, FlowFilter(ScopeConfig(SCOPE_ON)))

        assert channels == ["flow_stored", "done"]

    @pytest.mark.asyncio
    async def test_out_of_scope_crawl_flow_is_not_delivered(self):
        channels = await self._persist(NOISE_URL, FlowFilter(ScopeConfig(SCOPE_ON)))

        assert channels == ["flow_stored"]

    @pytest.mark.asyncio
    async def test_a_caller_without_a_gate_delivers_nothing(self):
        """Fail-closed: a forgotten gate loses auto-scan, never authorises it."""
        channels = await self._persist(IN_SCOPE_URL, None)

        assert channels == ["flow_stored"]
