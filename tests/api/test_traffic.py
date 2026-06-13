import asyncio
import tempfile
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from unittest.mock import MagicMock

from pwnproxy.transport.rest.app import app
from pwnproxy.shared.db import Base as CoreBase, FlowRecord
from pwnproxy.shared.hooks import HookBus


@pytest.fixture
def test_app():
    hook_bus = HookBus()
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        traffic_db = str(Path(tmp) / "traffic.db")
        scanner_db = str(Path(tmp) / "scanner_results.db")
        traffic_engine = create_async_engine(f"sqlite+aiosqlite:///{traffic_db}")
        scanner_engine = create_async_engine(f"sqlite+aiosqlite:///{scanner_db}")

        async def _init():
            async with traffic_engine.begin() as conn:
                await conn.run_sync(CoreBase.metadata.create_all)

        asyncio.run(_init())

        session_mgr = MagicMock()
        session_mgr.get_traffic_engine.return_value = traffic_engine
        app.state.hook_bus = hook_bus
        app.state.traffic_engine = traffic_engine
        app.state.scanner_engine = scanner_engine
        app.state.token_storage = None
        app.state.interceptor_controller = None
        app.state.repeater_engine = None
        app.state.intruder_engine = None
        app.state.session_manager = session_mgr

        factory = sessionmaker(traffic_engine, class_=AsyncSession, expire_on_commit=False)
        async def _seed():
            async with factory() as session:
                session.add_all([
                    FlowRecord(method="GET", url="http://example.com/",
                        request_headers={"Host": "example.com"}, request_body=None,
                        status_code=200, response_headers={}, response_body=None),
                    FlowRecord(method="POST", url="http://example.com/login",
                        request_headers={"Host": "example.com"}, request_body=b'{"u":"a"}',
                        status_code=401, response_headers={}, response_body=None),
                ])
                await session.commit()
        asyncio.run(_seed())

        with TestClient(app) as client:
            yield client

        asyncio.run(traffic_engine.dispose())
        asyncio.run(scanner_engine.dispose())


class TestTraffic:
    def test_list_flows(self, test_app):
        r = test_app.get("/api/v1/flows?limit=10")
        assert r.status_code == 200
        assert len(r.json()) >= 2

    def test_get_flow_by_id(self, test_app):
        r = test_app.get("/api/v1/flows/1")
        assert r.status_code == 200
        assert r.json()["id"] == 1

    def test_get_flow_not_found(self, test_app):
        r = test_app.get("/api/v1/flows/9999")
        assert r.status_code == 404
