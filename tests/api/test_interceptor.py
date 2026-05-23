import asyncio
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.api.main import app
from pwnproxy.core.db import Base as CoreBase
from pwnproxy.core.hooks import HookBus


@pytest.fixture
def test_app():
    hook_bus = HookBus()
    controller = MagicMock()
    controller.enabled = True
    controller.pending_count = 3

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        traffic_engine = create_async_engine(f"sqlite+aiosqlite:///{Path(tmp)/'traffic.db'}")
        scanner_engine = create_async_engine(f"sqlite+aiosqlite:///{Path(tmp)/'scanner.db'}")

        async def _init():
            async with traffic_engine.begin() as conn:
                await conn.run_sync(CoreBase.metadata.create_all)
        asyncio.run(_init())

        app.state.hook_bus = hook_bus
        app.state.traffic_engine = traffic_engine
        app.state.scanner_engine = scanner_engine
        app.state.token_storage = None
        app.state.interceptor_controller = controller
        app.state.repeater_engine = None
        app.state.intruder_engine = None

        with TestClient(app) as client:
            yield client

        asyncio.run(traffic_engine.dispose())
        asyncio.run(scanner_engine.dispose())


class TestInterceptor:
    def test_get_status(self, test_app):
        r = test_app.get("/api/v1/interceptor/status")
        assert r.status_code == 200
        assert r.json()["enabled"] is True
        assert r.json()["pending_count"] == 3

    def test_toggle(self, test_app):
        r = test_app.put("/api/v1/interceptor/toggle")
        assert r.status_code == 200
