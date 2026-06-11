import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.api.main import app
from pwnproxy.core.db import Base as CoreBase
from pwnproxy.core.hooks import HookBus
from pwnproxy.task.model import create_task_engine, init_task_db
from pwnproxy.task.store import TaskStore


@pytest.fixture
def test_app():
    hook_bus = HookBus()

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        traffic_engine = create_async_engine(f"sqlite+aiosqlite:///{Path(tmp)/'traffic.db'}")
        scanner_engine = create_async_engine(f"sqlite+aiosqlite:///{Path(tmp)/'scanner.db'}")
        task_engine = create_task_engine(str(tmp))

        async def _init():
            async with traffic_engine.begin() as conn:
                await conn.run_sync(CoreBase.metadata.create_all)
            await init_task_db(task_engine)
        asyncio.run(_init())

        task_store = TaskStore(task_engine)
        asyncio.run(task_store.init())

        session_mgr = MagicMock()
        session_mgr.active_name = "default"

        app.state.hook_bus = hook_bus
        app.state.traffic_engine = traffic_engine
        app.state.scanner_engine = scanner_engine
        app.state.token_storage = None
        app.state.interceptor_controller = None
        app.state.repeater_engine = None
        app.state.intruder_engine = None
        app.state.task_store = task_store
        app.state.session_manager = session_mgr
        app.state.plugin_loader = None

        with TestClient(app) as client:
            yield client, task_store

        asyncio.run(traffic_engine.dispose())
        asyncio.run(scanner_engine.dispose())
        asyncio.run(task_engine.dispose())


class TestRepeater:
    def test_send_request(self, test_app):
        client, task_store = test_app

        with patch("pwnproxy.api.routers.repeater.httpx.AsyncClient") as mock_client:
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.headers = {"content-type": "text/plain"}
            mock_resp.text = "Hello World"
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__.return_value = mock_ctx
            mock_client.return_value = mock_ctx
            mock_ctx.request.return_value = mock_resp

            r = client.post("/api/v1/repeater/send", json={
                "raw_request": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            })

        assert r.status_code == 200
        body = r.json()
        assert body["status_code"] == 200
        assert "Hello World" in body["body_preview"]
        assert body["task_id"]
