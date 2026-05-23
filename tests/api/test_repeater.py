import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.api.main import app
from pwnproxy.core.db import Base as CoreBase
from pwnproxy.core.hooks import HookBus


@pytest.fixture
def test_app():
    hook_bus = HookBus()

    repeater = AsyncMock()
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "text/plain"}
    mock_resp.content = b"Hello World"
    repeater.send.return_value = mock_resp

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
        app.state.interceptor_controller = None
        app.state.repeater_engine = repeater
        app.state.intruder_engine = None

        with TestClient(app) as client:
            yield client

        asyncio.run(traffic_engine.dispose())
        asyncio.run(scanner_engine.dispose())


class TestRepeater:
    def test_send_request(self, test_app):
        r = test_app.post("/api/v1/repeater/send", json={
            "raw_request": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        })
        assert r.status_code == 200
        body = r.json()
        assert body["status_code"] == 200
        assert "Hello World" in body["body_preview"]
