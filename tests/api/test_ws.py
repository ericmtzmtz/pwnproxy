import asyncio
import json
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.api.main import app
from pwnproxy.core.db import Base as CoreBase
from pwnproxy.core.hooks import HookBus
from pwnproxy.core.models import Flow


@pytest.fixture
def test_app():
    hook_bus = HookBus()
    app.state.hook_bus = hook_bus

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        traffic_db = str(Path(tmp) / "traffic.db")
        scanner_db = str(Path(tmp) / "scanner_results.db")

        traffic_engine = create_async_engine(f"sqlite+aiosqlite:///{traffic_db}")
        scanner_engine = create_async_engine(f"sqlite+aiosqlite:///{scanner_db}")

        app.state.traffic_engine = traffic_engine
        app.state.scanner_engine = scanner_engine

        with TestClient(app) as client:
            yield client, hook_bus

        asyncio.run(traffic_engine.dispose())
        asyncio.run(scanner_engine.dispose())


@pytest.mark.asyncio
async def test_websocket_receives_events(test_app):
    client, hook_bus = test_app

    with client.websocket_connect("/ws/traffic") as ws:
        flow = Flow(
            id="test-1", method="GET", url="http://example.com/",
            request_headers={}, request_body=None,
            status_code=200, response_headers={}, response_body=None,
        )
        hook_bus.publish("done", flow)
        await asyncio.sleep(0.2)

        data = ws.receive_text()
        parsed = json.loads(data)
        assert parsed["type"] == "flow"
        assert parsed["method"] == "GET"
        assert parsed["url"] == "http://example.com/"
