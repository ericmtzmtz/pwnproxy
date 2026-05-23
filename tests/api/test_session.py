import asyncio
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.api.main import app
from pwnproxy.core.db import Base as CoreBase
from pwnproxy.core.hooks import HookBus
from pwnproxy.modules.session_manager.models import TokenCandidate
from pwnproxy.modules.session_manager.storage import TokenStorage


@pytest.fixture
def test_app():
    hook_bus = HookBus()
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        traffic_engine = create_async_engine(f"sqlite+aiosqlite:///{Path(tmp)/'traffic.db'}")
        scanner_engine = create_async_engine(f"sqlite+aiosqlite:///{Path(tmp)/'scanner.db'}")

        async def _init():
            async with traffic_engine.begin() as conn:
                await conn.run_sync(CoreBase.metadata.create_all)
        asyncio.run(_init())

        storage = TokenStorage(db_path=str(Path(tmp) / "sessions.db"))
        asyncio.run(storage.init())
        asyncio.run(storage.save([
            TokenCandidate(token_type="jwt", token_value="eyJh.eyJzdWIiOiJhZG1pbiJ9.sig",
                          label="admin-jwt", source_url="http://x.com/login"),
            TokenCandidate(token_type="cookie", token_value="sessionid=abc123",
                          label="session", source_url="http://x.com/"),
        ]))

        app.state.hook_bus = hook_bus
        app.state.traffic_engine = traffic_engine
        app.state.scanner_engine = scanner_engine
        app.state.token_storage = storage
        app.state.interceptor_controller = None
        app.state.repeater_engine = None
        app.state.intruder_engine = None

        with TestClient(app) as client:
            yield client

        asyncio.run(storage.close())
        asyncio.run(traffic_engine.dispose())
        asyncio.run(scanner_engine.dispose())


class TestSessions:
    def test_list_sessions(self, test_app):
        r = test_app.get("/api/v1/sessions")
        assert r.status_code == 200
        data = r.json()
        assert len(data) >= 2

    def test_filter_by_type(self, test_app):
        r = test_app.get("/api/v1/sessions?token_type=jwt")
        assert r.status_code == 200
        data = r.json()
        assert all(t["token_type"] == "jwt" for t in data)

    def test_get_by_id(self, test_app):
        r = test_app.get("/api/v1/sessions/1")
        assert r.status_code == 200
        assert r.json()["id"] == 1

    def test_get_not_found(self, test_app):
        r = test_app.get("/api/v1/sessions/9999")
        assert r.status_code == 404

    def test_delete(self, test_app):
        r = test_app.delete("/api/v1/sessions/1")
        assert r.status_code == 204

    def test_delete_not_found(self, test_app):
        r = test_app.delete("/api/v1/sessions/9999")
        assert r.status_code == 404
