import asyncio
import tempfile
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from pwnproxy.api.main import app
from pwnproxy.core.db import Base as CoreBase, FlowRecord, init_db
from pwnproxy.core.hooks import HookBus


@pytest.fixture
def test_app():
    hook_bus = HookBus()
    app.state.hook_bus = hook_bus

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        traffic_db = str(Path(tmp) / "traffic.db")
        scanner_db = str(Path(tmp) / "scanner_results.db")

        traffic_engine = create_async_engine(f"sqlite+aiosqlite:///{traffic_db}")
        scanner_engine = create_async_engine(f"sqlite+aiosqlite:///{scanner_db}")

        async def _init():
            async with traffic_engine.begin() as conn:
                await conn.run_sync(CoreBase.metadata.create_all)

        asyncio.run(_init())

        app.state.traffic_engine = traffic_engine
        app.state.scanner_engine = scanner_engine

        factory = sessionmaker(traffic_engine, class_=AsyncSession, expire_on_commit=False)

        async def _seed():
            async with factory() as session:
                session.add(FlowRecord(
                    method="GET", url="http://example.com/",
                    request_headers={"Host": "example.com"},
                    request_body=None, status_code=200,
                    response_headers={}, response_body=None,
                    timestamp=datetime.utcnow(),
                ))
                await session.commit()

        asyncio.run(_seed())

        with TestClient(app) as client:
            yield client

        asyncio.run(traffic_engine.dispose())
        asyncio.run(scanner_engine.dispose())


class TestScannerTrigger:
    def test_trigger_valid_scanner(self, test_app):
        response = test_app.post(
            "/api/v1/scanners/trigger",
            json={"flow_id": 1, "scanners": ["sqli", "xss"]},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "triggered"
        assert response.json()["flow_id"] == 1

    def test_trigger_unknown_scanner(self, test_app):
        response = test_app.post(
            "/api/v1/scanners/trigger",
            json={"flow_id": 1, "scanners": ["unknown"]},
        )
        assert response.status_code == 400

    def test_trigger_nonexistent_flow(self, test_app):
        response = test_app.post(
            "/api/v1/scanners/trigger",
            json={"flow_id": 999, "scanners": ["sqli"]},
        )
        assert response.status_code == 404
