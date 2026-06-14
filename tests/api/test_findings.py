import asyncio
import tempfile
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from unittest.mock import MagicMock

from pwnproxy.transport.rest.app import app
from pwnproxy.shared.db import Base as CoreBase
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
            async with scanner_engine.begin() as conn:
                await conn.run_sync(lambda c: c.execute(text("""
                    CREATE TABLE IF NOT EXISTS scan_findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, method TEXT, url TEXT,
                        param_name TEXT, param_location TEXT, technique TEXT,
                        dbms TEXT, severity TEXT, confidence TEXT, payload TEXT,
                        evidence TEXT, baseline_ms REAL, response_ms REAL,
                        source_flow_id INTEGER, timestamp TIMESTAMP
                    )
                """)))
                await conn.execute(text(
                    "INSERT INTO scan_findings(method,url,param_name,param_location,"
                    "technique,dbms,severity,confidence,payload,timestamp) "
                    "VALUES('GET','http://x.com/test','id','query',"
                    "'error-based','mysql','high','certain','1=1',:ts)"
                ), {"ts": datetime.utcnow()})
                await conn.commit()

        asyncio.run(_init())

        session_mgr = MagicMock()
        session_mgr.get_scanner_engine.return_value = scanner_engine
        app.state.hook_bus = hook_bus
        app.state.traffic_engine = traffic_engine
        app.state.scanner_engine = scanner_engine
        app.state.token_storage = None
        app.state.interceptor_controller = None
        app.state.repeater_engine = None
        app.state.intruder_engine = None
        app.state.session_manager = session_mgr

        with TestClient(app) as client:
            yield client

        asyncio.run(traffic_engine.dispose())
        asyncio.run(scanner_engine.dispose())


class TestFindings:
    def test_get_sqli_findings(self, test_app):
        r = test_app.get("/api/v1/findings/sqli?limit=10")
        assert r.status_code == 200
        assert len(r.json()) >= 1

    def test_get_unknown_scanner(self, test_app):
        r = test_app.get("/api/v1/findings/unknown")
        assert r.status_code == 200

    def test_list_all_findings(self, test_app):
        r = test_app.get("/api/v1/findings?limit=10")
        assert r.status_code == 200
