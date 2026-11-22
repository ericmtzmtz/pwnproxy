"""`GET /tasks` list endpoint: `detail=true` inlines each task's config/result.

The Repeater history renders the raw request and the response of every saved
task in one round-trip, so the list endpoint must be able to inline the same
payload `GET /tasks/{id}` returns. Without `detail` the response stays exactly
as before (summaries only).
"""

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.services.session.store import TaskStore
from pwnproxy.shared.db import Base as CoreBase
from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.task_model import create_task_engine, init_task_db
from pwnproxy.transport.rest.app import app

RAW_ONE = "GET /admin HTTP/1.1\r\nHost: shop.test\r\n\r\n"
RAW_TWO = "POST /login HTTP/1.1\r\nHost: shop.test\r\n\r\nuser=a"


def _strip_timestamps(task: dict) -> dict:
    """Replace the wall-clock timestamps, which are assigned by the store."""
    out = dict(task)
    for key in ("created_at", "completed_at"):
        if key in out:
            out[key] = "<set>" if out[key] is not None else None
    return out


def _seed(store: TaskStore, task_type: str, config: dict, result: dict, session: str) -> str:
    async def _run() -> str:
        task_id = await store.create(task_type, config, session_name=session)
        await store.update(task_id, status="running")
        await store.update(task_id, status="completed", progress=1, total=1, result=result)
        return task_id

    return asyncio.run(_run())


@pytest.fixture
def test_app():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        traffic_engine = create_async_engine(f"sqlite+aiosqlite:///{Path(tmp) / 'traffic.db'}")
        scanner_engine = create_async_engine(f"sqlite+aiosqlite:///{Path(tmp) / 'scanner.db'}")
        task_engine = create_task_engine(str(tmp))

        async def _init() -> None:
            async with traffic_engine.begin() as conn:
                await conn.run_sync(CoreBase.metadata.create_all)
            await init_task_db(task_engine)

        asyncio.run(_init())

        task_store = TaskStore(task_engine)
        asyncio.run(task_store.init())

        repeater_result = {
            "status_code": 200,
            "headers": {"content-type": "text/plain"},
            "body": "hello",
            "duration_ms": 12.5,
        }
        first = _seed(task_store, "repeater", {"raw_request": RAW_ONE}, repeater_result, "default")
        second = _seed(task_store, "repeater", {"raw_request": RAW_TWO}, repeater_result, "default")
        # Another session: must never leak into the active session's listing.
        foreign = _seed(
            task_store, "repeater", {"raw_request": "GET /other HTTP/1.1\r\n\r\n"}, repeater_result, "other"
        )

        session_mgr = MagicMock()
        session_mgr.active_name = "default"
        session_mgr.task_store = task_store

        app.state.hook_bus = HookBus()
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
            yield client, {"first": first, "second": second, "foreign": foreign}

        asyncio.run(traffic_engine.dispose())
        asyncio.run(scanner_engine.dispose())
        asyncio.run(task_engine.dispose())


class TestTaskListDetail:
    def test_detail_true_inlines_config_and_result(self, test_app):
        client, ids = test_app

        r = client.get("/api/v1/tasks", params={"type": "repeater", "detail": "true"})

        assert r.status_code == 200, r.text
        assert [_strip_timestamps(t) for t in r.json()["tasks"]] == [
            {
                "id": ids["second"],
                "type": "repeater",
                "status": "completed",
                "progress": 1,
                "total": 1,
                "created_at": "<set>",
                "completed_at": "<set>",
                "config": {"raw_request": RAW_TWO},
                "result": {
                    "status_code": 200,
                    "headers": {"content-type": "text/plain"},
                    "body": "hello",
                    "duration_ms": 12.5,
                },
            },
            {
                "id": ids["first"],
                "type": "repeater",
                "status": "completed",
                "progress": 1,
                "total": 1,
                "created_at": "<set>",
                "completed_at": "<set>",
                "config": {"raw_request": RAW_ONE},
                "result": {
                    "status_code": 200,
                    "headers": {"content-type": "text/plain"},
                    "body": "hello",
                    "duration_ms": 12.5,
                },
            },
        ]

    def test_without_detail_response_is_unchanged(self, test_app):
        client, ids = test_app

        r = client.get("/api/v1/tasks", params={"type": "repeater"})

        assert r.status_code == 200, r.text
        assert [_strip_timestamps(t) for t in r.json()["tasks"]] == [
            {
                "id": ids["second"],
                "type": "repeater",
                "status": "completed",
                "progress": 1,
                "total": 1,
                "created_at": "<set>",
                "completed_at": "<set>",
            },
            {
                "id": ids["first"],
                "type": "repeater",
                "status": "completed",
                "progress": 1,
                "total": 1,
                "created_at": "<set>",
                "completed_at": "<set>",
            },
        ]

    def test_detail_true_keeps_active_session_filter(self, test_app):
        client, ids = test_app

        r = client.get("/api/v1/tasks", params={"type": "repeater", "detail": "true"})

        assert r.status_code == 200, r.text
        body = r.json()
        assert [t["id"] for t in body["tasks"]] == [ids["second"], ids["first"]]
        assert ids["foreign"] not in [t["id"] for t in body["tasks"]]

    def test_detail_false_is_same_as_absent(self, test_app):
        client, ids = test_app

        r = client.get("/api/v1/tasks", params={"type": "repeater", "detail": "false"})

        assert r.status_code == 200, r.text
        assert [_strip_timestamps(t) for t in r.json()["tasks"]] == [
            {
                "id": ids["second"],
                "type": "repeater",
                "status": "completed",
                "progress": 1,
                "total": 1,
                "created_at": "<set>",
                "completed_at": "<set>",
            },
            {
                "id": ids["first"],
                "type": "repeater",
                "status": "completed",
                "progress": 1,
                "total": 1,
                "created_at": "<set>",
                "completed_at": "<set>",
            },
        ]

    def test_limit_above_max_rejected(self, test_app):
        client, _ids = test_app

        r = client.get("/api/v1/tasks", params={"limit": 201})

        assert r.status_code == 422, r.text
