import asyncio
import tempfile
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
        session_mgr.active_name = "demo"
        # used for traffic room auth (list returns active session)
        session_mgr.list.return_value = [{"name": "demo"}]
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
                session.add_all(
                    [
                        FlowRecord(
                            method="GET",
                            url="http://example.com/",
                            request_headers={"Host": "example.com"},
                            request_body=None,
                            status_code=200,
                            response_headers={},
                            response_body=None,
                        ),
                    ]
                )
                await session.commit()

        asyncio.run(_seed())

        with TestClient(app) as client:
            yield client

        asyncio.run(traffic_engine.dispose())
        asyncio.run(scanner_engine.dispose())


class TestCommentAPI:
    def test_create_and_list(self, test_app):
        # create
        r = test_app.post("/api/v1/flows/1/comments", json={"body": "hello", "kind": "note"})
        assert r.status_code == 201, r.text
        cid = r.json()["id"]
        assert r.json()["body"] == "hello"
        assert r.json()["kind"] == "note"
        assert r.json()["resolved"] is False

        # list
        r = test_app.get("/api/v1/flows/1/comments")
        assert r.status_code == 200
        assert len(r.json()) == 1
        assert r.json()[0]["id"] == cid

        # comment_count appears on flow
        r = test_app.get("/api/v1/flows/1")
        assert r.status_code == 200
        assert r.json()["comment_count"] == 1

        r = test_app.get("/api/v1/flows?limit=10")
        assert r.status_code == 200
        flows = r.json()
        f1 = next(f for f in flows if f["id"] == 1)
        assert f1["comment_count"] == 1

    def test_create_404_on_missing_flow(self, test_app):
        r = test_app.post("/api/v1/flows/9999/comments", json={"body": "x"})
        assert r.status_code == 404

    def test_invalid_kind(self, test_app):
        r = test_app.post("/api/v1/flows/1/comments", json={"body": "x", "kind": "bad"})
        assert r.status_code == 422

    def test_update(self, test_app):
        r = test_app.post("/api/v1/flows/1/comments", json={"body": "orig"})
        cid = r.json()["id"]
        r = test_app.patch(f"/api/v1/flows/1/comments/{cid}", json={"body": "new", "kind": "flag", "resolved": True})
        assert r.status_code == 200
        assert r.json()["body"] == "new"
        assert r.json()["kind"] == "flag"
        assert r.json()["resolved"] is True
        assert r.json()["updated_at"] is not None

    def test_delete(self, test_app):
        r = test_app.post("/api/v1/flows/1/comments", json={"body": "to delete"})
        cid = r.json()["id"]
        r = test_app.delete(f"/api/v1/flows/1/comments/{cid}")
        assert r.status_code == 204
        r = test_app.get("/api/v1/flows/1/comments")
        assert r.json() == []
        # comment_count back to 0
        r = test_app.get("/api/v1/flows/1")
        assert r.json()["comment_count"] == 0

    def test_cascade_delete_on_flow(self, test_app):
        test_app.post("/api/v1/flows/1/comments", json={"body": "a"})
        test_app.post("/api/v1/flows/1/comments", json={"body": "b"})
        r = test_app.delete("/api/v1/flows/1")
        assert r.status_code == 204
        # flow gone
        r = test_app.get("/api/v1/flows/1")
        assert r.status_code == 404

    def test_comment_events_carry_session_id(self, test_app):
        hook_bus = test_app.app.state.hook_bus if hasattr(test_app, "app") else None
        # Use app.state.hook_bus directly
        from pwnproxy.transport.rest.app import app as app_mod

        hook_bus = app_mod.state.hook_bus
        q = hook_bus.register("comment.created")
        test_app.post("/api/v1/flows/1/comments", json={"body": "event test"})
        # HookBus is in-process, queue should have event
        import asyncio

        async def _get():
            try:
                return await asyncio.wait_for(q.get(), timeout=1.0)
            except asyncio.TimeoutError:
                return None

        evt = asyncio.run(_get())
        assert evt is not None
        assert evt.get("session_id") == "demo"
        assert evt.get("flow_id") == 1


class TestCommentRoomDispatcher:
    def test_comment_channel_routes_to_traffic(self):
        from pwnproxy.transport.ws.events import RoomDispatcher, RoomManager

        bus = HookBus()
        mgr = RoomManager()
        disp = RoomDispatcher(bus, mgr)
        # _room_for should map comment.created -> traffic:demo
        room = disp._room_for("comment.created", "demo", None)
        assert room == "traffic:demo"
        room2 = disp._room_for("comment.updated", "demo", None)
        assert room2 == "traffic:demo"
        room3 = disp._room_for("comment.deleted", "demo", None)
        assert room3 == "traffic:demo"
        # untagged -> None
        assert disp._room_for("comment.created", None, None) is None

    def test_untagged_comment_not_fanned_out(self):
        from pwnproxy.transport.ws.events import RoomDispatcher, RoomManager

        async def _run():
            bus = HookBus()
            mgr = RoomManager()
            disp = RoomDispatcher(bus, mgr)
            await disp.start()
            # publish untagged comment.created (no session_id)
            bus.publish("comment.created", {"flow_id": 1, "comment_id": 1, "body": "x"})
            await asyncio.sleep(0.05)
            # untagged counter should increase (dispatcher drops)
            assert disp._untagged >= 1
            # tagged should not increase untagged
            before = disp._untagged
            bus.publish("comment.created", {"session_id": "demo", "flow_id": 1, "comment_id": 2, "body": "y"})
            await asyncio.sleep(0.05)
            assert disp._untagged == before
            await disp.stop()

        asyncio.run(_run())
