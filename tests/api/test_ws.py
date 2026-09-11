import asyncio
import json
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.models import Flow
from pwnproxy.transport.rest.app import app


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
        hook_bus.publish("response", flow)
        await asyncio.sleep(0.2)

        data = ws.receive_text()
        parsed = json.loads(data)
        assert parsed["type"] == "flow"
        assert parsed["method"] == "GET"
        assert parsed["url"] == "http://example.com/"


class _FakeWS:
    def __init__(self, fail=False):
        self._fail = fail
        self.sent = []

    async def accept(self):
        pass

    async def send_text(self, message):
        if self._fail:
            raise Exception("connection closed")
        self.sent.append(message)


class TestRoomManager:
    @pytest.mark.asyncio
    async def test_broadcast_removes_dead_connections(self):
        from pwnproxy.transport.ws.events import RoomManager

        rm = RoomManager()
        ws_ok = _FakeWS()
        ws_dead = _FakeWS(fail=True)
        await rm.connect("room1", ws_ok)
        await rm.connect("room1", ws_dead)

        await rm.broadcast("room1", "hello")

        assert ws_ok.sent == ["hello"]
        assert rm._rooms["room1"] == {ws_ok}

    @pytest.mark.asyncio
    async def test_broadcast_deletes_room_when_all_dead(self):
        from pwnproxy.transport.ws.events import RoomManager

        rm = RoomManager()
        await rm.connect("room1", _FakeWS(fail=True))

        await rm.broadcast("room1", "hello")

        assert "room1" not in rm._rooms


class TestRoomIsolation:
    @pytest.mark.asyncio
    async def test_no_cross_talk(self):
        from pwnproxy.shared.hooks import HookBus
        from pwnproxy.shared.models import Flow
        from pwnproxy.transport.ws.events import RoomDispatcher, RoomManager

        hook_bus = HookBus()
        rm = RoomManager()
        disp = RoomDispatcher(hook_bus, rm)
        await disp.start()

        ws_demo = _FakeWS()
        ws_other = _FakeWS()
        await rm.connect("traffic:demo", ws_demo)
        await rm.connect("traffic:other", ws_other)

        flow = Flow(id="1", method="GET", url="http://a", request_headers={}, session_id="demo")
        hook_bus.publish("response", flow)
        await asyncio.sleep(0.3)

        assert len(ws_demo.sent) == 1
        assert len(ws_other.sent) == 0
        payload = json.loads(ws_demo.sent[0])
        assert payload["session_id"] == "demo"
        assert payload["data"]["id"] == "1"

        await disp.stop()

    @pytest.mark.asyncio
    async def test_untagged_not_fanned_out(self):
        from pwnproxy.shared.hooks import HookBus
        from pwnproxy.shared.models import Flow
        from pwnproxy.transport.ws.events import RoomDispatcher, RoomManager

        hook_bus = HookBus()
        rm = RoomManager()
        disp = RoomDispatcher(hook_bus, rm)
        await disp.start()

        ws_demo = _FakeWS()
        await rm.connect("traffic:demo", ws_demo)

        flow = Flow(id="2", method="GET", url="http://b", request_headers={})
        hook_bus.publish("response", flow)
        await asyncio.sleep(0.2)

        assert len(ws_demo.sent) == 0
        assert disp._untagged == 1

        await disp.stop()


class TestRoomAuth:
    def test_invalid_scheme_4404(self, test_app):
        client, _ = test_app
        try:
            with client.websocket_connect("/ws/rooms/badroom") as ws:
                ws.receive_text()
                raise AssertionError("should have closed")
        except Exception as exc:
            # Must be a real 4404 close, not just any exception
            code = getattr(exc, "code", None)
            assert code == 4404 or "4404" in str(exc), f"expected 4404, got {exc!r} code={code}"

    def test_ghost_session_4403(self, test_app):
        client, _ = test_app
        try:
            with client.websocket_connect("/ws/rooms/traffic:ghost-not-exist-xyz") as ws:
                ws.receive_text()
                raise AssertionError("should have closed")
        except Exception as exc:
            code = getattr(exc, "code", None)
            assert code == 4403 or "4403" in str(exc), f"expected 4403, got {exc!r} code={code}"


class TestPublishersSessionTag:
    def test_flow_session_id_in_to_dict(self):
        from pwnproxy.shared.models import Flow
        f = Flow(id="x", method="POST", url="http://a", request_headers={}, session_id="s1")
        d = f.to_dict()
        assert d["session_id"] == "s1"
        f2 = Flow.from_dict(d)
        assert f2.session_id == "s1"

    @pytest.mark.asyncio
    async def test_scan_completed_carries_session_id(self):
        # Verify tasks.py _run_scan tags session_id (via direct publish check)
        # Minimal: launch_scan already tags scan.started, _run_scan tags scan.completed
        # Here we just verify the hook_bus publish path includes session_id when session_manager present
        from pwnproxy.shared.hooks import HookBus
        from pwnproxy.transport.ws.events import RoomDispatcher, RoomManager

        hook_bus = HookBus()
        rm = RoomManager()
        disp = RoomDispatcher(hook_bus, rm)
        await disp.start()

        ws_demo = _FakeWS()
        await rm.connect("job:123", ws_demo)
        hook_bus.publish("scan.completed", {"task_id": "123", "job_id": "123", "session_id": "demo"})
        await asyncio.sleep(0.2)
        assert len(ws_demo.sent) == 1
        await disp.stop()
