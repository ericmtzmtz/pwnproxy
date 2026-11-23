"""Findings detected by a plugin must reach the live WebSocket streams.

The regression this file protects (``openspec/changes/live-plugin-findings``):
a plugin publishes a ``Finding`` **dataclass** on the raw ``finding`` channel;
the loader's storage consumer saves it, and the saved row is announced on
``finding.stored``. ``/ws/findings`` and ``/ws/events`` subscribe to that channel
and forward ``{"type": "finding", **row}``. Before the change the relays read the
raw channel and did ``{"type": "finding", **dataclass}`` → ``TypeError`` that
killed the connection, so a plugin finding never showed up in the UI.

Every rule has its negative: a failed save publishes nothing, an unserialisable
event leaves the socket alive, and a room for another session receives nothing.
"""

import asyncio
import contextlib
import json
import threading
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine

from pwnproxy.plugins.core import loader as loader_module
from pwnproxy.plugins.core.base import PluginMetadata, PwnPlugin, ScannerPlugin
from pwnproxy.plugins.core.loader import PluginLoader
from pwnproxy.shared.bus.topics import FINDING_STORED
from pwnproxy.shared.findings.events import publish_stored_finding
from pwnproxy.shared.findings.storage import FindingStorage
from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.finding import Finding
from pwnproxy.transport.rest.app import app

#: Fixed detection time: the row round-trips through SQLite (naive datetime).
DETECTED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)

#: The whole event the UI receives for the finding the plugin below yields.
EXPECTED_FINDING_EVENT = {
    "type": "finding",
    "id": 1,
    "scanner": "e2e-yield",
    "url": "http://target.local/item?id=1",
    "method": "GET",
    "param_name": "id",
    "param_location": "query",
    "technique": "error-based",
    "severity": "high",
    "confidence": "confirmed",
    "payload": "' OR 1=1-- -",
    "evidence": "SQL syntax error in the response body",
    "timestamp": "2026-01-02 03:04:05",
    "extra": {},
    "request_data": None,
    "triage_score": None,
    "triage_verdict": None,
    "triage_method": None,
    "triage_reason": None,
    "session_id": "demo",
}

#: ``POST /api/v1/findings`` body; ``sqli`` is a built-in name in the catalog.
POST_BODY = {
    "scanner": "sqli",
    "url": "http://target.local/item?id=1",
    "method": "GET",
    "param_name": "id",
    "param_location": "query",
    "technique": "error-based",
    "severity": "high",
    "confidence": "confirmed",
    "payload": "' OR 1=1-- -",
    "evidence": "SQL syntax error in the response body",
}


def _finding(scanner: str) -> Finding:
    """A complete finding; only ``scanner`` varies between the test plugins."""
    return Finding(
        scanner=scanner,
        url="http://target.local/item?id=1",
        method="GET",
        param_name="id",
        param_location="query",
        technique="error-based",
        severity="high",
        confidence="confirmed",
        payload="' OR 1=1-- -",
        evidence="SQL syntax error in the response body",
        timestamp=DETECTED_AT,
    )


class _YieldingPlugin(PwnPlugin):
    """A plugin that detects on every flow, exactly like an installed scanner."""

    def __init__(self, name: str = "e2e-yield") -> None:
        super().__init__(PluginMetadata(
            name=name, version="1.0.0", consumes=["flow"], produces=["finding"],
        ))

    async def on_flow(self, flow: Flow):
        yield _finding(self.metadata.name)


class _BuiltinStyleScanner(ScannerPlugin):
    """A built-in scanner: same base class and load route as the shipped ones."""

    async def on_flow(self, flow: Flow):
        yield _finding("e2e-builtin")


class _ExplodesOnStr:
    """Not JSON-serialisable: ``json.dumps(default=str)`` blows up on it."""

    def __str__(self) -> str:
        raise RuntimeError("cannot render this object")


def _flow() -> Flow:
    return Flow(id="flow-1", method="GET", url="http://target.local/item?id=1", request_headers={})


def _rows(engine) -> list[dict]:
    """Read the session's ``findings`` table through the ORM."""
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm import sessionmaker

    from pwnproxy.shared.findings.storage import FindingORM

    async def _read():
        factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with factory() as session:
            result = await session.execute(select(FindingORM).order_by(FindingORM.id))
            return [
                {c.name: getattr(row, c.name) for c in FindingORM.__table__.columns}
                for row in result.scalars().all()
            ]

    return asyncio.run(_read())


def _receive_json(ws, timeout: float = 10.0) -> dict:
    """Receive one JSON message, failing (not hanging) when none arrives.

    ``WebSocketTestSession.receive_json`` blocks forever, and a hanging test is
    not a red test: the read happens in a thread so a missing event fails with a
    clear message after ``timeout`` seconds.
    """
    box: dict = {}

    def _read() -> None:
        try:
            box["message"] = ws.receive_json()
        except Exception as exc:  # closed socket, wrong payload, ...
            box["error"] = exc

    reader = threading.Thread(target=_read, daemon=True)
    reader.start()
    reader.join(timeout)
    assert not reader.is_alive(), f"no WebSocket event within {timeout}s"
    assert "error" not in box, f"WebSocket read failed: {box.get('error')!r}"
    return box["message"]


@pytest.fixture
def live(tmp_path, monkeypatch):
    """The real app with a real loader, storage and session manager.

    Discovery is patched to find nothing: each test loads its own plugin
    explicitly, so no shipped scanner tries to reach the network.
    """
    hook_bus = HookBus()
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'scanner_results.db'}")
    asyncio.run(FindingStorage(engine).create_table())

    session_manager = MagicMock()
    session_manager.active_name = "demo"
    session_manager.get_scanner_engine.return_value = engine
    session_manager.list.return_value = [{"name": "demo"}, {"name": "other"}]

    loader = PluginLoader(hook_bus)
    loader._session_manager = session_manager
    monkeypatch.setattr(loader_module, "discover_plugins", lambda path=None: [])

    app.state.hook_bus = hook_bus
    app.state.plugin_loader = loader
    app.state.session_manager = session_manager

    with TestClient(app) as client:
        live_app = SimpleNamespace(client=client, bus=hook_bus, engine=engine, loader=loader)

        def start(*plugins, builtin: bool = False) -> None:
            """Load the given plugins on the app loop and run ``loader.start()``."""
            async def _run() -> None:
                for plugin in plugins:
                    if builtin:
                        await loader.load_builtin(plugin, config={})
                    else:
                        await loader.load(plugin)
                await loader.start()

            client.portal.call(_run)

        live_app.start = start
        try:
            yield live_app
        finally:
            # Teardown must not hide the test's own failure.
            with contextlib.suppress(Exception):
                client.portal.call(loader.shutdown)

    asyncio.run(engine.dispose())
    for attribute in ("hook_bus", "plugin_loader", "session_manager"):
        delattr(app.state, attribute)


def test_a_plugin_finding_is_stored_once_and_reaches_both_streams(live):
    """The main regression: ``yield Finding`` → one row → one event per stream."""
    live.start(_YieldingPlugin())

    with live.client.websocket_connect("/ws/findings") as findings_ws:
        with live.client.websocket_connect("/ws/events") as events_ws:
            live.bus.publish("flow", _flow())
            from_findings = _receive_json(findings_ws)
            from_events = _receive_json(events_ws)

    assert (from_findings, from_events, len(_rows(live.engine))) == (
        EXPECTED_FINDING_EVENT,
        EXPECTED_FINDING_EVENT,
        1,
    )


def test_a_builtin_loaded_scanner_takes_the_same_path(live):
    """A shipped scanner goes through ``load_builtin`` + ``ScannerPlugin.on_flow``."""
    live.start(_BuiltinStyleScanner(), builtin=True)

    with live.client.websocket_connect("/ws/events") as events_ws:
        live.bus.publish("flow", _flow())
        event = _receive_json(events_ws)

    assert (
        event["type"],
        event["scanner"],
        event["id"],
        event["session_id"],
        len(_rows(live.engine)),
    ) == ("finding", "e2e-builtin", 1, "demo", 1)


def test_post_findings_emits_one_event_per_stream_and_one_row(live):
    """The endpoint announces the row once; the raw channel keeps its shape."""
    live.start()  # the loader's storage consumer runs: a duplicate would be a 2nd row
    raw_channel = live.bus.register("finding")

    with live.client.websocket_connect("/ws/findings") as findings_ws:
        with live.client.websocket_connect("/ws/events") as events_ws:
            response = live.client.post("/api/v1/findings", json=POST_BODY)
            from_findings = _receive_json(findings_ws)
            from_events = _receive_json(events_ws)
            raw_event = live.client.portal.call(raw_channel.get)

    assert (
        response.status_code,
        from_findings["type"],
        from_findings["id"],
        from_findings["session_id"],
        from_events["id"],
        raw_event["id"],
        raw_event["session_id"],
        len(_rows(live.engine)),
    ) == (201, "finding", 1, "demo", 1, 1, "demo", 1)


def test_a_failed_save_emits_no_event(live):
    """No row means no event: neither channel may announce a phantom finding."""
    live.start()
    stored_channel = live.bus.register(FINDING_STORED)
    raw_channel = live.bus.register("finding")

    async def _drop() -> None:
        async with live.engine.begin() as conn:
            await conn.execute(text("DROP TABLE findings"))

    asyncio.run(_drop())
    response = live.client.post("/api/v1/findings", json=POST_BODY)

    assert (
        response.status_code,
        response.json(),
        stored_channel.has_data,
        raw_channel.has_data,
    ) == (500, {"detail": "could not save finding"}, False, False)


def test_the_relays_survive_an_unserialisable_event(live):
    """A bad message is logged and skipped; the next finding still arrives."""
    live.start()
    good_event = {"id": 5, "scanner": "xss", "url": "http://a", "session_id": "demo"}

    with live.client.websocket_connect("/ws/findings") as findings_ws:
        with live.client.websocket_connect("/ws/events") as events_ws:
            live.bus.publish(FINDING_STORED, _finding("sqli"))               # not a dict
            live.bus.publish(FINDING_STORED, {"scanner": "xss", "boom": _ExplodesOnStr()})
            publish_stored_finding(live.bus, good_event)
            from_findings = _receive_json(findings_ws)
            from_events = _receive_json(events_ws)

    expected = {"type": "finding", **good_event}
    assert (from_findings, from_events) == (expected, expected)


class _FakeWS:
    """Minimal room socket: records what the dispatcher sends."""

    def __init__(self) -> None:
        self.sent: list[str] = []

    async def accept(self) -> None:
        pass

    async def send_text(self, message: str) -> None:
        self.sent.append(message)


@pytest.mark.asyncio
async def test_a_findings_room_only_receives_its_own_session():
    """``finding.stored`` feeds ``findings:{session}`` and nothing else."""
    from pwnproxy.transport.ws.events import RoomDispatcher, RoomManager

    hook_bus = HookBus()
    room_manager = RoomManager()
    dispatcher = RoomDispatcher(hook_bus, room_manager)
    await dispatcher.start()
    own = _FakeWS()
    other = _FakeWS()
    await room_manager.connect("findings:demo", own)
    await room_manager.connect("findings:other", other)

    row = {"id": 3, "scanner": "sqli", "url": "http://a", "severity": "high"}
    publish_stored_finding(hook_bus, row, "demo")
    await asyncio.sleep(0.3)
    await dispatcher.stop()

    assert (
        [json.loads(message) for message in own.sent],
        other.sent,
    ) == (
        [{"type": "finding", "session_id": "demo", "job_id": None, "data": {**row, "session_id": "demo"}}],
        [],
    )
