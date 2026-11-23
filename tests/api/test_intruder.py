import asyncio
import contextlib
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from starlette.requests import Request as StarletteRequest

from pwnproxy.services.intruder.engine import IntruderEngine
from pwnproxy.services.session.store import TaskStore
from pwnproxy.shared.db import Base as CoreBase
from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.task_model import create_task_engine, init_task_db
from pwnproxy.transport.rest.app import app
from pwnproxy.transport.rest.intruder import IntruderResultItem
from pwnproxy.transport.rest.tasks import _run_intruder


@pytest.fixture
def test_app(api_client):
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

        wordlist = str(Path(tmp) / "words.txt")
        Path(wordlist).write_text("admin\nroot\ntest")

        session_mgr = MagicMock()
        session_mgr.active_name = "default"
        session_mgr.task_store = task_store

        app.state.hook_bus = hook_bus
        app.state.traffic_engine = traffic_engine
        app.state.scanner_engine = scanner_engine
        app.state.token_storage = None
        app.state.interceptor_controller = None
        app.state.repeater_engine = None
        app.state.intruder_engine = IntruderEngine(concurrency=1)
        app.state.task_store = task_store
        app.state.session_manager = session_mgr
        app.state.plugin_loader = None

        with api_client(app) as client:
            yield client, wordlist

        asyncio.run(traffic_engine.dispose())
        asyncio.run(scanner_engine.dispose())
        asyncio.run(task_engine.dispose())


class TestIntruder:
    def test_run_sniper(self, test_app):
        client, wl = test_app
        r = client.post("/api/v1/intruder/run", json={
            "raw_request": "GET /?user=§admin§ HTTP/1.1\r\nHost: x.com\r\n\r\n",
            "mode": "sniper",
            "wordlist_path": wl,
            "concurrency": 1,
        })
        assert r.status_code in (200, 500)
        if r.status_code == 200:
            data = r.json()
            assert data["total"] == 3

    def test_no_markers_error(self, test_app):
        client, wl = test_app
        r = client.post("/api/v1/intruder/run", json={
            "raw_request": "GET / HTTP/1.1\r\nHost: x.com\r\n\r\n",
            "mode": "sniper",
            "wordlist_path": wl,
        })
        assert r.status_code == 400


_FIXED_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 2\r\n"
    b"\r\n"
    b"ok"
)


async def _start_local_server() -> asyncio.AbstractServer:
    """Loopback HTTP server answering every request with a fixed response."""

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(Exception):
            await reader.readuntil(b"\r\n\r\n")
        writer.write(_FIXED_RESPONSE)
        with contextlib.suppress(Exception):
            await writer.drain()
        writer.close()

    return await asyncio.start_server(_handle, "127.0.0.1", 0)


class TestIntruderResultRawRequest:
    """Each intruder result reports the HTTP request that was actually sent."""

    @pytest.mark.asyncio
    async def test_results_carry_the_request_sent_for_each_payload(self, tmp_path):
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("alice\nbob")

        engine = create_task_engine(str(tmp_path / "tasks.db"))
        await init_task_db(engine)
        store = TaskStore(engine)
        await store.init()

        server = await _start_local_server()
        port = server.sockets[0].getsockname()[1]
        raw_request = (
            f"GET /?user=§x§ HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "X-Forwarded-Proto: http\r\n"
            "\r\n"
        )
        config = {
            "raw_request": raw_request,
            "mode": "sniper",
            "wordlist_path": str(wordlist),
            "concurrency": 1,
        }
        task_id = await store.create("intruder", config, session_name="default")

        intruder_engine = IntruderEngine(concurrency=1)
        request = StarletteRequest(
            {"type": "http", "app": SimpleNamespace(state=SimpleNamespace(intruder_engine=intruder_engine))}
        )

        try:
            await _run_intruder(config, task_id, store, request)
        finally:
            await intruder_engine.close()
            server.close()
            await server.wait_closed()
            await engine.dispose()

        task = await store.get(task_id)
        assert task["status"] == "completed", task.get("error")
        results = sorted(task["result"]["results"], key=lambda r: r["request_id"])
        sent = [
            {
                **r,
                # Wall-clock measurement, irrelevant to the contract under test.
                "timing_ms": "<ms>",
            }
            for r in results
        ]
        assert sent == [
            {
                "request_id": 1,
                "payload": "alice",
                "status_code": 200,
                "response_length": 2,
                "timing_ms": "<ms>",
                "response_headers": {"content-type": "text/plain", "content-length": "2"},
                "response_body": "ok",
                "error": None,
                "raw_request": (
                    f"GET /?user=alice HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                    "X-Forwarded-Proto: http\r\n\r\n"
                ),
            },
            {
                "request_id": 2,
                "payload": "bob",
                "status_code": 200,
                "response_length": 2,
                "timing_ms": "<ms>",
                "response_headers": {"content-type": "text/plain", "content-length": "2"},
                "response_body": "ok",
                "error": None,
                "raw_request": (
                    f"GET /?user=bob HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                    "X-Forwarded-Proto: http\r\n\r\n"
                ),
            },
        ]

    def test_result_saved_without_raw_request_reads_empty(self):
        """Tasks persisted before the field existed must still deserialize."""
        legacy = {
            "request_id": 1,
            "payload": "admin",
            "status_code": 200,
            "response_length": 5,
            "timing_ms": 1.0,
        }

        assert IntruderResultItem(**legacy).raw_request == ""
