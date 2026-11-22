"""POST /scan must hand the SSRF plugin the callback port of *this* API process.

The server is started with ``pwnproxy start --callback-port``, which binds the
OOB listener; the port is stored on ``app.state.callback_port``. A scan launched
from that process has to use it, otherwise the SSRF payloads knock on the
default port while the listener sits somewhere else and no blind SSRF is ever
confirmed.
"""

import importlib
import inspect
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from starlette.requests import Request as StarletteRequest

from apps.terminal.cli.scan import _resolve_scanner_config
from pwnproxy.services.session.store import TaskStore
from pwnproxy.shared.ports import DEFAULT_CALLBACK_PORT
from pwnproxy.shared.task_model import create_task_engine, init_task_db

plugins_rest = importlib.import_module("pwnproxy.transport.rest.plugins")


async def _wait_terminal(store, task_id, timeout_s=5.0):
    import asyncio

    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout_s
    while loop.time() < deadline:
        task = await store.get(task_id)
        if task and task["status"] in ("completed", "failed", "cancelled"):
            return task
        await asyncio.sleep(0.02)
    raise AssertionError("scan task did not reach terminal state in time")


async def _launch_ssrf_scan(tmp_path, callback_port):
    """Run POST /scan end to end, returning the loader the scan really built.

    ``callback_port`` is set on ``app.state`` only when not None, so the
    fallback path (server started without the attribute) is covered too.
    """
    engine = create_task_engine(str(tmp_path / "tasks.db"))
    await init_task_db(engine)
    store = TaskStore(engine)
    await store.init()

    mgr = SimpleNamespace(active_name="default", task_store=store)
    state = SimpleNamespace(
        session_manager=mgr,
        task_store=store,
        hook_bus=None,
        plugin_loader=None,
    )
    if callback_port is not None:
        state.callback_port = callback_port
    request = StarletteRequest({"type": "http", "app": SimpleNamespace(state=state)})

    captured = {}

    async def fake_scan_target(loader, url, timeout, **kwargs):
        # The loader is unloaded right after the task finishes, so read the
        # value the scan actually used while it is still alive.
        captured["ssrf_callback_port"] = loader.get_plugin("ssrf")._scanner.callback_port
        captured["_loader"] = loader
        return []

    try:
        with patch("apps.terminal.cli.scan._scan_target", new=fake_scan_target):
            resp = await plugins_rest.launch_scan(
                url="http://target.local/product?url=http://example.com",
                request=request,
                scanners="ssrf",
            )
            captured["task"] = await _wait_terminal(store, resp["task_id"])
    finally:
        loader = captured.pop("_loader", None)
        if loader is not None:
            await loader.shutdown()  # closes the SSRF replayer's http client
        await engine.dispose()
    return captured


@pytest.mark.asyncio
async def test_scan_uses_the_callback_port_of_the_api_process(tmp_path):
    captured = await _launch_ssrf_scan(tmp_path, callback_port=19992)

    assert (captured["task"]["status"], captured["ssrf_callback_port"]) == ("completed", 19992)


@pytest.mark.asyncio
async def test_scan_falls_back_to_the_shared_callback_port(tmp_path):
    captured = await _launch_ssrf_scan(tmp_path, callback_port=None)

    assert (captured["task"]["status"], captured["ssrf_callback_port"]) == (
        "completed",
        DEFAULT_CALLBACK_PORT,
    )
    # The constant the OOB listener and the payloads share is 17173.
    assert DEFAULT_CALLBACK_PORT == 17173


def test_resolve_scanner_config_carries_the_callback_port():
    assert _resolve_scanner_config("deep", "aggressive", 19994) == {
        "depth": "deep",
        "evasion_level": "aggressive",
        "callback_port": 19994,
    }


def test_resolve_scanner_config_defaults_to_the_shared_callback_port():
    assert _resolve_scanner_config() == {
        "depth": "fast",
        "evasion_level": "none",
        "callback_port": DEFAULT_CALLBACK_PORT,
    }


def test_api_server_stores_the_callback_port_on_app_state():
    """``/scan`` reads ``app.state.callback_port``; ``start`` must pass it in.

    Behavioral coverage of ``start_api_server`` would boot uvicorn and the whole
    triage/room stack, so this guards the wiring the same way
    ``tests/architecture/test_ports.py`` guards the other defaults.
    """
    from apps.api.server import start_api_server
    from apps.terminal.cli.start import start

    parameters = inspect.signature(start_api_server).parameters
    assert (
        parameters["callback_port"].default,
        "app.state.callback_port = callback_port" in inspect.getsource(start_api_server),
        "callback_port=callback_port" in inspect.getsource(start),
    ) == (DEFAULT_CALLBACK_PORT, True, True)
