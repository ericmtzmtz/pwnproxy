"""REST POST /scan launches a scan task against a request target (method/body/content_type).

Covers the scan-request-target spec: method/body/content_type accepted by the
endpoint, persisted in task config, propagated to the scan target runner, and
the GET/HEAD body-discard guard.
"""

import importlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from starlette.requests import Request as StarletteRequest

from pwnproxy.services.session.store import TaskStore
from pwnproxy.shared.task_model import create_task_engine, init_task_db

plugins_rest = importlib.import_module("pwnproxy.transport.rest.plugins")


async def _wait_terminal(store, task_id, timeout_s=5.0):
    import asyncio
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        task = await store.get(task_id)
        if task and task["status"] in ("completed", "failed", "cancelled"):
            return task
        await asyncio.sleep(0.02)
    raise AssertionError("scan task did not reach terminal state in time")


async def _launch_scan(store, **params):
    """Call the route function directly (like test_reports does), returning
    (resp, request) after the background task reaches a terminal state."""
    mgr = SimpleNamespace(active_name="default", task_store=store)
    app = SimpleNamespace(state=SimpleNamespace(
        session_manager=mgr, task_store=store, hook_bus=None, plugin_loader=None,
    ))
    request = StarletteRequest({"type": "http", "app": app})
    resp = await plugins_rest.launch_scan(request=request, **params)
    task = await _wait_terminal(store, resp["task_id"])
    return resp, task


_NULL_LOADER = SimpleNamespace()


@pytest.mark.asyncio
async def test_scan_launch_with_method_body_content_type(tmp_path):
    engine = create_task_engine(str(tmp_path / "tasks.db"))
    await init_task_db(engine)
    store = TaskStore(engine)
    await store.init()

    with patch("apps.terminal.cli.scan._scan_target", new=AsyncMock(return_value=[])) as scan_target, \
         patch("apps.terminal.cli.scan._build_scan_loader", new=AsyncMock(return_value=_NULL_LOADER)):
        resp, task = await _launch_scan(
            store,
            url="http://target.local/xxe",
            scanners="xxe",
            method="POST",
            body="<reset><login>x</login></reset>",
            content_type="text/xml",
        )

    assert resp["status"] == "running"
    assert task["status"] == "completed", task.get("error")

    config = task["config"]
    assert config["url"] == "http://target.local/xxe"
    assert config["method"] == "POST"
    assert config["body"] == "<reset><login>x</login></reset>"
    assert config["content_type"] == "text/xml"
    assert config["scanners"] == "xxe"

    call = scan_target.call_args
    assert call is not None
    kwargs = call.kwargs
    assert kwargs["method"] == "POST"
    assert kwargs["body"] == "<reset><login>x</login></reset>"
    assert kwargs["extra_headers"].get("Content-Type") == "text/xml"

    await engine.dispose()


@pytest.mark.asyncio
async def test_scan_launch_get_is_default(tmp_path):
    engine = create_task_engine(str(tmp_path / "tasks.db"))
    await init_task_db(engine)
    store = TaskStore(engine)
    await store.init()

    with patch("apps.terminal.cli.scan._scan_target", new=AsyncMock(return_value=[])) as scan_target, \
         patch("apps.terminal.cli.scan._build_scan_loader", new=AsyncMock(return_value=_NULL_LOADER)):
        resp, task = await _launch_scan(
            store,
            url="http://target.local/",
        )

    assert task["config"]["method"] == "GET"
    assert "body" not in task["config"]
    kwargs = scan_target.call_args.kwargs
    assert kwargs["method"] == "GET"
    assert kwargs["body"] is None

    await engine.dispose()


@pytest.mark.asyncio
async def test_scan_launch_get_with_body_discards_body(tmp_path):
    engine = create_task_engine(str(tmp_path / "tasks.db"))
    await init_task_db(engine)
    store = TaskStore(engine)
    await store.init()

    with patch("apps.terminal.cli.scan._scan_target", new=AsyncMock(return_value=[])) as scan_target, \
         patch("apps.terminal.cli.scan._build_scan_loader", new=AsyncMock(return_value=_NULL_LOADER)):
        resp, task = await _launch_scan(
            store,
            url="http://target.local/",
            body="<xml>ignored</xml>",  # no method -> GET default
        )

    assert task["status"] == "completed", task.get("error")
    # Config still records the body the client sent...
    assert task["config"].get("body") == "<xml>ignored</xml>"
    # ...but the runner discards it for GET and warns.
    kwargs = scan_target.call_args.kwargs
    assert kwargs["method"] == "GET"
    assert kwargs["body"] is None

    await engine.dispose()

