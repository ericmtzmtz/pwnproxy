"""``POST /api/v1/scan`` resolves its scanners through the plugin catalog.

The endpoint used to import ``apps.terminal.cli.scan`` and build the loader from a
hardcoded dict of five scanners, so a plugin installed from a package could never
be scanned through the API. It now asks
:func:`pwnproxy.plugins.core.catalog.build_scan_loader`, which honours the
machine-wide activation: an installed plugin runs only when it is enabled, and an
unknown name fails the task with a message instead of silently scanning nothing.

``scan_target`` is patched (no network) but ``build_scan_loader`` is real, which is
the point: the loader handed to the runner is what these tests inspect.
"""

import asyncio
import importlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from starlette.requests import Request as StarletteRequest

from pwnproxy.services.session.store import TaskStore
from pwnproxy.shared.task_model import create_task_engine, init_task_db

plugins_rest = importlib.import_module("pwnproxy.transport.rest.plugins")

#: A scanner that exists only as an installed entry point.
INSTALLED_SOURCE = '''
from pwnproxy.plugins.core.base import PluginMetadata, ScannerPlugin

LOADS = []


class FakeScanner(ScannerPlugin):
    metadata = PluginMetadata(
        name="authorization-matrix", version="2.0.0", author="fixture",
        consumes=["flow"], produces=["finding"],
    )

    async def on_load(self) -> None:
        LOADS.append(self.metadata.name)

    async def on_flow(self, flow):
        if False:
            yield None
'''


async def _wait_terminal(store, task_id, timeout_s=10.0):
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        task = await store.get(task_id)
        if task and task["status"] in ("completed", "failed", "cancelled"):
            return task
        await asyncio.sleep(0.02)
    raise AssertionError("scan task did not reach terminal state in time")


@pytest.fixture
def store(tmp_path):
    engine = create_task_engine(str(tmp_path / "tasks.db"))
    asyncio.run(init_task_db(engine))
    task_store = TaskStore(engine)
    asyncio.run(task_store.init())
    yield task_store
    asyncio.run(engine.dispose())


async def _launch(store, **params):
    """Run the ``POST /scan`` route with no live loader, returning task + call."""
    mgr = SimpleNamespace(active_name="default", task_store=store)
    app = SimpleNamespace(
        state=SimpleNamespace(
            session_manager=mgr, task_store=store, hook_bus=None, plugin_loader=None
        )
    )
    request = StarletteRequest({"type": "http", "app": app})
    with patch("pwnproxy.services.scan.runner.scan_target", new=AsyncMock(return_value=[])) as scan_target:
        response = await plugins_rest.launch_scan(request=request, **params)
        task = await _wait_terminal(store, response["task_id"])
    return response, task, scan_target


@pytest.mark.asyncio
async def test_an_enabled_installed_plugin_runs_in_the_scan(store, install_fake_plugin, activation_config):
    fake = install_fake_plugin(source=INSTALLED_SOURCE)
    activation_config(f"[plugin.activation]\n{fake.plugin_name} = true\n")

    _, task, scan_target = await _launch(store, url="http://target.local/", scanners=fake.plugin_name)

    loader = scan_target.call_args.args[0]
    assert (task["status"], loader.list_plugins()) == ("completed", [fake.plugin_name])


@pytest.mark.asyncio
async def test_a_disabled_installed_plugin_does_not_run_in_the_scan(
    store, install_fake_plugin, activation_config
):
    fake = install_fake_plugin(source=INSTALLED_SOURCE)
    activation_config("")

    _, task, scan_target = await _launch(store, url="http://target.local/", scanners=fake.plugin_name)

    loader = scan_target.call_args.args[0]
    assert (task["status"], loader.list_plugins()) == ("completed", [])


@pytest.mark.asyncio
async def test_an_unknown_scanner_fails_the_task_with_the_name(store):
    _, task, _ = await _launch(store, url="http://target.local/", scanners="nope")

    assert (task["status"], task["error"]) == ("failed", "Unknown scanner: nope")


@pytest.mark.asyncio
async def test_a_broken_installed_plugin_fails_the_task_with_the_reason(
    store, install_fake_plugin
):
    fake = install_fake_plugin(target="module_that_does_not_exist:Thing")

    _, task, _ = await _launch(store, url="http://target.local/", scanners=fake.plugin_name)

    assert (task["status"], task["error"]) == (
        "failed",
        f"Scanner '{fake.plugin_name}' failed to load: import failed "
        "(ModuleNotFoundError: No module named 'module_that_does_not_exist')",
    )


@pytest.mark.asyncio
async def test_the_builtins_are_all_available_without_a_live_loader(store):
    _, task, scan_target = await _launch(store, url="http://target.local/")

    loader = scan_target.call_args.args[0]
    assert (task["status"], sorted(loader.list_plugins())) == (
        "completed",
        ["command-injection", "lfi", "sqli", "ssrf", "xss", "xxe"],
    )
