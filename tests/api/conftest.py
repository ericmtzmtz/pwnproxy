"""Fixtures for the plugin-configuration HTTP tests (``test_plugin_config*``).

The fakes live in ``tests/api/_plugin_config_fakes.py`` and are imported from
there — never from this file. A test module that does
``from tests.api.conftest import ...`` breaks collection as soon as the run also
picks up ``apps/mcp/tests``: that package has an ``__init__.py`` and ``tests/``
does not, so ``tests`` resolves to the MCP package and the import fails with
``ModuleNotFoundError: No module named 'tests.api'``. The guard in
``tests/architecture/test_no_conftest_imports.py`` keeps it that way.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pwnproxy.shared.api_token import SCOPE_AGENT, write_token
from pwnproxy.shared.hooks import HookBus
from pwnproxy.transport.rest.app import app

from ._plugin_config_fakes import ConfigPlugin, FakeLoader, catalog_record

#: Token of the ``agent`` client (the MCP's). Written to a temporary config dir.
AGENT_TOKEN = "test-agent-token-8f2b6c1d4e7a"


@pytest.fixture
def plugin_config(api_client):
    """Mount a fake catalog on the API app and hand back a started client.

    Usage: ``scene = plugin_config()`` or
    ``scene = plugin_config(plugin, loaded=False, client=agent_client)``. The
    fixture removes everything it mounted and closes every client afterwards, so
    a test can build more than one scene in a row without inheriting state.
    """
    mounted = ("plugin_loader", "hook_bus", "task_store", "session_manager")
    opened: list[object] = []

    def build(
        plugin: object | None = None,
        *,
        loaded: bool = True,
        error: str | None = None,
        bus: HookBus | None = None,
        task_store: object | None = None,
        session_manager: object | None = None,
        client: object | None = None,
    ) -> SimpleNamespace:
        plugin = plugin if plugin is not None else ConfigPlugin()
        bus = bus if bus is not None else HookBus()
        app.state.plugin_loader = FakeLoader(
            catalog_record(plugin, error=error), plugin if loaded else None
        )
        app.state.hook_bus = bus
        app.state.task_store = task_store
        if session_manager is not None:
            app.state.session_manager = session_manager
        # Entered (not just built) so ``client.portal`` exists: a long action
        # runs inside the app's loop and the test polls it from there.
        started = client if client is not None else api_client(app)
        started.__enter__()
        opened.append(started)
        return SimpleNamespace(client=started, plugin=plugin, bus=bus)

    yield build

    for started in opened:
        started.__exit__(None, None, None)
    for attribute in mounted:
        if hasattr(app.state, attribute):
            delattr(app.state, attribute)


@pytest.fixture
def agent_client(tmp_path, monkeypatch, api_client):
    """A client whose token has scope ``agent`` (the token the MCP uses).

    The token file is written to a **temporary** config dir, so the suite never
    touches ``~/.pwnproxy`` and the ``full`` token of the session keeps working
    (``PWNPROXY_API_TOKEN`` is separate from the files).
    """
    monkeypatch.setenv("PWNPROXY_CONFIG_DIR", str(tmp_path))
    write_token(SCOPE_AGENT, AGENT_TOKEN)
    return api_client(app, headers={"Authorization": f"Bearer {AGENT_TOKEN}"})
