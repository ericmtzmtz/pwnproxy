"""``GET /api/v1/plugins`` and ``POST /api/v1/plugins/{name}/toggle``.

The endpoint is the only window the Web UI (and any other client) has into the
plugin catalog, so the tests pin the whole contract:

* every plugin appears, in a stable order, with the six obligatory fields and
  ``error`` for the broken ones;
* a disabled plugin still appears (``enabled: false``) — "hidden" and "off" are
  different things;
* without a loader the answer is ``200`` with the reason, never ``500``;
* the toggle maps the three failure modes to ``404`` / ``409`` / ``500`` and
  never leaves memory disagreeing with the config file.
"""

import asyncio
import importlib
from unittest.mock import MagicMock

import pytest

from pwnproxy.plugins.core.config import config_path
from pwnproxy.plugins.core.loader import PluginLoader
from pwnproxy.shared.hooks import HookBus
from pwnproxy.transport.rest.app import app

#: Built-ins shipped in the tree, in the order the catalog sorts them.
BUILTIN_NAMES = ["command-injection", "lfi", "sqli", "ssrf", "xss", "xxe"]

#: Fields ``GET /plugins`` must always return (spec: ``plugins-list``).
OBLIGATORY_FIELDS = {"name", "source", "package", "version", "enabled", "error"}

#: An installed scanner that records the ``on_load`` the loader gave it.
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


@pytest.fixture
def make_client(monkeypatch, api_client):
    """Return a factory that mounts a real ``PluginLoader`` on the API app."""

    def build(*, plugins_path=None):
        hook_bus = HookBus()
        loader = PluginLoader(hook_bus)
        asyncio.run(loader.refresh_catalog(plugins_path))
        app.state.hook_bus = hook_bus
        app.state.plugin_loader = loader
        app.state.session_manager = MagicMock()
        app.state.callback_port = 17173
        client = api_client(app)
        return client, loader

    yield build

    for attribute in ("plugin_loader", "hook_bus", "session_manager", "callback_port"):
        if hasattr(app.state, attribute):
            delattr(app.state, attribute)


def test_catalog_is_served_with_the_obligatory_fields(make_client):
    client, _ = make_client()

    response = client.get("/api/v1/plugins")

    body = response.json()
    assert response.status_code == 200
    assert body["error"] is None
    assert [plugin["name"] for plugin in body["plugins"]] == BUILTIN_NAMES
    assert [
        (
            plugin["source"],
            plugin["package"],
            plugin["version"],
            plugin["enabled"],
            plugin["error"],
            plugin["loaded"],
            plugin["category"],
        )
        for plugin in body["plugins"]
    ] == [
        ("builtin", "pwnproxy", version, True, None, True, "scanner")
        for version in ("0.1.0", "0.3.0", "0.3.0", "0.4.0", "0.3.0", "0.2.0")
    ]
    assert all(set(plugin) >= OBLIGATORY_FIELDS for plugin in body["plugins"])
    # Optional fields come from the metadata captured at discovery.
    sqli = body["plugins"][2]
    assert (sqli["author"], sqli["consumes"], sqli["produces"]) == (
        "pwnproxy",
        ["flow"],
        ["finding"],
    )
    assert {"description", "author", "consumes", "produces"} <= set(sqli)


def test_two_calls_return_the_same_order(make_client):
    client, _ = make_client()

    first = [(p["name"], p["source"], p["enabled"]) for p in client.get("/api/v1/plugins").json()["plugins"]]
    second = [(p["name"], p["source"], p["enabled"]) for p in client.get("/api/v1/plugins").json()["plugins"]]

    assert first == second == [("command-injection", "builtin", True)] + [
        (name, "builtin", True) for name in BUILTIN_NAMES[1:]
    ]


def test_a_disabled_builtin_is_listed_as_disabled(make_client, activation_config):
    activation_config("[plugin.activation]\nsqli = false\n")
    client, _ = make_client()

    plugins = {p["name"]: p for p in client.get("/api/v1/plugins").json()["plugins"]}

    assert (plugins["sqli"]["enabled"], plugins["sqli"]["error"], plugins["sqli"]["loaded"]) == (
        False,
        None,
        False,
    )
    assert len(plugins) == len(BUILTIN_NAMES)


def test_a_broken_installed_plugin_is_listed_with_its_error(make_client, install_fake_plugin):
    fake = install_fake_plugin(target="module_that_does_not_exist:Thing")
    client, _ = make_client()

    plugins = {p["name"]: p for p in client.get("/api/v1/plugins").json()["plugins"]}

    assert (plugins[fake.plugin_name]["source"], plugins[fake.plugin_name]["enabled"]) == ("installed", False)
    assert plugins[fake.plugin_name]["error"] == (
        "import failed (ModuleNotFoundError: No module named 'module_that_does_not_exist')"
    )


def test_an_installed_plugin_is_disabled_until_it_is_activated(make_client, install_fake_plugin):
    fake = install_fake_plugin()
    client, _ = make_client()

    plugins = {p["name"]: p for p in client.get("/api/v1/plugins").json()["plugins"]}

    assert (
        plugins[fake.plugin_name]["source"],
        plugins[fake.plugin_name]["package"],
        plugins[fake.plugin_name]["version"],
        plugins[fake.plugin_name]["enabled"],
        plugins[fake.plugin_name]["error"],
        plugins[fake.plugin_name]["loaded"],
    ) == ("installed", "pwnproxy-pro", "2.0.0", False, None, False)


def test_without_a_loader_the_reason_is_returned_with_200(monkeypatch, api_client):
    app.state.plugin_loader = None

    with api_client(app) as client:
        response = client.get("/api/v1/plugins")

    assert (response.status_code, response.json()) == (
        200,
        {"plugins": [], "error": "plugin_loader not available"},
    )


class TestToggle:
    def test_an_unknown_name_is_404_and_changes_nothing(self, make_client, activation_config):
        activation_config("")
        client, loader = make_client()

        response = client.post("/api/v1/plugins/does-not-exist/toggle")

        assert (response.status_code, response.json()) == (
            404,
            {"detail": "plugin 'does-not-exist' not found"},
        )
        assert (config_path().read_text(encoding="utf-8"), "does-not-exist" in loader.known_names()) == (
            "",
            False,
        )

    def test_a_broken_plugin_is_409_with_the_reason_and_is_not_persisted(
        self, make_client, install_fake_plugin, activation_config
    ):
        fake = install_fake_plugin(target="module_that_does_not_exist:Thing")
        activation_config("")
        client, loader = make_client()

        response = client.post(f"/api/v1/plugins/{fake.plugin_name}/toggle")

        assert (response.status_code, response.json()) == (
            409,
            {
                "detail": (
                    f"plugin '{fake.plugin_name}' cannot run: import failed "
                    "(ModuleNotFoundError: No module named 'module_that_does_not_exist')"
                )
            },
        )
        assert (loader.plugin_enabled(fake.plugin_name), config_path().read_text(encoding="utf-8")) == (
            False,
            "",
        )

    def test_disabling_a_builtin_persists_and_does_not_touch_the_session(
        self, make_client, activation_config
    ):
        activation_config("")
        client, loader = make_client()

        response = client.post("/api/v1/plugins/sqli/toggle")

        assert (response.status_code, response.json()) == (200, {"status": "disabled", "name": "sqli"})
        assert config_path().read_text(encoding="utf-8") == "[plugin.activation]\nsqli = false\n"
        assert (loader.plugin_enabled("sqli"), "sqli" in loader.list_plugins()) == (False, True)
        app.state.session_manager.mark_unsaved.assert_not_called()

    def test_an_unwritable_config_is_500_and_the_plugin_keeps_running(
        self, make_client, activation_config, tmp_path
    ):
        activation_config("")
        client, loader = make_client()
        config_path().unlink()
        config_path().mkdir()  # portable "not writable"

        response = client.post("/api/v1/plugins/sqli/toggle")

        assert response.status_code == 500
        assert response.json()["detail"].startswith("could not persist plugin state:")
        assert (loader.plugin_enabled("sqli"), "sqli" in loader.list_plugins()) == (True, True)
        assert list(tmp_path.iterdir()) == [config_path()]

    def test_enabling_an_installed_plugin_loads_it_and_persists(
        self, make_client, install_fake_plugin, activation_config
    ):
        fake = install_fake_plugin(source=INSTALLED_SOURCE)
        module = importlib.import_module(fake.module)
        activation_config("")
        client, loader = make_client()

        response = client.post(f"/api/v1/plugins/{fake.plugin_name}/toggle")

        assert (response.status_code, response.json()) == (
            200,
            {"status": "enabled", "name": fake.plugin_name},
        )
        assert config_path().read_text(encoding="utf-8") == (
            f"[plugin.activation]\n{fake.plugin_name} = true\n"
        )
        assert (loader.plugin_enabled(fake.plugin_name), module.LOADS) == (True, [fake.plugin_name])

    def test_the_toggle_is_machine_wide_and_survives_a_new_loader(
        self, make_client, activation_config
    ):
        activation_config("")
        client, _ = make_client()
        assert client.post("/api/v1/plugins/xxe/toggle").json()["status"] == "disabled"

        fresh = PluginLoader(HookBus())
        asyncio.run(fresh.refresh_catalog())

        assert (fresh.plugin_enabled("xxe"), "xxe" in fresh.list_plugins()) == (False, False)
