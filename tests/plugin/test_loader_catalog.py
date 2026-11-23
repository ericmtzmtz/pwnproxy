"""Loader behaviour around the catalog: activation, isolation and the toggle.

The loader is the only component that turns catalog records into running
plugins, so these tests cover the three promises the change makes:

* discovery is delegated (``discover_plugins`` is the single source of truth);
* a plugin that cannot run never takes the others (or the proxy) down;
* the on/off state is machine-wide (``[plugin.activation]``), persisted before
  the call is reported as done, and a failed write leaves memory untouched.
"""

import asyncio
import importlib
import tomllib

import pytest

import pwnproxy.plugins.core.loader as loader_module
from pwnproxy.plugins.core.catalog import PluginRecord, discover_plugins
from pwnproxy.plugins.core.config import ActivationConfigError, config_path
from pwnproxy.plugins.core.loader import (
    PluginLoader,
    PluginNotFoundError,
    PluginUnavailableError,
)
from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.models import Flow

BUILTIN_SCANNERS = {"command-injection", "lfi", "sqli", "ssrf", "xss", "xxe"}

#: A working installed scanner that records what the loader asked it to do.
COUNTER_SOURCE = '''
from pwnproxy.plugins.core.base import Finding, PluginMetadata, ScannerPlugin

CALLS = []
LOADS = []


class DeltaScanner(ScannerPlugin):
    metadata = PluginMetadata(
        name="delta-scan", version="0.9.0", author="fixture",
        consumes=["flow"], produces=["finding"],
    )

    async def on_load(self) -> None:
        LOADS.append(self.metadata.name)

    async def on_flow(self, flow):
        CALLS.append(flow.url)
        yield Finding(
            scanner="delta-scan", url=flow.url, method=flow.method,
            param_name="q", param_location="query", technique="fixture",
            severity="low", confidence="tentative", payload="", evidence="fixture",
        )
'''

SHADOW_COLLISION_SOURCE = '''
from pwnproxy.plugins.core.base import PluginMetadata, ScannerPlugin

LOADS = []


class ShadowSQLi(ScannerPlugin):
    metadata = PluginMetadata(
        name="sqli", version="9.9.9", author="shadow",
        consumes=["flow"], produces=["finding"],
    )

    def __init__(self):
        LOADS.append("instantiated")

    async def on_flow(self, flow):
        if False:
            yield None
'''

FAILING_ON_LOAD_SOURCE = '''
from pwnproxy.plugins.core.base import PluginMetadata, ScannerPlugin


class Exploding(ScannerPlugin):
    metadata = PluginMetadata(name="exploding", version="0.0.1", consumes=["flow"], produces=["finding"])

    async def on_load(self) -> None:
        raise RuntimeError("boom")

    async def on_flow(self, flow):
        if False:
            yield None
'''


def _flow(url: str = "http://target.local/?q=1") -> Flow:
    return Flow(id="f1", method="GET", url=url, request_headers={})


def _install_counter(install_fake_plugin):
    """Install the counting scanner and return ``(fake, module)``."""
    fake = install_fake_plugin(
        plugin_name="delta-scan", plugin_version="0.9.0",
        class_name="DeltaScanner", source=COUNTER_SOURCE,
    )
    return fake, importlib.import_module(fake.module)


def _install_exploding(install_fake_plugin):
    return install_fake_plugin(
        plugin_name="exploding", class_name="Exploding", source=FAILING_ON_LOAD_SOURCE,
    )


def _activation_table() -> dict:
    path = config_path()
    return tomllib.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


class TestCatalogDrivesDiscovery:
    @pytest.mark.asyncio
    async def test_nothing_configured_loads_exactly_the_builtins(self):
        loader = PluginLoader(HookBus())

        await loader.refresh_catalog()

        assert set(loader.list_plugins()) == BUILTIN_SCANNERS
        assert {record.name for record in loader.catalog()} == BUILTIN_SCANNERS
        await loader.shutdown()

    @pytest.mark.asyncio
    async def test_an_installed_plugin_is_discovered_but_stays_disabled(self, install_fake_plugin):
        fake = install_fake_plugin()
        loader = PluginLoader(HookBus())

        await loader.refresh_catalog()

        record = loader.get_record(fake.plugin_name)
        assert (record.source, record.package, record.error) == ("installed", "pwnproxy-pro", None)
        assert fake.plugin_name not in loader.list_plugins()
        assert loader.plugin_enabled(fake.plugin_name) is False
        assert fake.plugin_name in loader.disabled_names()
        await loader.shutdown()

    @pytest.mark.asyncio
    async def test_the_activation_table_loads_an_installed_plugin(self, install_fake_plugin, activation_config):
        fake, module = _install_counter(install_fake_plugin)
        activation_config(f"[plugin.activation]\n{fake.plugin_name} = true\n")
        loader = PluginLoader(HookBus())

        await loader.refresh_catalog()

        assert fake.plugin_name in loader.list_plugins()
        assert loader.plugin_enabled(fake.plugin_name) is True
        assert list(module.LOADS) == [fake.plugin_name]
        await loader.shutdown()

    @pytest.mark.asyncio
    async def test_a_builtin_disabled_in_the_config_is_not_loaded(self, activation_config):
        activation_config("[plugin.activation]\nsqli = false\n")
        loader = PluginLoader(HookBus())

        await loader.refresh_catalog()

        assert set(loader.list_plugins()) == BUILTIN_SCANNERS - {"sqli"}
        assert loader.plugin_enabled("sqli") is False
        assert loader.disabled_names() == ["sqli"]
        await loader.shutdown()


class TestFailureIsolation:
    @pytest.mark.asyncio
    async def test_a_broken_installed_plugin_does_not_stop_the_others(self, install_fake_plugin):
        fake = install_fake_plugin(target="module_that_does_not_exist:Thing")
        loader = PluginLoader(HookBus())

        await loader.refresh_catalog()

        assert set(loader.list_plugins()) == BUILTIN_SCANNERS
        record = loader.get_record(fake.plugin_name)
        assert record.error.startswith("import failed")
        assert loader.plugin_enabled(fake.plugin_name) is False
        await loader.shutdown()

    @pytest.mark.asyncio
    async def test_a_failing_on_load_leaves_the_plugin_out_with_its_error(
        self, install_fake_plugin, activation_config
    ):
        fake = _install_exploding(install_fake_plugin)
        activation_config(f"[plugin.activation]\n{fake.plugin_name} = true\n")
        loader = PluginLoader(HookBus())

        await loader.refresh_catalog()

        assert set(loader.list_plugins()) == BUILTIN_SCANNERS
        assert loader.get_record(fake.plugin_name).error == "on_load failed (RuntimeError: boom)"
        assert loader.plugin_enabled(fake.plugin_name) is False
        await loader.shutdown()

    @pytest.mark.asyncio
    async def test_a_collided_installed_plugin_never_runs(self, install_fake_plugin, activation_config):
        # Same name as a built-in, explicitly enabled: the collision still wins
        # and the built-in is what scans.
        shadow = install_fake_plugin(
            dist="pwnproxy-shadow", plugin_name="sqli",
            class_name="ShadowSQLi", source=SHADOW_COLLISION_SOURCE,
        )
        module = importlib.import_module(shadow.module)
        activation_config("[plugin.activation]\nsqli = true\n")
        loader = PluginLoader(HookBus())

        await loader.refresh_catalog()

        collided = [r for r in loader.catalog() if r.name == "sqli"]
        assert [(r.source, r.error) for r in collided] == [
            ("builtin", None),
            ("installed", "name collision with builtin 'sqli'"),
        ]
        assert module.LOADS == []  # the installed one never even got instantiated by the loader
        assert loader.plugin_enabled("sqli") is True
        assert loader.get_plugin("sqli").metadata.author != "shadow"
        await loader.shutdown()


class TestToggle:
    @pytest.mark.asyncio
    async def test_an_unknown_name_is_not_found_and_creates_nothing(self):
        loader = PluginLoader(HookBus())
        await loader.refresh_catalog()

        with pytest.raises(PluginNotFoundError):
            await loader.toggle("does-not-exist")

        assert "does-not-exist" not in loader.known_names()
        await loader.shutdown()

    @pytest.mark.asyncio
    async def test_disabling_a_builtin_persists_and_survives_a_restart(self, activation_config):
        activation_config("")
        loader = PluginLoader(HookBus())
        await loader.refresh_catalog()

        assert await loader.toggle("sqli") == "disabled"

        assert _activation_table() == {"plugin": {"activation": {"sqli": False}}}
        assert loader.plugin_enabled("sqli") is False
        await loader.shutdown()

        restarted = PluginLoader(HookBus())
        await restarted.refresh_catalog()
        assert "sqli" not in restarted.list_plugins()
        assert restarted.plugin_enabled("sqli") is False
        await restarted.shutdown()

    @pytest.mark.asyncio
    async def test_enabling_an_installed_plugin_loads_it_and_persists(self, install_fake_plugin, activation_config):
        fake, module = _install_counter(install_fake_plugin)
        activation_config("")
        loader = PluginLoader(HookBus())
        await loader.refresh_catalog()
        assert fake.plugin_name not in loader.list_plugins()

        assert await loader.toggle(fake.plugin_name) == "enabled"

        assert fake.plugin_name in loader.list_plugins()
        assert list(module.LOADS) == [fake.plugin_name]
        assert _activation_table() == {"plugin": {"activation": {fake.plugin_name: True}}}
        await loader.shutdown()

    @pytest.mark.asyncio
    async def test_toggling_a_broken_plugin_conflicts_and_persists_nothing(
        self, install_fake_plugin, activation_config
    ):
        fake = install_fake_plugin(target="module_that_does_not_exist:Thing")
        activation_config("")
        loader = PluginLoader(HookBus())
        await loader.refresh_catalog()

        with pytest.raises(PluginUnavailableError) as excinfo:
            await loader.toggle(fake.plugin_name)

        assert str(excinfo.value) == (
            f"plugin '{fake.plugin_name}' cannot run: import failed "
            "(ModuleNotFoundError: No module named 'module_that_does_not_exist')"
        )
        assert loader.plugin_enabled(fake.plugin_name) is False
        assert _activation_table() == {}
        await loader.shutdown()

    @pytest.mark.asyncio
    async def test_an_on_load_failure_during_the_toggle_keeps_the_plugin_off(
        self, install_fake_plugin, activation_config
    ):
        fake = _install_exploding(install_fake_plugin)
        activation_config("")
        loader = PluginLoader(HookBus())
        await loader.refresh_catalog()

        with pytest.raises(PluginUnavailableError):
            await loader.toggle(fake.plugin_name)

        assert fake.plugin_name not in loader.list_plugins()
        assert loader.plugin_enabled(fake.plugin_name) is False
        assert loader.get_record(fake.plugin_name).error == "on_load failed (RuntimeError: boom)"
        assert _activation_table() == {}
        await loader.shutdown()

    @pytest.mark.asyncio
    async def test_an_unwritable_config_on_enable_leaves_the_plugin_unloaded(
        self, install_fake_plugin, activation_config
    ):
        fake = install_fake_plugin()
        activation_config("")
        loader = PluginLoader(HookBus())
        await loader.refresh_catalog()
        config_path().unlink()
        config_path().mkdir()  # portable "not writable"

        with pytest.raises(ActivationConfigError):
            await loader.toggle(fake.plugin_name)

        assert fake.plugin_name not in loader.list_plugins()
        assert loader.plugin_enabled(fake.plugin_name) is False
        await loader.shutdown()

    @pytest.mark.asyncio
    async def test_an_unwritable_config_on_disable_keeps_the_plugin_running(self, activation_config):
        activation_config("")
        loader = PluginLoader(HookBus())
        await loader.refresh_catalog()
        config_path().unlink()
        config_path().mkdir()

        with pytest.raises(ActivationConfigError):
            await loader.toggle("sqli")

        assert loader.plugin_enabled("sqli") is True
        assert "sqli" in loader.list_plugins()
        await loader.shutdown()


class TestDisabledPluginsDoNotRun:
    @pytest.mark.asyncio
    async def test_a_disabled_plugin_consumes_no_flows_until_it_is_enabled(
        self, install_fake_plugin, activation_config, monkeypatch
    ):
        """The behavioural half of D4: disabled means "does not scan", not "hidden"."""
        fake, module = _install_counter(install_fake_plugin)
        activation_config("")
        # Only the installed plugin exists for this loader, so the flow below
        # cannot reach a real built-in scanner (no network in a unit test).
        records = [record for record in discover_plugins() if record.name == fake.plugin_name]
        monkeypatch.setattr(loader_module, "discover_plugins", lambda path=None: list(records))

        hook_bus = HookBus()
        loader = PluginLoader(hook_bus)
        await loader.start()

        hook_bus.publish("flow", _flow())
        await asyncio.sleep(0.2)
        assert module.CALLS == []

        await loader.toggle(fake.plugin_name)
        await asyncio.sleep(0.05)
        hook_bus.publish("flow", _flow("http://target.local/?q=2"))
        await asyncio.sleep(0.2)

        # ``HookBus`` buffers the events of a channel with no subscriber and
        # replays them on ``register``, so the flow published while the plugin was
        # off is scanned as soon as it starts consuming. That is pre-existing bus
        # behaviour (bounded pending buffer), not something the catalog added.
        assert module.CALLS == [
            "http://target.local/?q=1",
            "http://target.local/?q=2",
        ]
        await loader.shutdown()


class TestSessionState:
    def test_modules_json_no_longer_carries_the_plugins(self):
        from unittest.mock import MagicMock

        from pwnproxy.services.session.manager import SessionManager

        manager = SessionManager(MagicMock(), MagicMock(), MagicMock())

        assert manager._gather_module_state() == {"interceptor_enabled": True}

    @pytest.mark.asyncio
    async def test_a_legacy_modules_json_is_ignored_with_one_warning(self, caplog):
        """An old session must load fine and must not change what is enabled."""
        from unittest.mock import MagicMock

        from pwnproxy.services.session.manager import SessionManager

        manager = SessionManager(MagicMock(), MagicMock(), MagicMock())
        loader = PluginLoader(HookBus())
        await loader.refresh_catalog()
        manager.set_module_providers(plugin_loader=loader)

        with caplog.at_level("WARNING", logger="pwnproxy.services.session.manager"):
            await manager._apply_module_state(
                {"interceptor_enabled": True, "plugins": {"sqli": {"disabled": True}}}
            )
            await manager._apply_module_state({"plugins": {"sqli": {"disabled": True}}})

        assert loader.plugin_enabled("sqli") is True
        assert caplog.text.count("legacy 'plugins' key") == 1
        await loader.shutdown()


class TestSingleDiscoverySource:
    @pytest.mark.asyncio
    async def test_the_loader_loads_what_the_catalog_returns(self, monkeypatch):
        """Guard 6.3: if the loader walked the tree again, the built-ins appear."""
        from pwnproxy.plugins.core.base import PluginMetadata, ScannerPlugin

        class OnlyFromCatalog(ScannerPlugin):
            metadata = PluginMetadata(
                name="only-from-catalog", version="1.0.0",
                consumes=["flow"], produces=["finding"],
            )

            async def on_flow(self, flow):
                if False:
                    yield None

        records = [PluginRecord(
            name="only-from-catalog", source="builtin", package="pwnproxy",
            version="1.0.0", entry_point="fixture", factory=OnlyFromCatalog,
            metadata=OnlyFromCatalog.metadata,
        )]
        monkeypatch.setattr(loader_module, "discover_plugins", lambda path=None: list(records))
        loader = PluginLoader(HookBus())

        await loader.discover_scanners()

        assert loader.list_plugins() == ["only-from-catalog"]
        await loader.shutdown()
