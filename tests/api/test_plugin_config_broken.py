"""A plugin whose ``on_load()`` failed stays *configurable* over HTTP.

Design D4 (``openspec/changes/archive/2026-11-24-plugin-config-api``) has the
configuration routes fall back to a **disposable instance** built from the
catalog's ``record.factory`` and never calling ``on_load()``. One of the reasons
is explicit: a plugin whose ``on_load()`` fails because of its own configuration
— or because an external requirement is not met yet — must still be fixable
through the API. That only works if the loader keeps the factory when
``on_load()`` is what failed.

The negative is the other failure: when the factory itself raises (or discovery
never got one) there is nothing to configure, so every route answers ``409``.

Nothing here is mocked below the transport: the catalog is the real one
(``refresh_catalog`` over a fake installed distribution) and the API reads it
through the real ``PluginLoader``, because the bug lives in what the loader
leaves on the catalog record.
"""

from __future__ import annotations

import asyncio
import importlib
from types import SimpleNamespace

import pytest

from pwnproxy.plugins.core.loader import PluginLoader
from pwnproxy.shared.hooks import HookBus
from pwnproxy.transport.rest.app import app

#: Plugin name every message of the contract quotes (the neutral example).
NAME = "example-checker"

#: A plugin that declares a schema, a collection and an action, and whose
#: ``on_load()`` raises while ``endpoint`` is empty — the case the API exists to
#: fix. Its store lives at module level on purpose: the configuration routes
#: build a **disposable** instance per call, so an attribute of ``self`` would be
#: thrown away between the write and the read that follows.
ON_LOAD_FAILS_SOURCE = '''
from pwnproxy.plugins.core.base import PluginMetadata, ScannerPlugin
from pwnproxy.plugins.core.config_schema import (
    ActionSpec,
    CollectionSpec,
    FieldSpec,
    PluginConfigSchema,
)

LOADS = []
WRITES = []
SETTINGS = {"endpoint": "", "retries": 1}
ITEMS = []


class ExampleChecker(ScannerPlugin):
    metadata = PluginMetadata(
        name="example-checker",
        version="2.0.0",
        author="fixture",
        consumes=["flow"],
        produces=["finding"],
    )

    def config_schema(self):
        return PluginConfigSchema(
            settings=[
                FieldSpec(key="endpoint", type="string", required=True, max_length=128),
                FieldSpec(key="retries", type="integer", minimum=0, maximum=5),
            ],
            collections=[
                CollectionSpec(
                    name="webhooks",
                    max_items=1,
                    item=[
                        FieldSpec(key="name", type="string", required=True, max_length=16),
                        FieldSpec(key="auth_header", type="string", secret=True, max_length=64),
                    ],
                )
            ],
            actions=[ActionSpec(name="ping")],
        )

    def config_read(self):
        return dict(SETTINGS)

    def config_write(self, values):
        WRITES.append(dict(values))
        SETTINGS.update(values)

    def collection_list(self, name):
        return [dict(item) for item in ITEMS]

    def collection_create(self, name, values):
        item = {"id": str(values["name"])}
        item.update({key: value for key, value in values.items() if key != "auth_header"})
        item["auth_header__set"] = "auth_header" in values
        ITEMS.append(item)
        return dict(item)

    async def on_load(self):
        LOADS.append(self.metadata.name)
        if not SETTINGS["endpoint"]:
            raise RuntimeError("setting 'endpoint' is empty")

    async def on_flow(self, flow):
        if False:
            yield None
'''

#: The other failure: the constructor raises, so not even a disposable instance
#: can be built and there is nothing to read or write.
INSTANTIATION_FAILS_SOURCE = '''
from pwnproxy.plugins.core.base import PluginMetadata, ScannerPlugin
from pwnproxy.plugins.core.config_schema import FieldSpec, PluginConfigSchema

INSTANTIATIONS = []


class ExampleChecker(ScannerPlugin):
    metadata = PluginMetadata(
        name="example-checker",
        version="2.0.0",
        author="fixture",
        consumes=["flow"],
        produces=["finding"],
    )

    def __init__(self):
        INSTANTIATIONS.append(1)
        raise RuntimeError("the plugin needs a resource that is not there")

    def config_schema(self):
        return PluginConfigSchema(settings=[FieldSpec(key="endpoint", type="string")])

    async def on_flow(self, flow):
        if False:
            yield None
'''

#: The schema of :data:`ON_LOAD_FAILS_SOURCE`, written out field by field: the
#: published form is the contract, not a re-serialisation of the fake.
EXPECTED_SCHEMA = {
    "plugin": NAME,
    "schema_version": 1,
    "settings": [
        {
            "key": "endpoint",
            "type": "string",
            "required": True,
            "secret": False,
            "read_only": False,
            "max_length": 128,
        },
        {
            "key": "retries",
            "type": "integer",
            "required": False,
            "secret": False,
            "read_only": False,
            "minimum": 0,
            "maximum": 5,
        },
    ],
    "collections": [
        {
            "name": "webhooks",
            "max_items": 1,
            "item": [
                {
                    "key": "name",
                    "type": "string",
                    "required": True,
                    "secret": False,
                    "read_only": False,
                    "max_length": 16,
                },
                {
                    "key": "auth_header",
                    "type": "string",
                    "required": False,
                    "secret": True,
                    "read_only": False,
                    "max_length": 64,
                },
            ],
        }
    ],
    "actions": [
        {"name": "ping", "long_running": False, "requires_scope": "full", "parameters": []}
    ],
}

#: What ``GET …/settings`` reports before anything is written.
INITIAL_SETTINGS = {
    "plugin": NAME,
    "schema_version": 1,
    "values": {"endpoint": {"value": ""}, "retries": {"value": 1}},
}


@pytest.fixture
def broken_catalog(install_fake_plugin, activation_config, api_client):
    """Install ``example-checker`` failing the way ``source`` says; mount it.

    Returns a callable that installs the plugin, enables it in the activation
    table, loads the **real** catalog and mounts it on the API app, so the test
    sees exactly what the loader left on the record.
    """

    def build(source: str) -> SimpleNamespace:
        fake = install_fake_plugin(
            dist="example-checker-dist",
            plugin_name=NAME,
            class_name="ExampleChecker",
            source=source,
        )
        module = importlib.import_module(fake.module)
        activation_config(f"[plugin.activation]\n{NAME} = true\n")
        hook_bus = HookBus()
        loader = PluginLoader(hook_bus)
        asyncio.run(loader.refresh_catalog())
        app.state.hook_bus = hook_bus
        app.state.plugin_loader = loader
        return SimpleNamespace(client=api_client(app), module=module, loader=loader)

    try:
        yield build
    finally:
        for attribute in ("hook_bus", "plugin_loader"):
            if hasattr(app.state, attribute):
                delattr(app.state, attribute)


class TestOnLoadFailedPluginIsConfigurable:
    """The plugin does not run, but its configuration can be read and written."""

    def test_schema_settings_and_a_write_work(self, broken_catalog):
        scene = broken_catalog(ON_LOAD_FAILS_SOURCE)

        schema = scene.client.get(f"/api/v1/plugins/{NAME}/schema")
        before = scene.client.get(f"/api/v1/plugins/{NAME}/settings")
        written = scene.client.patch(
            f"/api/v1/plugins/{NAME}/settings",
            json={"values": {"endpoint": "http://lab.local/hook"}},
        )
        after = scene.client.get(f"/api/v1/plugins/{NAME}/settings")

        assert (
            schema.status_code,
            schema.json(),
            before.status_code,
            before.json(),
            written.status_code,
            written.json(),
            after.json(),
            scene.module.WRITES,
        ) == (
            200,
            EXPECTED_SCHEMA,
            200,
            INITIAL_SETTINGS,
            200,
            {
                "plugin": NAME,
                "schema_version": 1,
                "values": {
                    "endpoint": {"value": "http://lab.local/hook"},
                    "retries": {"value": 1},
                },
            },
            {
                "plugin": NAME,
                "schema_version": 1,
                "values": {
                    "endpoint": {"value": "http://lab.local/hook"},
                    "retries": {"value": 1},
                },
            },
            [{"endpoint": "http://lab.local/hook"}],
        )

    def test_a_collection_can_be_read_and_written(self, broken_catalog):
        scene = broken_catalog(ON_LOAD_FAILS_SOURCE)

        created = scene.client.post(
            f"/api/v1/plugins/{NAME}/collections/webhooks",
            json={"values": {"name": "app"}},
        )
        listing = scene.client.get(f"/api/v1/plugins/{NAME}/collections/webhooks")

        assert (created.status_code, created.json(), listing.status_code, listing.json()) == (
            201,
            {"id": "app", "values": {"name": {"value": "app"}, "auth_header": {"set": False}}},
            200,
            {
                "plugin": NAME,
                "collection": "webhooks",
                "schema_version": 1,
                "max_items": 1,
                "items": [
                    {
                        "id": "app",
                        "values": {"name": {"value": "app"}, "auth_header": {"set": False}},
                    }
                ],
            },
        )

    def test_the_plugin_stays_broken_and_does_not_run(self, broken_catalog):
        scene = broken_catalog(ON_LOAD_FAILS_SOURCE)
        error = "on_load failed (RuntimeError: setting 'endpoint' is empty)"

        catalog = scene.client.get("/api/v1/plugins")
        action = scene.client.post(f"/api/v1/plugins/{NAME}/actions/ping", json={"parameters": {}})

        assert (
            [
                plugin
                for plugin in catalog.json()["plugins"]
                if plugin["name"] == NAME
            ],
            action.status_code,
            action.json(),
            NAME in scene.loader.list_plugins(),
            scene.module.LOADS,
        ) == (
            [
                {
                    "name": NAME,
                    "source": "installed",
                    "package": "example-checker-dist",
                    "version": "2.0.0",
                    "enabled": False,
                    "error": error,
                    "loaded": False,
                    "category": "scanner",
                    "description": "",
                    "author": "fixture",
                    "consumes": ["flow"],
                    "produces": ["finding"],
                }
            ],
            409,
            {"detail": f"plugin '{NAME}' cannot run: {error}"},
            False,
            [NAME],
        )

    def test_toggling_it_still_fails_and_persists_nothing(self, broken_catalog):
        scene = broken_catalog(ON_LOAD_FAILS_SOURCE)

        toggled = scene.client.post(f"/api/v1/plugins/{NAME}/toggle")
        config = scene.client.get(f"/api/v1/plugins/{NAME}/settings")

        assert (
            toggled.status_code,
            toggled.json(),
            config.status_code,
            scene.loader.plugin_enabled(NAME),
        ) == (
            409,
            {
                "detail": (
                    f"plugin '{NAME}' cannot run: "
                    "on_load failed (RuntimeError: setting 'endpoint' is empty)"
                )
            },
            200,
            False,
        )


class TestFactoryFailureIsNotConfigurable:
    """Without a usable factory there is nothing to ask, so everything is ``409``."""

    def test_every_route_answers_409_with_the_catalog_reason(self, broken_catalog):
        scene = broken_catalog(INSTANTIATION_FAILS_SOURCE)
        # The catalog's own wording for this phase (``loader._set_catalog_error``).
        error = "instantiation failed (the plugin needs a resource that is not there)"

        schema = scene.client.get(f"/api/v1/plugins/{NAME}/schema")
        settings = scene.client.get(f"/api/v1/plugins/{NAME}/settings")
        written = scene.client.patch(
            f"/api/v1/plugins/{NAME}/settings", json={"values": {"endpoint": "http://lab.local"}}
        )
        listing = scene.client.get(f"/api/v1/plugins/{NAME}/collections/webhooks")

        assert (
            schema.status_code,
            schema.json(),
            settings.status_code,
            settings.json(),
            written.json(),
            listing.json(),
            scene.module.INSTANTIATIONS,
        ) == (
            409,
            {"detail": f"plugin '{NAME}' cannot run: {error}"},
            409,
            {"detail": f"plugin '{NAME}' cannot run: {error}"},
            {"detail": f"plugin '{NAME}' cannot run: {error}"},
            {"detail": f"plugin '{NAME}' cannot run: {error}"},
            [1],
        )
