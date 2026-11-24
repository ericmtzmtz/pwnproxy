"""HTTP contract of ``/api/v1/plugins/{name}``: schema, settings, collections, actions.

``specs/plugin-config/spec.md`` is the contract, and every requirement carries its
negative here: an unknown name, a broken plugin, a value that breaks the schema,
the plugin's own rule, a full collection, an action on a plugin that is not
loaded, a secret that must not come back, a scope that cannot write it, and a
write that leaves no audit trail.

The one test that cannot use the fake catalog (a plugin installed and **disabled**
on disk) builds it with ``install_fake_plugin``; everything else runs over the
fakes of ``tests/api/_plugin_config_fakes.py`` so the assertion is about the transport.

``tests/api/test_plugin_config_guard.py`` holds the route/scope matrix and
``tests/api/test_ws_plugin_config.py`` the ``/ws/events`` relay.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime

import pytest

from pwnproxy.plugins.core.config_schema import (
    ActionSpec,
    CollectionSpec,
    FieldSpec,
    PluginConfigSchema,
)
from pwnproxy.services.session.store import TaskStore
from pwnproxy.shared.bus.topics import PLUGIN_CONFIG_CHANGED
from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.task_model import create_task_engine, init_task_db
from pwnproxy.transport.rest.app import app
from pwnproxy.transport.rest.auth import FORBIDDEN_SCOPE_DETAIL

from ._plugin_config_fakes import CANARY, NAME, ConfigPlugin, NoSchemaPlugin

#: The schema of ``tests/api/_plugin_config_fakes.py`` written out by hand, field
#: by field: the published form is the contract, not a re-serialisation of the fake.
EXPECTED_SCHEMA = {
    "plugin": NAME,
    "schema_version": 1,
    "settings": [
        {
            "key": "environment",
            "type": "enum",
            "required": False,
            "secret": False,
            "read_only": False,
            "default": "lab",
            "choices": ["lab", "staging"],
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
        {
            "key": "signing_key",
            "type": "string",
            "required": False,
            "secret": True,
            "read_only": False,
            "max_length": 64,
        },
    ],
    "collections": [
        {
            "name": "webhooks",
            "max_items": 2,
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
                    "key": "events",
                    "type": "array",
                    "required": False,
                    "secret": False,
                    "read_only": False,
                    "max_items": 4,
                    "items": "string",
                },
                {
                    "key": "status",
                    "type": "enum",
                    "required": False,
                    "secret": False,
                    "read_only": True,
                    "choices": ["active", "failing"],
                },
                {
                    "key": "signing_key",
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
        {
            "name": "ping",
            "long_running": False,
            "requires_scope": "full",
            "parameters": [
                {
                    "key": "name",
                    "type": "string",
                    "required": True,
                    "secret": False,
                    "read_only": False,
                }
            ],
        },
        {
            "name": "send_test",
            "long_running": True,
            "requires_scope": "full",
            "parameters": [
                {
                    "key": "payload",
                    "type": "string",
                    "required": False,
                    "secret": False,
                    "read_only": False,
                }
            ],
        },
        {"name": "probe", "long_running": False, "requires_scope": "agent", "parameters": []},
    ],
}

#: Settings of the fake before any write (the secret reports ``set: false``).
INITIAL_SETTINGS = {
    "plugin": NAME,
    "schema_version": 1,
    "values": {
        "environment": {"value": "lab"},
        "retries": {"value": 1},
        "signing_key": {"set": False},
    },
}

#: Every route of the router with a name that is not in the catalog.
ROUTES_MISSING = [
    ("GET", "/api/v1/plugins/nope/schema", None),
    ("GET", "/api/v1/plugins/nope/settings", None),
    ("PATCH", "/api/v1/plugins/nope/settings", {"values": {"retries": 2}}),
    ("GET", "/api/v1/plugins/nope/collections/webhooks", None),
    ("POST", "/api/v1/plugins/nope/collections/webhooks", {"values": {"name": "app"}}),
    (
        "PATCH",
        "/api/v1/plugins/nope/collections/webhooks/app",
        {"values": {"name": "app"}},
    ),
    ("DELETE", "/api/v1/plugins/nope/collections/webhooks/app", None),
    ("POST", "/api/v1/plugins/nope/actions/ping", {"parameters": {}}),
]


def _request(client, method: str, url: str, body: dict | None = None):
    """Send one request, with a body only when the route takes one."""
    return client.request(method, url, json=body) if body is not None else client.request(
        method, url
    )


#: Logger of the audit line; a rejected write must leave nothing under it.
CONFIG_LOGGER = "pwnproxy.plugins.core.config_service"


def _config_log_lines(caplog) -> list[str]:
    """Messages of the audit logger captured by ``caplog``."""
    return [record.getMessage() for record in caplog.records if record.name == CONFIG_LOGGER]


class TestSchema:
    # @escenario plugin-config/esquema-versionado/el-esquema-declarado-se-publica-completo
    def test_the_schema_is_published_field_by_field(self, plugin_config):
        scene = plugin_config()

        response = scene.client.get(f"/api/v1/plugins/{NAME}/schema")

        assert (response.status_code, response.json()) == (200, EXPECTED_SCHEMA)

    # @escenario plugin-config/esquema-versionado/un-plugin-sin-esquema-responde-un-esquema-vacio
    def test_a_plugin_without_a_schema_answers_empty(self, plugin_config):
        scene = plugin_config(NoSchemaPlugin())

        schema = scene.client.get(f"/api/v1/plugins/{NAME}/schema")
        settings = scene.client.get(f"/api/v1/plugins/{NAME}/settings")

        assert (
            schema.status_code,
            schema.json(),
            settings.status_code,
            settings.json(),
        ) == (
            200,
            {
                "plugin": NAME,
                "schema_version": 1,
                "settings": [],
                "collections": [],
                "actions": [],
            },
            200,
            {"plugin": NAME, "schema_version": 1, "values": {}},
        )

    # @escenario plugin-config/esquema-versionado/un-esquema-invalido-no-se-publica
    @pytest.mark.parametrize(
        ("schema", "reason"),
        [
            (
                PluginConfigSchema(settings=[FieldSpec(key="retries", type="integer", secret=True)]),
                "field 'retries' is secret but its type is 'integer' "
                "(only string fields can be secret)",
            ),
            (
                PluginConfigSchema(
                    settings=[FieldSpec(key="environment", type="string", choices=["lab"])]
                ),
                "field 'environment' declares choices but is not an enum",
            ),
            (
                PluginConfigSchema(
                    actions=[
                        ActionSpec(
                            name="send_test",
                            parameters=[FieldSpec(key="token", type="string", secret=True)],
                        )
                    ]
                ),
                "action parameter 'token' cannot be secret: "
                "a long action persists its parameters",
            ),
        ],
    )
    def test_an_invalid_schema_is_409_and_publishes_nothing(self, plugin_config, schema, reason):
        scene = plugin_config(ConfigPlugin(schema))

        response = scene.client.get(f"/api/v1/plugins/{NAME}/schema")

        assert (response.status_code, response.json(), set(response.json())) == (
            409,
            {"detail": f"plugin '{NAME}' declares an invalid configuration schema: {reason}"},
            {"detail"},
        )

    # @escenario plugin-config/rutas-y-codigos/nombre-fuera-del-catalogo
    @pytest.mark.parametrize(("method", "url", "body"), ROUTES_MISSING)
    def test_an_unknown_name_is_404_on_every_route(self, plugin_config, method, url, body):
        scene = plugin_config()

        response = _request(scene.client, method, url, body)

        assert (response.status_code, response.json()) == (
            404,
            {"detail": "plugin 'nope' not found"},
        )

    # @escenario plugin-config/rutas-y-codigos/plugin-roto
    def test_a_broken_record_is_409_with_the_catalog_reason(self, plugin_config):
        # A broken package is never loaded: the catalog has the error, not a plugin.
        scene = plugin_config(loaded=False, error="import failed (ImportError: nope)")

        response = scene.client.get(f"/api/v1/plugins/{NAME}/settings")

        assert (response.status_code, response.json()) == (
            409,
            {"detail": f"plugin '{NAME}' cannot run: import failed (ImportError: nope)"},
        )


class TestSettings:
    def test_the_settings_are_rendered_with_the_uniform_shape(self, plugin_config):
        scene = plugin_config()

        response = scene.client.get(f"/api/v1/plugins/{NAME}/settings")

        assert (response.status_code, response.json()) == (200, INITIAL_SETTINGS)

    # @escenario plugin-config/validacion-del-nucleo/escritura-parcial
    def test_a_patch_writes_only_the_keys_it_sends(self, plugin_config):
        scene = plugin_config()

        response = scene.client.patch(
            f"/api/v1/plugins/{NAME}/settings", json={"values": {"environment": "staging"}}
        )

        assert (
            response.status_code,
            response.json(),
            scene.plugin.settings,
        ) == (
            200,
            {
                "plugin": NAME,
                "schema_version": 1,
                "values": {
                    "environment": {"value": "staging"},
                    "retries": {"value": 1},
                    "signing_key": {"set": False},
                },
            },
            {"environment": "staging", "retries": 1},
        )

    # @escenario plugin-config/validacion-del-nucleo/clave-desconocida
    @pytest.mark.parametrize(
        ("values", "field", "message"),
        [
            ({"no_existe": 1}, "no_existe", "unknown field"),
            ({"retries": "texto"}, "retries", "expected an integer"),
            ({"environment": "prod"}, "environment", "value is not one of the declared choices"),
            ({"retries": 9}, "retries", "value is above the maximum 5"),
            ({"signing_key": "x" * 65}, "signing_key", "string is longer than 64 characters"),
            ({"retries": None}, "retries", "null is not a value"),
        ],
    )
    def test_an_invalid_write_is_422_and_never_reaches_the_plugin(
        self, plugin_config, values, field, message
    ):
        scene = plugin_config()

        response = scene.client.patch(
            f"/api/v1/plugins/{NAME}/settings", json={"values": values}
        )

        assert (
            response.status_code,
            response.json(),
            scene.plugin.call_count("config_write"),
        ) == (422, {"detail": {"field": field, "message": message}}, 0)

    def test_a_read_only_setting_cannot_be_written(self, plugin_config):
        schema = PluginConfigSchema(
            settings=[
                FieldSpec(key="status", type="enum", choices=["active", "failing"], read_only=True)
            ]
        )
        scene = plugin_config(ConfigPlugin(schema))

        response = scene.client.patch(
            f"/api/v1/plugins/{NAME}/settings", json={"values": {"status": "active"}}
        )

        assert (
            response.status_code,
            response.json(),
            scene.plugin.call_count("config_write"),
        ) == (422, {"detail": {"field": "status", "message": "read-only field"}}, 0)

    # @escenario plugin-config/reglas-del-plugin/plugin-que-revienta
    def test_an_unexpected_plugin_error_is_a_fixed_500_with_the_trace_in_the_log(
        self, plugin_config, caplog
    ):
        scene = plugin_config()
        scene.plugin.fail_read = RuntimeError(f"sqlite exploded with signing_key={CANARY}")

        with caplog.at_level(logging.ERROR):
            response = scene.client.get(f"/api/v1/plugins/{NAME}/settings")

        assert (
            response.status_code,
            response.json(),
            CANARY in response.text,
            f"sqlite exploded with signing_key={CANARY}" in caplog.text,
        ) == (500, {"detail": f"plugin '{NAME}' failed"}, False, True)


class TestSecrets:
    # @escenario plugin-config/secretos/la-lectura-no-trae-el-valor
    def test_a_secret_written_with_full_never_comes_back(self, plugin_config):
        scene = plugin_config()

        written = scene.client.patch(
            f"/api/v1/plugins/{NAME}/settings", json={"values": {"signing_key": CANARY}}
        )
        settings = scene.client.get(f"/api/v1/plugins/{NAME}/settings")
        created = scene.client.post(
            f"/api/v1/plugins/{NAME}/collections/webhooks",
            json={"values": {"name": "app", "signing_key": CANARY}},
        )
        collection = scene.client.get(f"/api/v1/plugins/{NAME}/collections/webhooks")

        assert (
            written.status_code,
            written.json()["values"]["signing_key"],
            settings.json()["values"]["signing_key"],
            CANARY in settings.text,
            created.status_code,
            created.json(),
            collection.json(),
            CANARY in collection.text,
            scene.plugin.setting_secrets["signing_key"],
            scene.plugin.item_secrets[("webhooks", "app", "signing_key")],
        ) == (
            200,
            {"set": True},
            {"set": True},
            False,
            201,
            {
                "id": "app",
                "values": {
                    "name": {"value": "app"},
                    "signing_key": {"set": True},
                },
            },
            {
                "plugin": NAME,
                "collection": "webhooks",
                "schema_version": 1,
                "max_items": 2,
                "items": [
                    {
                        "id": "app",
                        "values": {
                            "name": {"value": "app"},
                            "signing_key": {"set": True},
                        },
                    }
                ],
            },
            False,
            CANARY,
            CANARY,
        )

    # @escenario plugin-config/secretos/el-error-de-validacion-no-repite-el-valor
    def test_the_422_of_a_secret_does_not_echo_it(self, plugin_config):
        scene = plugin_config()
        too_long = CANARY * 20

        response = scene.client.patch(
            f"/api/v1/plugins/{NAME}/settings", json={"values": {"signing_key": too_long}}
        )

        assert (
            response.status_code,
            response.json(),
            CANARY in response.text,
        ) == (
            422,
            {"detail": {"field": "signing_key", "message": "string is longer than 64 characters"}},
            False,
        )

    # @escenario plugin-config/secretos/un-plugin-que-devuelve-el-secreto-no-lo-publica
    def test_a_hostile_plugin_cannot_publish_its_own_secret(self, plugin_config):
        """The fake returns the value *and* `signing_key__set`: only the flag survives."""
        scene = plugin_config()
        scene.plugin.setting_secrets["signing_key"] = CANARY
        scene.plugin.items.append({"id": "app", "name": "app", "signing_key": CANARY, "signing_key__set": True})

        settings = scene.client.get(f"/api/v1/plugins/{NAME}/settings")
        collection = scene.client.get(f"/api/v1/plugins/{NAME}/collections/webhooks")

        assert (
            settings.json()["values"]["signing_key"],
            CANARY in settings.text,
            collection.json()["items"][0]["values"]["signing_key"],
            CANARY in collection.text,
        ) == ({"set": True}, False, {"set": True}, False)


class TestScopeMatrix:
    # @escenario plugin-config/alcance-full/agent-no-escribe-un-secreto
    def test_agent_cannot_write_a_settings_secret_and_the_old_value_survives(
        self, plugin_config, agent_client
    ):
        scene = plugin_config(client=agent_client)
        scene.plugin.setting_secrets["signing_key"] = "previous-value"

        response = scene.client.patch(
            f"/api/v1/plugins/{NAME}/settings",
            # An invalid key travels too: the 403 must win over the 422.
            json={"values": {"signing_key": CANARY, "no_existe": 1}},
        )
        readback = scene.client.get(f"/api/v1/plugins/{NAME}/settings")

        assert (
            response.status_code,
            response.json(),
            scene.plugin.call_count("config_write"),
            scene.plugin.setting_secrets["signing_key"],
            readback.json()["values"]["signing_key"],
            CANARY in response.text,
        ) == (
            403,
            {"detail": "Secret fields can only be written with a token of scope 'full' (Web UI or CLI)"},
            0,
            "previous-value",
            {"set": True},
            False,
        )

    # @escenario plugin-config/alcance-full/agent-escribe-lo-que-no-es-secreto
    def test_agent_writes_a_setting_that_is_not_secret(self, plugin_config, agent_client):
        scene = plugin_config(client=agent_client)

        response = scene.client.patch(
            f"/api/v1/plugins/{NAME}/settings", json={"values": {"retries": 3}}
        )

        assert (
            response.status_code,
            response.json()["values"]["retries"],
            scene.plugin.settings["retries"],
        ) == (200, {"value": 3}, 3)

    def test_agent_cannot_create_or_update_an_item_with_a_secret(
        self, plugin_config, agent_client
    ):
        scene = plugin_config(client=agent_client)
        scene.plugin.items.append({"id": "app", "name": "app", "signing_key__set": False})

        create = scene.client.post(
            f"/api/v1/plugins/{NAME}/collections/webhooks",
            json={"values": {"name": "ci", "signing_key": CANARY}},
        )
        update = scene.client.patch(
            f"/api/v1/plugins/{NAME}/collections/webhooks/app",
            json={"values": {"signing_key": CANARY}},
        )
        collection = scene.client.get(f"/api/v1/plugins/{NAME}/collections/webhooks")

        assert (
            create.status_code,
            create.json(),
            update.status_code,
            update.json(),
            scene.plugin.call_count("collection_create"),
            scene.plugin.call_count("collection_update"),
            [item["id"] for item in collection.json()["items"]],
            collection.json()["items"][0]["values"]["signing_key"],
            scene.plugin.item_secrets,
        ) == (
            403,
            {"detail": "Secret fields can only be written with a token of scope 'full' (Web UI or CLI)"},
            403,
            {"detail": "Secret fields can only be written with a token of scope 'full' (Web UI or CLI)"},
            0,
            0,
            ["app"],
            {"set": False},
            {},
        )

    def test_agent_writes_an_item_without_secrets(self, plugin_config, agent_client):
        scene = plugin_config(client=agent_client)

        response = scene.client.post(
            f"/api/v1/plugins/{NAME}/collections/webhooks",
            json={"values": {"name": "ci", "events": ["app.lab"]}},
        )

        assert (response.status_code, response.json()) == (
            201,
            {
                "id": "ci",
                "values": {
                    "name": {"value": "ci"},
                    "events": {"value": ["app.lab"]},
                    "signing_key": {"set": False},
                },
            },
        )

    # @escenario plugin-config/alcance-full/accion-que-exige-full-con-token-agent
    def test_agent_cannot_run_an_action_that_requires_full(self, plugin_config, agent_client):
        scene = plugin_config(client=agent_client)

        response = scene.client.post(
            f"/api/v1/plugins/{NAME}/actions/ping",
            # The name is missing too: the 403 must win over the 422.
            json={"parameters": {}},
        )

        assert (
            response.status_code,
            response.json(),
            scene.plugin.call_count("run_action"),
        ) == (403, {"detail": FORBIDDEN_SCOPE_DETAIL}, 0)

    def test_agent_runs_an_action_declared_for_agent(self, plugin_config, agent_client):
        scene = plugin_config(client=agent_client)

        response = scene.client.post(
            f"/api/v1/plugins/{NAME}/actions/probe", json={"parameters": {}}
        )

        assert (response.status_code, response.json()) == (
            200,
            {"plugin": NAME, "action": "probe", "status": "completed", "result": {"ok": True}},
        )

    def test_full_writes_the_secret_and_the_read_says_set(self, plugin_config):
        scene = plugin_config()

        written = scene.client.patch(
            f"/api/v1/plugins/{NAME}/settings", json={"values": {"signing_key": CANARY}}
        )
        readback = scene.client.get(f"/api/v1/plugins/{NAME}/settings")

        assert (
            written.status_code,
            readback.json()["values"]["signing_key"],
            CANARY in readback.text,
        ) == (200, {"set": True}, False)


#: Installed plugin for the "configure it while it is off" test. ``on_load`` records
#: its call: the disposable instance the API builds must never reach it.
DISABLED_PLUGIN_SOURCE = '''
from pwnproxy.plugins.core.base import (
    ActionSpec,
    FieldSpec,
    PluginConfigSchema,
    PluginMetadata,
    ScannerPlugin,
)

LOADS = []
WRITES = []


class DisabledPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="example-checker",
        version="2.0.0",
        author="fixture",
        consumes=["flow"],
        produces=["finding"],
    )

    def __init__(self):
        super().__init__()
        self.settings = {"environment": "lab"}

    async def on_load(self) -> None:
        LOADS.append(self.metadata.name)

    def config_schema(self) -> PluginConfigSchema:
        return PluginConfigSchema(
            settings=[
                FieldSpec(key="environment", type="enum", choices=["lab", "staging"]),
                FieldSpec(key="signing_key", type="string", secret=True),
            ],
            actions=[ActionSpec(name="probe", requires_scope="agent")],
        )

    def config_read(self):
        return dict(self.settings)

    def config_write(self, values):
        WRITES.append(dict(values))
        self.settings.update(values)

    async def on_flow(self, flow):
        if False:
            yield None
'''


@pytest.fixture
def installed_and_disabled(install_fake_plugin, activation_config, api_client):
    """A real catalog with the fake plugin installed and **off** (it cannot load yet)."""
    import importlib

    from pwnproxy.plugins.core.loader import PluginLoader

    fake = install_fake_plugin(source=DISABLED_PLUGIN_SOURCE, class_name="DisabledPlugin")
    module = importlib.import_module(fake.module)
    activation_config("")  # an installed plugin is off until the user turns it on
    hook_bus = HookBus()
    loader = PluginLoader(hook_bus)
    asyncio.run(loader.refresh_catalog())
    app.state.hook_bus = hook_bus
    app.state.plugin_loader = loader
    try:
        yield api_client(app), module
    finally:
        for attribute in ("hook_bus", "plugin_loader"):
            if hasattr(app.state, attribute):
                delattr(app.state, attribute)


class TestDisabledPlugin:
    # @escenario plugin-config/rutas-y-codigos/configurar-un-plugin-desactivado
    def test_the_configuration_of_a_disabled_plugin_can_be_read_and_written(
        self, installed_and_disabled
    ):
        client, module = installed_and_disabled

        schema = client.get(f"/api/v1/plugins/{NAME}/schema")
        written = client.patch(
            f"/api/v1/plugins/{NAME}/settings", json={"values": {"environment": "staging"}}
        )
        catalog = client.get("/api/v1/plugins")

        assert (
            schema.status_code,
            written.status_code,
            written.json()["values"]["environment"],
            module.LOADS,
            [
                (plugin["enabled"], plugin["loaded"])
                for plugin in catalog.json()["plugins"]
                if plugin["name"] == NAME
            ],
        ) == (200, 200, {"value": "staging"}, [], [(False, False)])

    # @escenario plugin-config/rutas-y-codigos/accion-sobre-un-plugin-no-cargado
    def test_an_action_on_a_disabled_plugin_is_409(self, installed_and_disabled):
        client, module = installed_and_disabled

        response = client.post(f"/api/v1/plugins/{NAME}/actions/probe", json={"parameters": {}})

        assert (response.status_code, response.json(), module.LOADS) == (
            409,
            {"detail": f"plugin '{NAME}' is not loaded"},
            [],
        )


class TestCollections:
    # @escenario plugin-config/colecciones/crear-hasta-el-maximo
    def test_the_items_are_created_up_to_the_declared_maximum(self, plugin_config):
        scene = plugin_config()

        first = scene.client.post(
            f"/api/v1/plugins/{NAME}/collections/webhooks",
            json={"values": {"name": "app", "events": ["app.lab"]}},
        )
        second = scene.client.post(
            f"/api/v1/plugins/{NAME}/collections/webhooks", json={"values": {"name": "ci"}}
        )
        listing = scene.client.get(f"/api/v1/plugins/{NAME}/collections/webhooks")

        assert (
            first.status_code,
            first.json(),
            second.status_code,
            listing.status_code,
            listing.json()["max_items"],
            [item["id"] for item in listing.json()["items"]],
        ) == (
            201,
            {
                "id": "app",
                "values": {
                    "name": {"value": "app"},
                    "events": {"value": ["app.lab"]},
                    "signing_key": {"set": False},
                },
            },
            201,
            200,
            2,
            ["app", "ci"],
        )

    # @escenario plugin-config/colecciones/coleccion-llena
    def test_a_full_collection_is_409_without_asking_the_plugin(self, plugin_config):
        scene = plugin_config()
        for webhook in ("app", "ci"):
            scene.client.post(
                f"/api/v1/plugins/{NAME}/collections/webhooks", json={"values": {"name": webhook}}
            )

        response = scene.client.post(
            f"/api/v1/plugins/{NAME}/collections/webhooks", json={"values": {"name": "deploy"}}
        )

        assert (
            response.status_code,
            response.json(),
            scene.plugin.call_count("collection_create"),
            [item["id"] for item in scene.plugin.items],
        ) == (409, {"detail": "collection 'webhooks' is full (max 2 items)"}, 2, ["app", "ci"])

    # @escenario plugin-config/colecciones/borrar-libera-capacidad
    def test_deleting_frees_capacity(self, plugin_config):
        scene = plugin_config()
        for webhook in ("app", "ci"):
            scene.client.post(
                f"/api/v1/plugins/{NAME}/collections/webhooks", json={"values": {"name": webhook}}
            )

        deleted = scene.client.delete(f"/api/v1/plugins/{NAME}/collections/webhooks/app")
        recreated = scene.client.post(
            f"/api/v1/plugins/{NAME}/collections/webhooks", json={"values": {"name": "deploy"}}
        )

        assert (
            deleted.status_code,
            deleted.content,
            recreated.status_code,
            recreated.json()["id"],
            [item["id"] for item in scene.plugin.items],
        ) == (204, b"", 201, "deploy", ["ci", "deploy"])

    @pytest.mark.parametrize("method", ["PATCH", "DELETE"])
    def test_an_unknown_item_is_404(self, plugin_config, method):
        scene = plugin_config()
        body = {"values": {"name": "app"}} if method == "PATCH" else None

        response = _request(
            scene.client, method, f"/api/v1/plugins/{NAME}/collections/webhooks/ghost", body
        )

        assert (response.status_code, response.json()) == (
            404,
            {"detail": f"plugin '{NAME}' has no webhooks 'ghost'"},
        )

    # @escenario plugin-config/colecciones/el-maximo-no-es-la-politica
    def test_the_plugin_policy_is_422_not_409(self, plugin_config):
        schema = PluginConfigSchema(
            collections=[
                CollectionSpec(
                    name="webhooks",
                    max_items=5,
                    item=[FieldSpec(key="name", type="string", required=True)],
                )
            ]
        )
        scene = plugin_config(ConfigPlugin(schema))
        statuses = [
            scene.client.post(
                f"/api/v1/plugins/{NAME}/collections/webhooks", json={"values": {"name": webhook}}
            ).status_code
            for webhook in ("a", "b", "c", "d")
        ]
        scene.plugin.reject = ("name", "webhook names must be unique")

        response = scene.client.post(
            f"/api/v1/plugins/{NAME}/collections/webhooks", json={"values": {"name": "e"}}
        )

        assert (
            statuses,
            response.status_code,
            response.json(),
            [item["id"] for item in scene.plugin.items],
        ) == (
            [201, 201, 201, 201],
            422,
            {
                "detail": {
                    "field": "name",
                    "message": "webhook names must be unique",
                }
            },
            ["a", "b", "c", "d"],
        )

    def test_a_collection_the_schema_does_not_declare_is_404(self, plugin_config):
        scene = plugin_config()

        response = scene.client.get(f"/api/v1/plugins/{NAME}/collections/schedules")

        assert (response.status_code, response.json()) == (
            404,
            {"detail": f"plugin '{NAME}' declares no collection 'schedules'"},
        )


def _wait_for_task(client, store: TaskStore, task_id: str, timeout: float = 5.0) -> dict:
    """Poll the task through the app's loop until it reaches a terminal state."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        task = client.portal.call(store.get, task_id)
        if task and task["status"] in ("completed", "failed", "cancelled"):
            return task
        time.sleep(0.02)
    raise AssertionError(f"task {task_id} did not finish in {timeout}s")


@pytest.fixture
def task_store(tmp_path):
    """A real ``TaskStore`` on a temporary database (the scan tests' pattern)."""
    engine = create_task_engine(str(tmp_path / "tasks.db"))
    asyncio.run(init_task_db(engine))
    store = TaskStore(engine)
    asyncio.run(store.init())
    try:
        yield store
    finally:
        asyncio.run(engine.dispose())


class TestActions:
    # @escenario plugin-config/acciones/accion-corta
    def test_a_short_action_answers_its_result_inline(self, plugin_config):
        scene = plugin_config()

        response = scene.client.post(
            f"/api/v1/plugins/{NAME}/actions/ping", json={"parameters": {"name": "app"}}
        )

        assert (response.status_code, response.json(), scene.plugin.action_calls) == (
            200,
            {
                "plugin": NAME,
                "action": "ping",
                "status": "completed",
                "result": {"ok": True},
            },
            [("ping", {"name": "app"})],
        )

    # @escenario plugin-config/acciones/accion-larga-devuelve-task-id
    def test_a_long_action_is_202_and_its_result_lands_in_the_task(self, plugin_config, task_store):
        scene = plugin_config(task_store=task_store)

        response = scene.client.post(
            f"/api/v1/plugins/{NAME}/actions/send_test", json={"parameters": {}}
        )
        payload = response.json()
        task = _wait_for_task(scene.client, task_store, payload["task_id"])
        polled = scene.client.get(f"/api/v1/tasks/{payload['task_id']}")

        assert (
            response.status_code,
            payload,
            task["type"],
            task["status"],
            task["result"],
            task["error"],
            polled.status_code,
            polled.json()["result"],
        ) == (
            202,
            {"plugin": NAME, "action": "send_test", "status": "running", "task_id": payload["task_id"]},
            "plugin_action",
            "completed",
            {"ok": True},
            None,
            200,
            {"ok": True},
        )

    # @escenario plugin-config/acciones/la-accion-larga-falla
    def test_a_failing_long_action_keeps_the_task_failed_without_a_trace(
        self, plugin_config, task_store, caplog
    ):
        scene = plugin_config(task_store=task_store)
        scene.plugin.action_error = RuntimeError(f"login went wrong with {CANARY}")

        with caplog.at_level(logging.ERROR):
            response = scene.client.post(
                f"/api/v1/plugins/{NAME}/actions/send_test", json={"parameters": {}}
            )
            task = _wait_for_task(scene.client, task_store, response.json()["task_id"])

        assert (
            response.status_code,
            task["status"],
            task["error"],
            CANARY in json.dumps(task),
            CANARY in caplog.text,
        ) == (
            202,
            "failed",
            f"plugin '{NAME}' action 'send_test' failed",
            False,
            True,
        )

    # @escenario plugin-config/acciones/parametros-de-la-accion-invalidos
    def test_invalid_parameters_are_422_and_the_action_never_runs(self, plugin_config):
        scene = plugin_config()

        response = scene.client.post(
            f"/api/v1/plugins/{NAME}/actions/ping", json={"parameters": {}}
        )

        assert (
            response.status_code,
            response.json(),
            scene.plugin.call_count("run_action"),
        ) == (
            422,
            {"detail": {"field": "name", "message": "required field is missing"}},
            0,
        )

    def test_an_undeclared_action_is_404(self, plugin_config):
        scene = plugin_config()

        response = scene.client.post(
            f"/api/v1/plugins/{NAME}/actions/self_destruct", json={"parameters": {}}
        )

        assert (response.status_code, response.json()) == (
            404,
            {"detail": f"plugin '{NAME}' declares no action 'self_destruct'"},
        )

    def test_a_long_action_without_a_task_store_is_503(self, plugin_config):
        """It is never run inline: the contract says ``202`` + ``task_id`` or nothing."""
        scene = plugin_config()

        response = scene.client.post(
            f"/api/v1/plugins/{NAME}/actions/send_test", json={"parameters": {}}
        )

        assert (response.status_code, response.json(), scene.plugin.call_count("run_action")) == (
            503,
            {"detail": "task store not available"},
            0,
        )


class TestAudit:
    # @escenario plugin-config/auditoria/evento-sin-valores
    def test_a_confirmed_write_publishes_the_event_and_one_log_line(self, plugin_config, caplog):
        scene = plugin_config()
        queue = scene.bus.register(PLUGIN_CONFIG_CHANGED)

        with caplog.at_level(logging.INFO, logger="pwnproxy.plugins.core.config_service"):
            response = scene.client.patch(
                f"/api/v1/plugins/{NAME}/settings", json={"values": {"signing_key": CANARY}}
            )
        event = queue.get_nowait()
        timestamp = event.pop("timestamp")

        assert (
            response.status_code,
            event,
            datetime.fromisoformat(timestamp) is not None,
            CANARY in json.dumps(event),
            [
                (record.levelname, f"plugin={NAME}" in record.getMessage())
                for record in caplog.records
                if "plugin config changed" in record.getMessage()
            ],
            CANARY in caplog.text,
        ) == (
            200,
            {
                "plugin": NAME,
                "kind": "settings",
                "target": "settings",
                "item_id": None,
                "changed": ["signing_key"],
                "scope": "full",
            },
            True,
            False,
            [("INFO", True)],
            False,
        )

    # @escenario plugin-config/auditoria/escritura-fallida-sin-evento
    def test_a_rejected_write_leaves_no_event_and_no_success_line(self, plugin_config, caplog):
        scene = plugin_config()
        queue = scene.bus.register(PLUGIN_CONFIG_CHANGED)

        with caplog.at_level(logging.INFO, logger="pwnproxy.plugins.core.config_service"):
            response = scene.client.patch(
                f"/api/v1/plugins/{NAME}/settings", json={"values": {"no_existe": 1}}
            )

        assert (response.status_code, queue.has_data, _config_log_lines(caplog)) == (
            422,
            False,
            [],
        )

    def test_a_forbidden_write_leaves_no_event_either(self, plugin_config, agent_client, caplog):
        scene = plugin_config(client=agent_client)
        queue = scene.bus.register(PLUGIN_CONFIG_CHANGED)

        with caplog.at_level(logging.INFO, logger="pwnproxy.plugins.core.config_service"):
            response = scene.client.patch(
                f"/api/v1/plugins/{NAME}/settings", json={"values": {"signing_key": CANARY}}
            )

        assert (response.status_code, queue.has_data, _config_log_lines(caplog)) == (
            403,
            False,
            [],
        )

    def test_the_collection_and_action_events_name_their_target(self, plugin_config):
        scene = plugin_config()
        queue = scene.bus.register(PLUGIN_CONFIG_CHANGED)

        created = scene.client.post(
            f"/api/v1/plugins/{NAME}/collections/webhooks",
            json={"values": {"name": "app", "events": ["app.lab"]}},
        )
        delete = scene.client.delete(f"/api/v1/plugins/{NAME}/collections/webhooks/app")
        action = scene.client.post(
            f"/api/v1/plugins/{NAME}/actions/probe", json={"parameters": {}}
        )
        events = [queue.get_nowait() for _ in range(3)]
        for event in events:
            event.pop("timestamp")

        assert (
            created.status_code,
            delete.status_code,
            action.status_code,
            events,
        ) == (
            201,
            204,
            200,
            [
                {
                    "plugin": NAME,
                    "kind": "collection",
                    "target": "webhooks",
                    "item_id": "app",
                    "changed": ["events", "name"],
                    "scope": "full",
                },
                {
                    "plugin": NAME,
                    "kind": "collection",
                    "target": "webhooks",
                    "item_id": "app",
                    "changed": [],
                    "scope": "full",
                },
                {
                    "plugin": NAME,
                    "kind": "action",
                    "target": "probe",
                    "item_id": None,
                    "changed": [],
                    "scope": "full",
                },
            ],
        )
