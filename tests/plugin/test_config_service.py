"""Service-level tests for ``pwnproxy.plugins.core.config_service``.

These are the rules of the change that do **not** need a HTTP client: what the
core validates, what it refuses to publish, how the plugin's own errors travel,
and the two decisions that shape the service — a disabled plugin can be
configured (with a disposable instance and no ``on_load()``) and an action cannot
run on a plugin that is not loaded.

The HTTP half (status codes over the wire, the scope matrix, the audit event) is
covered by ``tests/api/test_plugin_config*.py``.
"""

from __future__ import annotations

import asyncio
import importlib
import logging

import pytest

from pwnproxy.plugins.core.catalog import PluginRecord
from pwnproxy.plugins.core.config_schema import (
    ActionSpec,
    CollectionSpec,
    FieldSpec,
    PluginConfigSchema,
    PluginItemNotFound,
    PluginValidationError,
    SchemaViolation,
)
from pwnproxy.plugins.core.config_service import (
    ActionNotDeclared,
    CollectionFull,
    CollectionNotDeclared,
    InvalidConfigSchema,
    ItemNotFound,
    MissingPluginMethod,
    PluginCannotRun,
    PluginConfigService,
    PluginNotFound,
    PluginNotLoaded,
    TaskStoreUnavailable,
    error_response,
)
from pwnproxy.plugins.core.loader import PluginLoader
from pwnproxy.services.session.store import TaskStore
from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.task_model import create_task_engine

#: Value that must never reach an API body: any leak is an assertion failure.
CANARY = "CANARIO-9d41f0"

#: Name the fake catalog uses; every message of the contract quotes it.
NAME = "example-checker"


class NoSchemaPlugin:
    """A plugin with no configuration contract at all (like the six scanners)."""

    def __init__(self) -> None:
        self.loaded = False
        self.calls: list[str] = []

    async def on_load(self) -> None:
        self.loaded = True


class FakePlugin(NoSchemaPlugin):
    """A plugin that declares a schema and records everything the core asks it.

    ``settings`` and ``items`` are the plugin's own store (the core never keeps
    them), ``calls`` is the spy that proves a rejected write never arrived, and
    ``reject`` makes any write raise :class:`PluginValidationError` with the
    plugin's own message.
    """

    def __init__(self, schema: PluginConfigSchema | None = None) -> None:
        super().__init__()
        self.schema = schema or _schema()
        self.settings: dict[str, object] = {"environment": "lab"}
        self.secrets: set[str] = {"signing_key"}
        self.items: list[dict[str, object]] = []
        self.configuration_writes: list[dict[str, object]] = []
        self.reject: tuple[str, str] | None = None
        self.action_result: object = {"ok": True}
        self.action_error: BaseException | None = None

    def config_schema(self) -> PluginConfigSchema:
        self.calls.append("config_schema")
        return self.schema

    def config_read(self) -> dict[str, object]:
        self.calls.append("config_read")
        reported = dict(self.settings)
        for key in self.secrets:
            # A hostile plugin: it also reports the value of its own secret.
            reported[key] = CANARY
            reported[f"{key}__set"] = True
        return reported

    def config_write(self, values: dict[str, object]) -> None:
        self.calls.append("config_write")
        if self.reject:
            raise PluginValidationError(*self.reject)
        self.configuration_writes.append(dict(values))
        for key, value in values.items():
            if key == "signing_key":
                self.secrets.add(key)
            else:
                self.settings[key] = value

    def collection_list(self, name: str) -> list[dict[str, object]]:
        self.calls.append("collection_list")
        return [dict(item) for item in self.items]

    def collection_create(self, name: str, values: dict[str, object]) -> dict[str, object]:
        self.calls.append("collection_create")
        if self.reject:
            raise PluginValidationError(*self.reject)
        item = {"id": values.get("name"), **values}
        if "signing_key" in values:
            self.secrets.add("signing_key")
            item["signing_key__set"] = True
        item.pop("signing_key", None)
        self.items.append(item)
        return dict(item)

    def collection_update(
        self, name: str, item_id: str, values: dict[str, object]
    ) -> dict[str, object]:
        self.calls.append("collection_update")
        item = next((entry for entry in self.items if entry["id"] == item_id), None)
        if item is None:
            raise PluginItemNotFound(name, item_id)
        if self.reject:
            raise PluginValidationError(*self.reject)
        item.update(values)
        return dict(item)

    def collection_delete(self, name: str, item_id: str) -> None:
        self.calls.append("collection_delete")
        item = next((entry for entry in self.items if entry["id"] == item_id), None)
        if item is None:
            raise PluginItemNotFound(name, item_id)
        self.items.remove(item)

    def run_action(self, name: str, parameters: dict[str, object]) -> object:
        self.calls.append("run_action")
        if self.action_error is not None:
            raise self.action_error
        return self.action_result


def _schema() -> PluginConfigSchema:
    """The schema every fake declares unless a test says otherwise."""
    return PluginConfigSchema(
        settings=[
            FieldSpec(key="environment", type="enum", choices=["lab", "staging"], default="lab"),
            FieldSpec(key="retries", type="integer", minimum=0, maximum=5),
            FieldSpec(key="signing_key", type="string", max_length=64, secret=True),
        ],
        collections=[
            CollectionSpec(
                name="webhooks",
                max_items=2,
                item=[
                    FieldSpec(key="name", type="string", required=True, max_length=16),
                    FieldSpec(key="events", type="array", items="string", max_items=4),
                    FieldSpec(key="status", type="enum", choices=["active", "failing"], read_only=True),
                    FieldSpec(key="signing_key", type="string", max_length=4096, secret=True),
                ],
            )
        ],
        actions=[
            ActionSpec(
                name="ping",
                parameters=[FieldSpec(key="name", type="string", required=True)],
            ),
            ActionSpec(name="send_test", long_running=True),
        ],
    )


def _immutable_name_schema() -> PluginConfigSchema:
    """``_schema()`` with ``name`` frozen: the field that addresses the item.

    ``name`` is ``required`` and ``immutable``, so it is demanded exactly once, on
    the create. ``events`` stays editable, which is what proves the rule does not
    freeze the whole item.
    """
    return PluginConfigSchema(
        settings=_schema().settings,
        collections=[
            CollectionSpec(
                name="webhooks",
                max_items=2,
                item=[
                    FieldSpec(key="name", type="string", required=True, max_length=16, immutable=True),
                    FieldSpec(key="events", type="array", items="string", max_items=4),
                ],
            )
        ],
        actions=_schema().actions,
    )


class FakeLoader:
    """The only two things the service needs from a loader (D4's seam)."""

    def __init__(
        self,
        record: PluginRecord | None = None,
        loaded: object | None = None,
    ) -> None:
        self._records = {record.name: record} if record is not None else {}
        self._loaded = {record.name: loaded} if (record is not None and loaded is not None) else {}

    def get_record(self, name: str) -> PluginRecord | None:
        return self._records.get(name)

    def get_plugin(self, name: str) -> object | None:
        return self._loaded.get(name)


def _record(factory, *, error: str | None = None, name: str = NAME) -> PluginRecord:
    return PluginRecord(
        name=name,
        source="installed",
        package="example-checker",
        version="1.0.0",
        entry_point="fake_plugin:Configurable",
        factory=factory,
        error=error,
        metadata=None,
    )


def _service(plugin, *, task_store=None, hook_bus=None) -> tuple[PluginConfigService, list]:
    """Build a service over a catalog whose record is ``plugin`` (not loaded)."""
    created: list = []

    def factory():
        instance = plugin() if callable(plugin) else plugin
        created.append(instance)
        return instance

    loader = FakeLoader(_record(factory))
    return PluginConfigService(loader, task_store=task_store, hook_bus=hook_bus), created


def _loaded_service(plugin, *, task_store=None) -> PluginConfigService:
    """Build a service over a catalog whose plugin is already loaded."""
    return PluginConfigService(FakeLoader(_record(lambda: plugin), loaded=plugin), task_store=task_store)


async def _wait_for_task(store: TaskStore, task_id: str, timeout: float = 5.0) -> dict:
    """Poll ``TaskStore`` until the task reaches a terminal state."""
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        task = await store.get(task_id)
        assert task is not None
        if task["status"] in ("completed", "failed", "cancelled"):
            return task
        assert asyncio.get_running_loop().time() < deadline, f"task did not finish: {task}"
        await asyncio.sleep(0.01)


class TestErrorResponse:
    @pytest.mark.parametrize(
        ("exc", "expected"),
        [
            (SchemaViolation("signing_key", "unknown field"), (422, {"field": "signing_key", "message": "unknown field"})),
            (
                PluginValidationError("name", "webhook names must be unique"),
                (422, {"field": "name", "message": "webhook names must be unique"}),
            ),
            (PluginNotFound(NAME), (404, f"plugin '{NAME}' not found")),
            (CollectionNotDeclared(NAME, "ids"), (404, f"plugin '{NAME}' declares no collection 'ids'")),
            (ActionNotDeclared(NAME, "run"), (404, f"plugin '{NAME}' declares no action 'run'")),
            (ItemNotFound(NAME, "webhooks", "app"), (404, f"plugin '{NAME}' has no webhooks 'app'")),
            (PluginCannotRun(NAME, "boom"), (409, f"plugin '{NAME}' cannot run: boom")),
            (
                InvalidConfigSchema(NAME, "bad"),
                (409, f"plugin '{NAME}' declares an invalid configuration schema: bad"),
            ),
            (PluginNotLoaded(NAME), (409, f"plugin '{NAME}' is not loaded")),
            (CollectionFull("webhooks", 2), (409, "collection 'webhooks' is full (max 2 items)")),
            (MissingPluginMethod(NAME, "config_read"), (409, f"plugin '{NAME}' declares no config_read")),
            (TaskStoreUnavailable(), (503, "task store not available")),
        ],
    )
    def test_the_code_table_lives_in_one_place(self, exc, expected):
        assert error_response(exc, plugin=NAME) == expected

    def test_anything_else_is_a_fixed_500(self):
        """The internal message must not reach the client (the trace goes to the log)."""
        exc = RuntimeError(f"sqlite exploded while writing signing_key={CANARY}")

        status, detail = error_response(exc, plugin=NAME)

        assert (status, detail) == (500, f"plugin '{NAME}' failed")
        assert CANARY not in str(detail)


class TestSchema:
    @pytest.mark.asyncio
    # @escenario plugin-config/esquema-versionado/el-esquema-declarado-se-publica-completo
    async def test_the_schema_is_published_under_the_catalog_name(self):
        plugin = FakePlugin(PluginConfigSchema(plugin="spoofed", settings=_schema().settings))
        service, _ = _service(plugin)

        published = await service.schema(NAME)

        assert published == {**plugin.schema.to_dict(), "plugin": NAME}

    @pytest.mark.asyncio
    # @escenario plugin-config/esquema-versionado/un-plugin-sin-esquema-responde-un-esquema-vacio
    async def test_a_plugin_without_a_schema_publishes_the_empty_one(self):
        service, created = _service(NoSchemaPlugin())

        published = await service.schema(NAME)

        assert published == {
            "plugin": NAME,
            "schema_version": 1,
            "settings": [],
            "collections": [],
            "actions": [],
        }
        assert len(created) == 1

    @pytest.mark.asyncio
    # @escenario plugin-config/rutas-y-codigos/nombre-fuera-del-catalogo
    async def test_an_unknown_name_is_not_found(self):
        service = PluginConfigService(FakeLoader())

        with pytest.raises(PluginNotFound) as excinfo:
            await service.schema("does-not-exist")

        assert error_response(excinfo.value, plugin="does-not-exist") == (
            404,
            "plugin 'does-not-exist' not found",
        )

    @pytest.mark.asyncio
    # @escenario plugin-config/rutas-y-codigos/plugin-roto
    async def test_a_broken_record_cannot_run(self):
        service = PluginConfigService(FakeLoader(_record(None, error="import failed (ImportError: nope)")))

        with pytest.raises(PluginCannotRun) as excinfo:
            await service.schema(NAME)

        assert error_response(excinfo.value, plugin=NAME) == (
            409,
            f"plugin '{NAME}' cannot run: import failed (ImportError: nope)",
        )

    @pytest.mark.asyncio
    async def test_a_factory_that_raises_cannot_run(self):
        def factory():
            raise RuntimeError("no license")

        service = PluginConfigService(FakeLoader(_record(factory)))

        with pytest.raises(PluginCannotRun) as excinfo:
            await service.schema(NAME)

        assert str(excinfo.value) == f"plugin '{NAME}' cannot run: instantiation failed (RuntimeError: no license)"

    @pytest.mark.asyncio
    # @escenario plugin-config/esquema-versionado/un-esquema-invalido-no-se-publica
    @pytest.mark.parametrize(
        ("schema", "reason"),
        [
            (
                PluginConfigSchema(settings=[FieldSpec(key="retries", type="integer", secret=True)]),
                "field 'retries' is secret but its type is 'integer' (only string fields can be secret)",
            ),
            (
                PluginConfigSchema(settings=[FieldSpec(key="environment", type="string", choices=["lab"])]),
                "field 'environment' declares choices but is not an enum",
            ),
            (
                PluginConfigSchema(
                    actions=[ActionSpec(name="run", parameters=[FieldSpec(key="signing_key", type="string", secret=True)])]
                ),
                "action parameter 'signing_key' cannot be secret: a long action persists its parameters",
            ),
        ],
    )
    async def test_an_invalid_schema_is_a_conflict_with_its_reason(self, schema, reason):
        service, _ = _service(FakePlugin(schema))

        with pytest.raises(InvalidConfigSchema) as excinfo:
            await service.schema(NAME)

        assert error_response(excinfo.value, plugin=NAME) == (
            409,
            f"plugin '{NAME}' declares an invalid configuration schema: {reason}",
        )

    @pytest.mark.asyncio
    async def test_a_schema_that_is_not_a_schema_is_a_conflict(self):
        plugin = FakePlugin()
        plugin.config_schema = lambda: {"settings": []}  # type: ignore[method-assign]
        service, _ = _service(plugin)

        with pytest.raises(InvalidConfigSchema) as excinfo:
            await service.schema(NAME)

        assert str(excinfo.value) == (
            f"plugin '{NAME}' declares an invalid configuration schema: "
            "config_schema() must return a PluginConfigSchema"
        )

    @pytest.mark.asyncio
    async def test_an_async_schema_is_accepted(self):
        """A plugin may implement the contract with ``async def``."""
        plugin = FakePlugin()

        async def config_schema():
            return plugin.schema

        plugin.config_schema = config_schema  # type: ignore[method-assign]
        service, _ = _service(plugin)

        published = await service.schema(NAME)

        assert published["settings"] == [spec.to_dict() for spec in plugin.schema.settings]

    @pytest.mark.asyncio
    async def test_the_schema_is_read_from_the_plugin_every_time(self):
        """No cache: a plugin that reloads publishes its new schema immediately."""
        plugin = FakePlugin()
        service, _ = _service(plugin)

        await service.schema(NAME)
        plugin.schema = PluginConfigSchema(settings=[FieldSpec(key="depth", type="integer")])
        published = await service.schema(NAME)

        assert [spec["key"] for spec in published["settings"]] == ["depth"]


class TestSettings:
    @pytest.mark.asyncio
    # @escenario plugin-config/secretos-de-solo-escritura/la-lectura-no-trae-el-valor
    async def test_a_read_never_publishes_the_value_of_a_secret(self):
        plugin = FakePlugin()
        service, _ = _service(plugin)

        payload = await service.read_settings(NAME)

        assert payload == {
            "plugin": NAME,
            "schema_version": 1,
            "values": {
                "environment": {"value": "lab"},
                "signing_key": {"set": True},
            },
        }
        assert CANARY not in str(payload)

    @pytest.mark.asyncio
    # @escenario plugin-config/esquema-versionado/un-plugin-sin-esquema-responde-un-esquema-vacio
    async def test_a_plugin_without_settings_answers_empty_values(self):
        service, _ = _service(NoSchemaPlugin())

        assert await service.read_settings(NAME) == {
            "plugin": NAME,
            "schema_version": 1,
            "values": {},
        }

    @pytest.mark.asyncio
    async def test_settings_without_a_reader_are_a_conflict(self):
        class WriteOnly(FakePlugin):
            config_read = None  # type: ignore[assignment]

        service, _ = _service(WriteOnly())

        with pytest.raises(MissingPluginMethod) as excinfo:
            await service.read_settings(NAME)

        assert str(excinfo.value) == f"plugin '{NAME}' declares no config_read"

    @pytest.mark.asyncio
    # @escenario plugin-config/validacion-antes-del-plugin/escritura-parcial
    async def test_a_write_touches_only_the_keys_it_sends(self):
        plugin = FakePlugin()
        plugin.settings["retries"] = 3
        service, _ = _service(plugin)

        payload = await service.write_settings(NAME, {"environment": "staging"})

        assert payload["values"]["environment"] == {"value": "staging"}
        assert payload["values"]["retries"] == {"value": 3}
        assert plugin.configuration_writes == [{"environment": "staging"}]

    @pytest.mark.asyncio
    # @escenario plugin-config/alcance-full-para-secretos/full-escribe-el-secreto-y-la-lectura-solo-dice-set
    async def test_a_written_secret_is_read_back_only_as_set(self):
        plugin = FakePlugin()
        service, _ = _service(plugin)

        payload = await service.write_settings(NAME, {"signing_key": CANARY})

        assert payload["values"]["signing_key"] == {"set": True}
        assert CANARY not in str(payload)

    @pytest.mark.asyncio
    # @escenario plugin-config/validacion-antes-del-plugin/clave-desconocida
    @pytest.mark.parametrize(
        ("values", "field", "message"),
        [
            ({"no_existe": 1}, "no_existe", "unknown field"),
            ({"retries": "texto"}, "retries", "expected an integer"),
            ({"environment": "produccion"}, "environment", "value is not one of the declared choices"),
            ({"retries": 9}, "retries", "value is above the maximum 5"),
            ({"signing_key": "x" * 65}, "signing_key", "string is longer than 64 characters"),
            ({"signing_key": None}, "signing_key", "null is not a value"),
        ],
    )
    async def test_an_invalid_write_never_reaches_the_plugin(self, values, field, message):
        plugin = FakePlugin()
        service, _ = _service(plugin)

        with pytest.raises(SchemaViolation) as excinfo:
            await service.write_settings(NAME, values)

        assert error_response(excinfo.value, plugin=NAME) == (422, {"field": field, "message": message})
        assert plugin.configuration_writes == []
        assert "config_write" not in plugin.calls

    @pytest.mark.asyncio
    # @escenario plugin-config/reglas-del-plugin/una-regla-del-plugin-llega-como-422-con-su-mensaje
    async def test_the_plugins_own_validation_message_travels_untouched(self):
        plugin = FakePlugin()
        plugin.reject = ("environment", "environment 'client' needs a license")
        service, _ = _service(plugin)

        with pytest.raises(PluginValidationError) as excinfo:
            await service.write_settings(NAME, {"environment": "staging"})

        assert error_response(excinfo.value, plugin=NAME) == (
            422,
            {"field": "environment", "message": "environment 'client' needs a license"},
        )

    @pytest.mark.asyncio
    # @escenario plugin-config/reglas-del-plugin/excepcion-inesperada-del-plugin
    async def test_an_unexpected_exception_is_a_fixed_500_and_leaves_the_secret_out(self):
        plugin = FakePlugin()

        def config_write(values):
            raise RuntimeError(f"disk full while saving signing_key={CANARY}")

        plugin.config_write = config_write  # type: ignore[method-assign]
        service, _ = _service(plugin)

        with pytest.raises(RuntimeError) as excinfo:
            await service.write_settings(NAME, {"signing_key": CANARY})

        # The raw exception keeps the value (it is what the log will print); the
        # body the client gets does not.
        assert CANARY in str(excinfo.value)
        assert error_response(excinfo.value, plugin=NAME) == (500, f"plugin '{NAME}' failed")

    @pytest.mark.asyncio
    async def test_a_plugin_without_a_writer_is_a_conflict(self):
        class ReadOnly(FakePlugin):
            config_write = None  # type: ignore[assignment]

        service, _ = _service(ReadOnly())

        with pytest.raises(MissingPluginMethod) as excinfo:
            await service.write_settings(NAME, {"environment": "lab"})

        assert str(excinfo.value) == f"plugin '{NAME}' declares no config_write"

    @pytest.mark.asyncio
    async def test_a_writer_without_reader_answers_what_it_just_wrote(self):
        class WriteOnly(FakePlugin):
            config_read = None  # type: ignore[assignment]

        service, _ = _service(WriteOnly())

        payload = await service.write_settings(NAME, {"environment": "staging", "signing_key": CANARY})

        assert payload == {
            "plugin": NAME,
            "schema_version": 1,
            "values": {"environment": {"value": "staging"}, "signing_key": {"set": True}},
        }
        assert CANARY not in str(payload)


class TestCollections:
    @pytest.mark.asyncio
    # @escenario plugin-config/colecciones-con-maximo/crear-hasta-el-maximo
    async def test_the_collection_is_published_with_its_capacity_and_rendered_items(self):
        plugin = FakePlugin()
        plugin.items = [{"id": "app", "name": "app", "events": ["app.lab"], "signing_key__set": True}]
        service, _ = _service(plugin)

        payload = await service.list_items(NAME, "webhooks")

        assert payload == {
            "plugin": NAME,
            "collection": "webhooks",
            "schema_version": 1,
            "max_items": 2,
            "items": [
                {
                    "id": "app",
                    "values": {
                        "name": {"value": "app"},
                        "events": {"value": ["app.lab"]},
                        "signing_key": {"set": True},
                    },
                }
            ],
        }

    @pytest.mark.asyncio
    async def test_an_undeclared_collection_is_not_found(self):
        service, _ = _service(FakePlugin())

        with pytest.raises(CollectionNotDeclared) as excinfo:
            await service.list_items(NAME, "no_existe")

        assert error_response(excinfo.value, plugin=NAME) == (
            404,
            f"plugin '{NAME}' declares no collection 'no_existe'",
        )

    @pytest.mark.asyncio
    # @escenario plugin-config/colecciones-con-maximo/coleccion-llena
    async def test_a_full_collection_is_a_conflict_without_calling_the_plugin(self):
        plugin = FakePlugin()
        plugin.items = [{"id": "app", "name": "app"}, {"id": "billing", "name": "billing"}]
        service, _ = _service(plugin)

        with pytest.raises(CollectionFull) as excinfo:
            await service.create_item(NAME, "webhooks", {"name": "catalog"})

        assert error_response(excinfo.value, plugin=NAME) == (
            409,
            "collection 'webhooks' is full (max 2 items)",
        )
        assert "collection_create" not in plugin.calls

    @pytest.mark.asyncio
    # @escenario plugin-config/colecciones-con-maximo/borrar-libera-capacidad
    async def test_delete_frees_capacity(self):
        plugin = FakePlugin()
        plugin.items = [{"id": "app", "name": "app"}, {"id": "billing", "name": "billing"}]
        service, _ = _service(plugin)

        await service.delete_item(NAME, "webhooks", "billing")
        created = await service.create_item(NAME, "webhooks", {"name": "catalog"})

        assert created == {
            "id": "catalog",
            "values": {"name": {"value": "catalog"}, "signing_key": {"set": False}},
        }
        assert [item["id"] for item in plugin.items] == ["app", "catalog"]

    @pytest.mark.asyncio
    # @escenario plugin-config/reglas-del-plugin/elemento-inexistente
    async def test_deleting_an_item_the_plugin_no_longer_has_is_not_found(self):
        plugin = FakePlugin()
        service, _ = _service(plugin)

        with pytest.raises(ItemNotFound) as excinfo:
            await service.delete_item(NAME, "webhooks", "fantasma")

        assert error_response(excinfo.value, plugin=NAME) == (
            404,
            f"plugin '{NAME}' has no webhooks 'fantasma'",
        )

    @pytest.mark.asyncio
    async def test_updating_a_missing_item_is_not_found(self):
        service, _ = _service(FakePlugin())

        with pytest.raises(ItemNotFound) as excinfo:
            await service.update_item(NAME, "webhooks", "fantasma", {"name": "x"})

        assert str(excinfo.value) == f"plugin '{NAME}' has no webhooks 'fantasma'"

    @pytest.mark.asyncio
    # @escenario plugin-config/colecciones-con-maximo/el-maximo-no-es-la-politica
    async def test_the_plugins_policy_answers_422_not_409(self):
        plugin = FakePlugin()
        plugin.reject = ("name", "at most 1 active webhook in this environment")
        service, _ = _service(plugin)

        with pytest.raises(PluginValidationError) as excinfo:
            await service.create_item(NAME, "webhooks", {"name": "app"})

        assert error_response(excinfo.value, plugin=NAME) == (
            422,
            {"field": "name", "message": "at most 1 active webhook in this environment"},
        )
        assert plugin.items == []

    @pytest.mark.asyncio
    # @escenario plugin-config/validacion-antes-del-plugin/clave-desconocida
    async def test_an_item_write_is_validated_and_the_field_names_the_collection(self):
        plugin = FakePlugin()
        service, _ = _service(plugin)

        with pytest.raises(SchemaViolation) as excinfo:
            await service.create_item(NAME, "webhooks", {"name": "x" * 17})

        assert error_response(excinfo.value, plugin=NAME) == (
            422,
            {"field": "webhooks.name", "message": "string is longer than 16 characters"},
        )
        assert "collection_create" not in plugin.calls

    @pytest.mark.asyncio
    # @escenario plugin-config/validacion-antes-del-plugin/campo-de-solo-lectura
    async def test_a_read_only_item_field_cannot_be_written(self):
        plugin = FakePlugin()
        plugin.items = [{"id": "app", "name": "app"}]
        service, _ = _service(plugin)

        with pytest.raises(SchemaViolation) as excinfo:
            await service.update_item(NAME, "webhooks", "app", {"status": "failing"})

        assert error_response(excinfo.value, plugin=NAME) == (
            422,
            {"field": "webhooks.status", "message": "read-only field"},
        )
        assert plugin.items == [{"id": "app", "name": "app"}]

    @pytest.mark.asyncio
    async def test_an_immutable_item_field_is_refused_before_the_plugin_is_called(self):
        """The item exists and the value is the one it has: it is still a ``422``."""
        plugin = FakePlugin(_immutable_name_schema())
        plugin.items = [{"id": "app", "name": "app"}]
        service, _ = _service(plugin)

        with pytest.raises(SchemaViolation) as excinfo:
            await service.update_item(NAME, "webhooks", "app", {"name": "app"})

        assert (
            error_response(excinfo.value, plugin=NAME),
            plugin.calls.count("collection_update"),
            plugin.items,
        ) == (
            (422, {"field": "webhooks.name", "message": "cannot change after the item is created"}),
            0,
            [{"id": "app", "name": "app"}],
        )

    @pytest.mark.asyncio
    async def test_an_immutable_field_travels_on_the_create_and_the_rest_still_changes(self):
        plugin = FakePlugin(_immutable_name_schema())
        service, _ = _service(plugin)

        created = await service.create_item(
            NAME, "webhooks", {"name": "app", "events": ["finding"]}
        )
        updated = await service.update_item(NAME, "webhooks", "app", {"events": ["finding", "leak"]})

        assert (created, updated["values"], plugin.calls.count("collection_update")) == (
            {"id": "app", "values": {"name": {"value": "app"}, "events": {"value": ["finding"]}}},
            {"name": {"value": "app"}, "events": {"value": ["finding", "leak"]}},
            1,
        )

    @pytest.mark.asyncio
    async def test_a_create_requires_the_required_fields(self):
        plugin = FakePlugin()
        service, _ = _service(plugin)

        with pytest.raises(SchemaViolation) as excinfo:
            await service.create_item(NAME, "webhooks", {"events": []})

        assert error_response(excinfo.value, plugin=NAME) == (
            422,
            {"field": "webhooks.name", "message": "required field is missing"},
        )

    @pytest.mark.asyncio
    async def test_an_item_the_plugin_returns_without_an_id_is_a_fixed_500(self):
        plugin = FakePlugin()
        plugin.collection_create = lambda name, values: {"name": values.get("name")}  # type: ignore[method-assign]
        service, _ = _service(plugin)

        with pytest.raises(RuntimeError) as excinfo:
            await service.create_item(NAME, "webhooks", {"name": "app"})

        assert error_response(excinfo.value, plugin=NAME) == (500, f"plugin '{NAME}' failed")

    @pytest.mark.asyncio
    async def test_a_collection_without_a_lister_is_a_conflict(self):
        class NoLister(FakePlugin):
            collection_list = None  # type: ignore[assignment]

        service, _ = _service(NoLister())

        with pytest.raises(MissingPluginMethod) as excinfo:
            await service.list_items(NAME, "webhooks")

        assert str(excinfo.value) == f"plugin '{NAME}' declares no collection_list"


class TestActions:
    @pytest.mark.asyncio
    # @escenario plugin-config/acciones/accion-corta
    async def test_a_short_action_answers_its_result_in_line(self):
        plugin = FakePlugin()
        plugin.action_result = {"webhook": "app", "events": 3}
        service = _loaded_service(plugin)

        payload = await service.run_action(NAME, "ping", {"name": "app"})

        assert payload == {
            "plugin": NAME,
            "action": "ping",
            "status": "completed",
            "result": {"webhook": "app", "events": 3},
        }

    @pytest.mark.asyncio
    # @escenario plugin-config/acciones/parametros-de-la-accion-invalidos
    @pytest.mark.parametrize(
        ("parameters", "field", "message"),
        [
            ({}, "name", "required field is missing"),
            ({"name": 7}, "name", "expected a string"),
            ({"name": "app", "extra": 1}, "extra", "unknown field"),
        ],
    )
    async def test_invalid_parameters_never_reach_the_plugin(self, parameters, field, message):
        plugin = FakePlugin()
        service = _loaded_service(plugin)

        with pytest.raises(SchemaViolation) as excinfo:
            await service.run_action(NAME, "ping", parameters)

        assert error_response(excinfo.value, plugin=NAME) == (422, {"field": field, "message": message})
        assert "run_action" not in plugin.calls

    @pytest.mark.asyncio
    async def test_an_undeclared_action_is_not_found(self):
        service = _loaded_service(FakePlugin())

        with pytest.raises(ActionNotDeclared) as excinfo:
            await service.run_action(NAME, "rm_rf", {})

        assert error_response(excinfo.value, plugin=NAME) == (
            404,
            f"plugin '{NAME}' declares no action 'rm_rf'",
        )

    @pytest.mark.asyncio
    # @escenario plugin-config/rutas-y-codigos/accion-sobre-un-plugin-no-cargado
    async def test_an_action_needs_a_loaded_plugin(self):
        service, created = _service(FakePlugin())

        with pytest.raises(PluginNotLoaded) as excinfo:
            await service.run_action(NAME, "ping", {"name": "app"})

        assert error_response(excinfo.value, plugin=NAME) == (409, f"plugin '{NAME}' is not loaded")
        assert created == []  # no disposable instance for an action

    @pytest.mark.asyncio
    async def test_an_action_on_a_broken_plugin_says_why(self):
        service = PluginConfigService(FakeLoader(_record(None, error="on_load failed (RuntimeError: boom)")))

        with pytest.raises(PluginCannotRun) as excinfo:
            await service.run_action(NAME, "ping", {"name": "app"})

        assert error_response(excinfo.value, plugin=NAME) == (
            409,
            f"plugin '{NAME}' cannot run: on_load failed (RuntimeError: boom)",
        )

    @pytest.mark.asyncio
    # @escenario plugin-config/acciones/accion-larga-devuelve-task-id
    async def test_a_long_action_runs_through_the_task_store(self, tmp_path):
        engine = create_task_engine(str(tmp_path))
        store = TaskStore(engine)
        await store.init()
        plugin = FakePlugin()
        plugin.action_result = {"findings": 2}
        service = _loaded_service(plugin, task_store=store)

        started = await service.run_action(NAME, "send_test", {})
        task = await _wait_for_task(store, started["task_id"])

        assert started == {
            "plugin": NAME,
            "action": "send_test",
            "status": "running",
            "task_id": started["task_id"],
        }
        assert (task["type"], task["status"], task["result"], task["error"]) == (
            "plugin_action",
            "completed",
            {"findings": 2},
            None,
        )
        assert task["config"] == {"plugin": NAME, "action": "send_test", "parameters": {}}
        await engine.dispose()

    @pytest.mark.asyncio
    # @escenario plugin-config/acciones/la-accion-larga-falla
    async def test_a_failing_long_action_stores_a_fixed_error_and_no_trace(self, tmp_path, caplog):
        engine = create_task_engine(str(tmp_path))
        store = TaskStore(engine)
        await store.init()
        plugin = FakePlugin()
        plugin.action_error = RuntimeError(f"target rejected signing_key={CANARY}")
        service = _loaded_service(plugin, task_store=store)

        with caplog.at_level(logging.ERROR, logger="pwnproxy.plugins.core.config_service"):
            started = await service.run_action(NAME, "send_test", {})
            task = await _wait_for_task(store, started["task_id"])

        assert (task["status"], task["error"], task["result"]) == (
            "failed",
            f"plugin '{NAME}' action 'send_test' failed",
            None,
        )
        assert CANARY not in str(task)
        assert "Traceback" not in str(task["error"])
        assert "RuntimeError" in caplog.text  # the trace went to the log, not to tasks.db
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_a_long_action_without_a_task_store_is_unavailable(self):
        service = _loaded_service(FakePlugin())

        with pytest.raises(TaskStoreUnavailable) as excinfo:
            await service.run_action(NAME, "send_test", {})

        assert error_response(excinfo.value, plugin=NAME) == (503, "task store not available")

    @pytest.mark.asyncio
    async def test_a_scalar_result_is_stored_under_result(self, tmp_path):
        engine = create_task_engine(str(tmp_path))
        store = TaskStore(engine)
        await store.init()
        plugin = FakePlugin()
        plugin.action_result = ["a", "b"]
        service = _loaded_service(plugin, task_store=store)

        started = await service.run_action(NAME, "send_test", {})
        task = await _wait_for_task(store, started["task_id"])

        assert (task["status"], task["result"]) == ("completed", {"result": ["a", "b"]})
        await engine.dispose()


class TestDisabledPluginIsConfigurable:
    @pytest.mark.asyncio
    # @escenario plugin-config/rutas-y-codigos/configurar-un-plugin-desactivado
    async def test_a_disabled_plugin_is_read_and_written_without_on_load(
        self, install_fake_plugin, activation_config
    ):
        """D4 through the real catalog: disposable instance, never ``on_load()``."""
        fake = install_fake_plugin(
            plugin_name="configurable",
            plugin_version="1.0.0",
            class_name="Configurable",
            source=CONFIGURABLE_SOURCE,
        )
        module = importlib.import_module(fake.module)
        activation_config("")  # installed plugins are off unless configured on
        loader = PluginLoader(HookBus())
        await loader.refresh_catalog()

        # The plugin is in the catalog, disabled, and not loaded.
        assert loader.get_plugin("configurable") is None
        assert loader.plugin_enabled("configurable") is False

        service = PluginConfigService(loader, hook_bus=HookBus())
        published = await service.schema("configurable")
        written = await service.write_settings("configurable", {"environment": "staging"})

        assert published == {
            "plugin": "configurable",
            "schema_version": 1,
            "settings": [
                {
                    "key": "environment",
                    "type": "string",
                    "required": False,
                    "secret": False,
                    "read_only": False,
                    "immutable": False,
                }
            ],
            "collections": [],
            "actions": [
                {
                    "name": "ping",
                    "long_running": False,
                    "requires_scope": "full",
                    "parameters": [],
                }
            ],
        }
        assert written["values"] == {"environment": {"value": "staging"}}
        assert module.WRITES == [{"environment": "staging"}]
        assert module.LOADS == []  # on_load() never ran
        assert loader.get_plugin("configurable") is None  # and it did not become loaded
        assert loader.plugin_enabled("configurable") is False
        await loader.shutdown()

    @pytest.mark.asyncio
    # @escenario plugin-config/rutas-y-codigos/accion-sobre-un-plugin-no-cargado
    async def test_a_disabled_plugin_does_not_run_actions(self, install_fake_plugin, activation_config):
        fake = install_fake_plugin(
            plugin_name="configurable",
            plugin_version="1.0.0",
            class_name="Configurable",
            source=CONFIGURABLE_SOURCE,
        )
        module = importlib.import_module(fake.module)
        activation_config("")
        loader = PluginLoader(HookBus())
        await loader.refresh_catalog()
        service = PluginConfigService(loader)

        with pytest.raises(PluginNotLoaded) as excinfo:
            await service.run_action("configurable", "ping", {"name": "app"})

        assert error_response(excinfo.value, plugin="configurable") == (
            409,
            "plugin 'configurable' is not loaded",
        )
        assert module.ACTIONS == []
        await loader.shutdown()


#: Installed plugin used through the real catalog: it counts ``on_load()``, the
#: writes and the actions, so the test can prove what the core did **not** call.
CONFIGURABLE_SOURCE = """
from pwnproxy.plugins.core.base import (
    ActionSpec,
    FieldSpec,
    PluginConfigSchema,
    PluginMetadata,
    ScannerPlugin,
)

LOADS = []
WRITES = []
ACTIONS = []
STATE = []


class Configurable(ScannerPlugin):
    metadata = PluginMetadata(
        name="configurable", version="1.0.0", author="fixture",
        consumes=["flow"], produces=["finding"],
    )

    async def on_load(self) -> None:
        LOADS.append(self.metadata.name)

    def config_schema(self):
        return PluginConfigSchema(
            settings=[FieldSpec(key="environment", type="string")],
            actions=[ActionSpec(name="ping")],
        )

    def config_read(self):
        return {"environment": STATE[-1] if STATE else ""}

    def config_write(self, values):
        WRITES.append(dict(values))
        STATE.append(values.get("environment", ""))

    def run_action(self, name, parameters):
        ACTIONS.append(name)
        return {"ok": True}

    async def on_flow(self, flow):
        if False:
            yield None
"""
