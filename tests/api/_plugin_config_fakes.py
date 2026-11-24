"""Fake plugin catalog for the plugin-configuration HTTP tests.

The API tests need a plugin **catalog** without touching the disk and without a
real plugin package, so this module carries a fake one: a plugin that declares
the schema of the contract and records every call the core makes on it, plus a
``FakeLoader`` with the only two lookups ``PluginConfigService`` uses
(``get_record``/``get_plugin``).

Why a fake and not the ``install_fake_plugin`` fixture: the interesting paths of
these tests are "the plugin is loaded" (state has to survive between the write
and the read that follows), "the plugin is broken" (``record.error``) and "the
plugin is not loaded" (an action answers ``409``). All three are one keyword
away here and none of them needs a distribution on disk. The one test that does
need a real installed-and-disabled plugin builds it explicitly.

This is a plain module and **not** a ``conftest.py`` on purpose: a test module
that imports names from ``conftest`` (or from ``tests.*``) breaks collection the
moment the run also picks up ``apps/mcp/tests``, whose ``__init__.py`` makes
``tests`` resolve to the MCP package. ``tests/api/conftest.py`` imports the fakes
from here for its fixtures; the tests import them with a relative import.
"""

from __future__ import annotations

from pwnproxy.plugins.core.catalog import PluginRecord
from pwnproxy.plugins.core.config_schema import (
    ActionSpec,
    CollectionSpec,
    FieldSpec,
    PluginConfigSchema,
    PluginItemNotFound,
    PluginValidationError,
)

#: Value a secret is written with. Any appearance of it in a response, an event
#: or a log line is a leak and the assertion fails.
CANARY = "CANARIO-9d41f0c0"

#: Plugin name every message of the contract quotes.
NAME = "example-checker"


def default_schema() -> PluginConfigSchema:
    """The schema of the contract, as a plugin would declare it.

    Three settings (one secret), a collection capped at two items with one secret
    field and a read-only one, and three actions: a plain one with a required
    parameter, a long-running one, and one an ``agent`` token may run.
    """
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
                    FieldSpec(
                        key="status",
                        type="enum",
                        choices=["active", "failing"],
                        read_only=True,
                    ),
                    FieldSpec(key="signing_key", type="string", max_length=64, secret=True),
                ],
            )
        ],
        actions=[
            ActionSpec(
                name="ping",
                parameters=[FieldSpec(key="name", type="string", required=True)],
            ),
            ActionSpec(
                name="send_test",
                long_running=True,
                parameters=[FieldSpec(key="payload", type="string")],
            ),
            ActionSpec(name="probe", requires_scope="agent"),
        ],
    )


class NoSchemaPlugin:
    """A plugin with no configuration contract at all (like the six scanners)."""

    def __init__(self) -> None:
        self.loaded = False
        self.calls: list[str] = []

    async def on_load(self) -> None:
        self.loaded = True


class ConfigPlugin(NoSchemaPlugin):
    """A plugin that declares a schema and records what the core asks it.

    The plugin keeps its own store (``settings``/``items``) — the core never does
    — and keeps the value of every secret **out** of the renderable state, in
    ``setting_secrets``/``item_secrets``, which is what makes the leak test
    meaningful: the value exists and still may not come back.
    """

    def __init__(self, schema: PluginConfigSchema | None = None) -> None:
        super().__init__()
        self.schema = schema if schema is not None else default_schema()
        self.settings: dict[str, object] = {"environment": "lab", "retries": 1}
        self.setting_secrets: dict[str, str] = {}
        self.items: list[dict[str, object]] = []
        self.item_secrets: dict[tuple[str, str, str], str] = {}
        #: A hostile plugin: its read also returns the value of a stored secret.
        self.hostile = True
        #: ``(field, message)`` the next write raises as ``PluginValidationError``.
        self.reject: tuple[str, str] | None = None
        self.fail_read: BaseException | None = None
        self.action_result: object = {"ok": True}
        self.action_error: BaseException | None = None
        self.action_calls: list[tuple[str, dict[str, object]]] = []

    def config_schema(self) -> PluginConfigSchema:
        self.calls.append("config_schema")
        return self.schema

    def config_read(self) -> dict[str, object]:
        self.calls.append("config_read")
        if self.fail_read is not None:
            raise self.fail_read
        reported: dict[str, object] = dict(self.settings)
        for key, value in self.setting_secrets.items():
            if self.hostile:
                reported[key] = value
            reported[f"{key}__set"] = True
        return reported

    def config_write(self, values: dict[str, object]) -> None:
        self.calls.append("config_write")
        if self.reject:
            raise PluginValidationError(*self.reject)
        for key, value in values.items():
            if key == "signing_key":
                self.setting_secrets[key] = str(value)
            else:
                self.settings[key] = value

    def collection_list(self, name: str) -> list[dict[str, object]]:
        self.calls.append("collection_list")
        return [dict(item) for item in self.items]

    def collection_create(self, name: str, values: dict[str, object]) -> dict[str, object]:
        self.calls.append("collection_create")
        if self.reject:
            raise PluginValidationError(*self.reject)
        item: dict[str, object] = {"id": str(values.get("name"))}
        item.update({key: value for key, value in values.items() if key != "signing_key"})
        item["signing_key__set"] = "signing_key" in values
        if "signing_key" in values:
            self.item_secrets[(name, str(item["id"]), "signing_key")] = str(values["signing_key"])
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
        for key, value in values.items():
            if key == "signing_key":
                item["signing_key__set"] = True
                self.item_secrets[(name, item_id, key)] = str(value)
            else:
                item[key] = value
        return dict(item)

    def collection_delete(self, name: str, item_id: str) -> None:
        self.calls.append("collection_delete")
        item = next((entry for entry in self.items if entry["id"] == item_id), None)
        if item is None:
            raise PluginItemNotFound(name, item_id)
        self.items.remove(item)

    def run_action(self, name: str, parameters: dict[str, object]) -> object:
        self.calls.append("run_action")
        self.action_calls.append((name, dict(parameters)))
        if self.action_error is not None:
            raise self.action_error
        return self.action_result

    def call_count(self, method: str) -> int:
        """How many times the core called ``method`` (0 proves a rejection)."""
        return self.calls.count(method)


class FakeLoader:
    """The two lookups :class:`PluginConfigService` makes on a loader."""

    def __init__(self, record: PluginRecord | None = None, loaded: object | None = None) -> None:
        self._records = {record.name: record} if record is not None else {}
        self._loaded = (
            {record.name: loaded} if (record is not None and loaded is not None) else {}
        )

    def get_record(self, name: str) -> PluginRecord | None:
        return self._records.get(name)

    def get_plugin(self, name: str) -> object | None:
        return self._loaded.get(name)


def catalog_record(
    plugin: object, *, name: str = NAME, error: str | None = None
) -> PluginRecord:
    """Describe ``plugin`` as a catalog record.

    A record with ``error`` has **no** factory, exactly like the real catalog
    (``loader._catalog_error`` drops it): a broken plugin cannot be instantiated,
    so the disposable-instance path must not be reachable for it either.
    """
    return PluginRecord(
        name=name,
        source="installed",
        package="example-checker",
        version="2.0.0",
        entry_point="fake_plugin:ConfigPlugin",
        factory=None if error else (lambda: plugin),
        error=error,
        metadata=None,
    )
