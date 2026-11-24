"""The service that carries a plugin's configuration contract to the API.

The core does **not** store plugin configuration: it validates a request against
the schema the plugin published (``config_schema.py``), calls the plugin's own
method and renders what comes back. The plugin keeps its store and its business
rules; when one of those rules rejects an operation the plugin raises
:class:`~pwnproxy.plugins.core.config_schema.PluginValidationError` and the client
receives **the plugin's** message, untouched.

Two rules shape this module:

* **The plugin does not have to be loaded to be configured.** A plugin that
  cannot load (no license, a bad value that breaks ``on_load()``) would otherwise
  be impossible to fix through any channel except its own CLI. When it is not
  loaded, one *disposable* instance is created with the catalog's factory and
  ``on_load()`` is **never** called on it (this is synchronous and the instance is
  dropped at the end of the call). Consequence for plugin authors: creating an
  instance must have no side effects — no network, no store opened in
  ``__init__``. Actions are the exception: they need a live plugin (``409``).
* **Writing does not reload the plugin.** ``config_write`` and ``collection_*``
  are the single seam: the plugin persists *and* applies the change to its live
  state there. Reloading would replay the events the bus buffered while the
  plugin was off and would restart its consumer tasks.

Error mapping (the whole table lives in :func:`error_response`):

=============================  =========  ==========================================
Raised by                      Status     ``detail``
=============================  =========  ==========================================
``SchemaViolation``            ``422``    ``{"field": …, "message": …}``
``PluginValidationError``      ``422``    ``{"field": …, "message": …}``
``PluginNotFound``             ``404``    ``plugin '<n>' not found``
``CollectionNotDeclared``      ``404``    ``plugin '<n>' declares no collection '<c>'``
``ActionNotDeclared``          ``404``    ``plugin '<n>' declares no action '<a>'``
``ItemNotFound``               ``404``    ``plugin '<n>' has no <c> '<id>'``
``PluginCannotRun``            ``409``    ``plugin '<n>' cannot run: <reason>``
``InvalidConfigSchema``        ``409``    ``plugin '<n>' declares an invalid … schema``
``PluginNotLoaded``            ``409``    ``plugin '<n>' is not loaded``
``CollectionFull``             ``409``    ``collection '<c>' is full (max <n> items)``
``MissingPluginMethod``        ``409``    ``plugin '<n>' declares no <method>``
``PluginLoaderUnavailable``    ``503``    ``plugin_loader not available``
``TaskStoreUnavailable``       ``503``    ``task store not available``
anything else                  ``500``    ``plugin '<n>' failed`` (trace only in the log)
=============================  =========  ==========================================

Plugin methods may be plain or ``async``; both are awaited when needed, so a
plugin does not have to know how the core calls it. Results are expected to be
flat mappings of *field key → value*; a list item also carries ``id``.

Auditing: every **confirmed** write publishes :data:`PLUGIN_CONFIG_CHANGED` and
logs one line, both with the *names* of the keys that changed and the scope of
the token that did it — never a value (a secret is write-only by contract). A
write that fails publishes nothing: the trail exists only for changes that
happened. There is no audit store here on purpose; that would be a different
change and the plugin already keeps its own.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pwnproxy.plugins.core.catalog import PluginRecord
from pwnproxy.plugins.core.config_schema import (
    CollectionSpec,
    InvalidPluginSchema,
    PluginConfigSchema,
    PluginItemNotFound,
    PluginValidationError,
    SchemaViolation,
    render_values,
    secret_keys,
    validate_schema,
    validate_values,
)
from pwnproxy.shared.api_token import SCOPE_FULL
from pwnproxy.shared.bus.topics import PLUGIN_CONFIG_CHANGED

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps the import graph light
    from pwnproxy.plugins.core.base import PwnPlugin
    from pwnproxy.plugins.core.loader import UniversalPluginLoader

logger = logging.getLogger(__name__)

#: Task type a long-running action is stored under (``GET /api/v1/tasks/{id}``).
PLUGIN_ACTION_TASK_TYPE = "plugin_action"


class PluginConfigError(Exception):
    """Base of the errors this service raises on behalf of a plugin.

    Attributes:
        status: HTTP status the transport must answer with.
        detail: Body of the ``detail`` field, ready to serialize.
    """

    status: int = 500

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


class PluginLoaderUnavailable(PluginConfigError):
    """There is no plugin loader in this process (``503``)."""

    status = 503

    def __init__(self) -> None:
        super().__init__("plugin_loader not available")


class TaskStoreUnavailable(PluginConfigError):
    """A long action needs the ``TaskStore`` and there is none (``503``)."""

    status = 503

    def __init__(self) -> None:
        super().__init__("task store not available")


class PluginNotFound(PluginConfigError):
    """The name is not in the catalog (``404``)."""

    status = 404

    def __init__(self, name: str) -> None:
        super().__init__(f"plugin '{name}' not found")


class CollectionNotDeclared(PluginConfigError):
    """The plugin's schema does not declare that collection (``404``)."""

    status = 404

    def __init__(self, name: str, collection: str) -> None:
        super().__init__(f"plugin '{name}' declares no collection '{collection}'")


class ActionNotDeclared(PluginConfigError):
    """The plugin's schema does not declare that action (``404``)."""

    status = 404

    def __init__(self, name: str, action: str) -> None:
        super().__init__(f"plugin '{name}' declares no action '{action}'")


class ItemNotFound(PluginConfigError):
    """The plugin no longer has that item (``404``)."""

    status = 404

    def __init__(self, name: str, collection: str, item_id: str) -> None:
        super().__init__(f"plugin '{name}' has no {collection} '{item_id}'")


class PluginCannotRun(PluginConfigError):
    """The plugin exists but cannot be instantiated right now (``409``)."""

    status = 409

    def __init__(self, name: str, reason: str) -> None:
        super().__init__(f"plugin '{name}' cannot run: {reason}")


class InvalidConfigSchema(PluginConfigError):
    """The plugin declared a schema outside the vocabulary (``409``)."""

    status = 409

    def __init__(self, name: str, reason: str) -> None:
        super().__init__(f"plugin '{name}' declares an invalid configuration schema: {reason}")


class PluginNotLoaded(PluginConfigError):
    """A live plugin is needed (actions) and there is none (``409``)."""

    status = 409

    def __init__(self, name: str) -> None:
        super().__init__(f"plugin '{name}' is not loaded")


class CollectionFull(PluginConfigError):
    """The collection already holds ``max_items`` items (``409``)."""

    status = 409

    def __init__(self, collection: str, max_items: int) -> None:
        super().__init__(f"collection '{collection}' is full (max {max_items} items)")


class MissingPluginMethod(PluginConfigError):
    """The plugin declares a schema but not the method that operation needs (``409``)."""

    status = 409

    def __init__(self, name: str, method: str) -> None:
        super().__init__(f"plugin '{name}' declares no {method}")


def error_response(exc: BaseException, *, plugin: str) -> tuple[int, str | dict[str, str]]:
    """Translate an exception from this layer into ``(status, detail)``.

    The single site where the HTTP table of the contract lives, so a route only
    has to do ``status, detail = error_response(exc, plugin=name)`` and never
    grew its own ``except`` ladder.

    Args:
        exc: Exception raised while reading/writing/running a plugin operation.
        plugin: Plugin name, used by the fixed ``500`` body only.

    Returns:
        The status code and the body of the ``detail`` field.
    """
    if isinstance(exc, SchemaViolation | PluginValidationError):
        return 422, {"field": exc.field, "message": exc.message}
    if isinstance(exc, PluginConfigError):
        return exc.status, exc.detail
    return 500, f"plugin '{plugin}' failed"


class PluginConfigService:
    """Read and write a plugin's configuration through its declared schema.

    Args:
        loader: The plugin loader (catalog + loaded instances). ``None`` means
            "this process has no loader": every operation answers ``503``.
        task_store: Store used to run and publish long actions. Optional; only a
            ``long_running`` action needs it (otherwise ``503``, never a
            synchronous run of something declared long).
        hook_bus: Event bus the audit trail is published on. Optional; a write
            that succeeded stays successful even when the bus is missing.

    The service has no cache: a schema is read from the plugin on every call, so
    a reloaded plugin publishes its new schema immediately.
    """

    def __init__(
        self,
        loader: UniversalPluginLoader | None,
        task_store: Any | None = None,
        hook_bus: Any | None = None,
    ) -> None:
        self._loader = loader
        self._task_store = task_store
        self._hook_bus = hook_bus

    # ------------------------------------------------------------------ schema

    async def schema(self, name: str) -> dict[str, Any]:
        """Return the published schema of ``name``.

        Args:
            name: Plugin name, as it appears in the catalog.

        Returns:
            The schema exactly as declared, with the **catalog** name in
            ``plugin`` (a plugin cannot publish itself under another name). A
            plugin without ``config_schema`` publishes the empty schema, so every
            client has one code path.

        Raises:
            PluginNotFound: ``name`` is not in the catalog (``404``).
            PluginCannotRun: The catalog reports an error or the factory fails (``409``).
            InvalidConfigSchema: The declared schema breaks the vocabulary (``409``).
        """
        declared = await self.declared_schema(name)
        return {**declared.to_dict(), "plugin": name}

    async def declared_schema(self, name: str) -> PluginConfigSchema:
        """Return the validated schema of ``name`` as a value, not as JSON.

        The transport needs the ``FieldSpec``/``ActionSpec`` objects to resolve
        the scope matrix (:func:`secret_keys`, :func:`action_scope`) before any
        value is validated; a client only ever sees :meth:`schema`.

        Args:
            name: Plugin name.

        Returns:
            The schema the plugin declared (empty when it declares none).

        Raises:
            PluginNotFound: ``name`` is not in the catalog (``404``).
            PluginCannotRun: The catalog reports an error or the factory fails (``409``).
            InvalidConfigSchema: The declared schema breaks the vocabulary (``409``).

        Note:
            A write resolves this first and then the write itself, so a plugin
            that is **not** loaded is instantiated twice. That is legal because
            creating an instance has no side effects (design D4).
        """
        return await self._schema_of(self._instance(name), name)

    # ---------------------------------------------------------------- settings

    async def read_settings(self, name: str) -> dict[str, Any]:
        """Return the settings of ``name`` rendered as ``{"value"}/{"set"}``.

        Args:
            name: Plugin name.

        Returns:
            ``{"plugin", "schema_version", "values"}``. A plugin with an empty
            schema answers ``values: {}`` — it declares no settings, so there is
            nothing to read (and no ``config_read`` is required of it).

        Raises:
            PluginNotFound, PluginCannotRun, InvalidConfigSchema: As in :meth:`schema`.
            MissingPluginMethod: Settings are declared but ``config_read`` is not (``409``).
        """
        plugin = self._instance(name)
        declared = await self._schema_of(plugin, name)
        return await self._settings_payload(plugin, declared, name)

    async def write_settings(
        self, name: str, values: Mapping[str, Any], *, scope: str = SCOPE_FULL
    ) -> dict[str, Any]:
        """Write the keys present in ``values`` and return the settings again.

        The write is **partial**: a key that is not sent is not touched, and
        ``null`` is not "delete" (v1 has no delete; a secret is overwritten).

        Args:
            name: Plugin name.
            values: Flat mapping of settings. Validated against the schema before
                the plugin sees it.
            scope: Scope of the token that asked for the write (``full`` or
                ``agent``). Only reported in the audit event: the transport has
                already refused a secret write from an ``agent`` token.

        Returns:
            The same shape as :meth:`read_settings`, read back from the plugin so
            the client sees the plugin's normalized value and the ``{"set": …}``
            of its secrets.

        Raises:
            SchemaViolation: The write breaks the schema (``422``); the plugin is
                never called.
            MissingPluginMethod: ``config_write`` is missing (``409``).
            PluginValidationError: The plugin rejected the write (``422``);
                re-raised untouched so the client reads its own message.
            PluginNotFound, PluginCannotRun, InvalidConfigSchema: As in :meth:`schema`.
        """
        plugin = self._instance(name)
        declared = await self._schema_of(plugin, name)
        validate_values(declared.settings, values, partial=True)
        writer = self._method(plugin, name, "config_write")
        await _resolve(writer(dict(values)))
        self._audit(name, "settings", "settings", None, values.keys(), scope)
        return await self._settings_payload(plugin, declared, name, written=values)

    # ------------------------------------------------------------- collections

    async def list_items(self, name: str, collection: str) -> dict[str, Any]:
        """Return one collection of ``name``.

        Args:
            name: Plugin name.
            collection: Collection name, as declared by the schema.

        Returns:
            ``{"plugin", "collection", "schema_version", "max_items", "items"}``
            where each item is ``{"id": …, "values": {...}}``.

        Raises:
            CollectionNotDeclared: The schema does not declare it (``404``).
            MissingPluginMethod: ``collection_list`` is missing (``409``).
            PluginNotFound, PluginCannotRun, InvalidConfigSchema: As in :meth:`schema`.
        """
        plugin = self._instance(name)
        declared = await self._schema_of(plugin, name)
        spec = self._collection_spec(declared, name, collection)
        reported = await self._reported_items(plugin, name, collection)
        return self._collection_payload(declared, name, spec, reported)

    async def create_item(
        self,
        name: str,
        collection: str,
        values: Mapping[str, Any],
        *,
        scope: str = SCOPE_FULL,
    ) -> dict[str, Any]:
        """Create one item in ``collection``.

        The capacity of the collection is checked **before** calling the plugin,
        so a full collection answers ``409`` without the plugin doing anything.
        The plugin's own policy still answers ``422`` with its message: capacity
        ("does it fit?") and policy ("is it valid?") are different questions.

        Args:
            name: Plugin name.
            collection: Collection name.
            values: Flat mapping with every ``required`` field.
            scope: Scope of the token that asked for the write; audited only.

        Returns:
            ``{"id": …, "values": {...}}`` of the created item.

        Raises:
            CollectionFull: The collection is at ``max_items`` (``409``).
            SchemaViolation: The values break the schema (``422``); the plugin is
                never called.
            PluginValidationError: The plugin rejected the item (``422``).
            CollectionNotDeclared, MissingPluginMethod, PluginNotFound,
            PluginCannotRun, InvalidConfigSchema: As above.
        """
        plugin = self._instance(name)
        declared = await self._schema_of(plugin, name)
        spec = self._collection_spec(declared, name, collection)
        self._validate_item_values(spec, collection, values, partial=False)
        creator = self._method(plugin, name, "collection_create")
        existing = await self._reported_items(plugin, name, collection)
        if len(existing) >= spec.max_items:
            raise CollectionFull(collection, spec.max_items)
        created = await _resolve(creator(collection, dict(values)))
        rendered = self._render_item(spec, created, name)
        self._audit(name, "collection", collection, rendered["id"], values.keys(), scope)
        return rendered

    async def update_item(
        self,
        name: str,
        collection: str,
        item_id: str,
        values: Mapping[str, Any],
        *,
        scope: str = SCOPE_FULL,
    ) -> dict[str, Any]:
        """Change the keys present in ``values`` of one item.

        Args:
            name: Plugin name.
            collection: Collection name.
            item_id: Identifier the plugin gave the item.
            values: Flat mapping; only the keys sent are validated and written.
            scope: Scope of the token that asked for the write; audited only.

        Returns:
            ``{"id": …, "values": {...}}`` of the updated item.

        Raises:
            SchemaViolation: The values break the schema (``422``).
            ItemNotFound: The plugin does not have that item (``404``).
            PluginValidationError: The plugin rejected the change (``422``).
            CollectionNotDeclared, MissingPluginMethod, PluginNotFound,
            PluginCannotRun, InvalidConfigSchema: As above.
        """
        plugin = self._instance(name)
        declared = await self._schema_of(plugin, name)
        spec = self._collection_spec(declared, name, collection)
        self._validate_item_values(spec, collection, values, partial=True)
        updater = self._method(plugin, name, "collection_update")
        try:
            updated = await _resolve(updater(collection, item_id, dict(values)))
        except PluginItemNotFound as exc:
            raise ItemNotFound(name, exc.collection, exc.item_id) from None
        rendered = self._render_item(spec, updated, name, fallback_id=item_id)
        self._audit(name, "collection", collection, rendered["id"], values.keys(), scope)
        return rendered

    async def delete_item(
        self, name: str, collection: str, item_id: str, *, scope: str = SCOPE_FULL
    ) -> None:
        """Delete one item. Nothing is validated: the id is the whole request.

        Args:
            name: Plugin name.
            collection: Collection name.
            item_id: Identifier to delete.
            scope: Scope of the token that asked for the delete; audited only.

        Raises:
            ItemNotFound: The plugin does not have that item (``404``).
            CollectionNotDeclared, MissingPluginMethod, PluginNotFound,
            PluginCannotRun, InvalidConfigSchema: As above.
        """
        plugin = self._instance(name)
        declared = await self._schema_of(plugin, name)
        self._collection_spec(declared, name, collection)
        deleter = self._method(plugin, name, "collection_delete")
        try:
            await _resolve(deleter(collection, item_id))
        except PluginItemNotFound as exc:
            raise ItemNotFound(name, exc.collection, exc.item_id) from None
        self._audit(name, "collection", collection, item_id, (), scope)

    # ----------------------------------------------------------------- actions

    async def run_action(
        self,
        name: str,
        action: str,
        parameters: Mapping[str, Any],
        *,
        scope: str = SCOPE_FULL,
    ) -> dict[str, Any]:
        """Run one declared action of a **loaded** plugin.

        Args:
            name: Plugin name.
            action: Action name, as declared by the schema.
            parameters: Flat mapping validated against the action's parameters.
                Never carries a secret: a parameter cannot be declared one.
            scope: Scope of the token that ran it; audited only. The transport
                refuses a ``full`` action from an ``agent`` token before this.

        Returns:
            ``{"status": "completed", "result": …}`` for a short action, or
            ``{"status": "running", "task_id": …}`` for a long one (the result
            then lands in ``GET /api/v1/tasks/{task_id}``).

        Raises:
            PluginNotLoaded: The plugin is not loaded (``409``); an action means
                "do it now", which a plugin that is off cannot promise.
            ActionNotDeclared: The schema does not declare it (``404``).
            SchemaViolation: The parameters break the schema (``422``).
            TaskStoreUnavailable: A long action without a ``TaskStore`` (``503``).
            PluginValidationError: The plugin rejected the call (``422``).
            PluginNotFound, PluginCannotRun, InvalidConfigSchema: As in :meth:`schema`.
        """
        loader = self._require_loader()
        plugin = loader.get_plugin(name)
        if plugin is None:
            record = self._record(name)
            if record.error:
                raise PluginCannotRun(name, record.error)
            raise PluginNotLoaded(name)
        declared = await self._schema_of(plugin, name)
        spec = declared.action(action)
        if spec is None:
            raise ActionNotDeclared(name, action)
        validate_values(spec.parameters, parameters, partial=False)
        runner = self._method(plugin, name, "run_action")

        if not spec.long_running:
            result = await _resolve(runner(action, dict(parameters)))
            self._audit(name, "action", action, None, (), scope)
            return {"plugin": name, "action": action, "status": "completed", "result": result}

        store = self._task_store
        if store is None:
            raise TaskStoreUnavailable()
        task_id = await store.create(
            PLUGIN_ACTION_TASK_TYPE,
            {"plugin": name, "action": action, "parameters": dict(parameters)},
        )
        store.track(
            task_id,
            self._run_long_action(name, action, runner, dict(parameters), task_id, store),
        )
        self._audit(name, "action", action, None, (), scope)
        return {"plugin": name, "action": action, "status": "running", "task_id": task_id}

    # ---------------------------------------------------------------- internals

    def _audit(
        self,
        name: str,
        kind: str,
        target: str,
        item_id: str | None,
        changed: Sequence[str],
        scope: str,
    ) -> None:
        """Announce a **confirmed** change: bus event plus one log line.

        Called after the plugin's own write returned and never before, so a
        ``403``/``422``/``409`` leaves no trail of a change that did not happen.
        The payload carries the *names* of the keys, the target and the scope —
        never a value, because a secret is write-only by contract.

        A missing bus is not an error for the caller: the write already happened,
        so the operation still succeeds and this method only records that the
        event could not be published.

        Args:
            name: Plugin name.
            kind: ``settings``, ``collection`` or ``action``.
            target: ``settings``, the collection name or the action name.
            item_id: Item the change touched, when it touched one.
            changed: Names of the keys written (empty for a delete or an action).
            scope: Scope of the token that made the change (``full``/``agent``).
        """
        names = sorted(str(key) for key in changed)
        payload = {
            "plugin": name,
            "kind": kind,
            "target": target,
            "item_id": item_id,
            "changed": names,
            "scope": scope,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        logger.info(
            "plugin config changed: plugin=%s kind=%s target=%s item_id=%s changed=%s scope=%s",
            name,
            kind,
            target,
            item_id,
            ",".join(names),
            scope,
        )
        if self._hook_bus is None:
            logger.warning(
                "no hook bus: %s not published for plugin '%s'", PLUGIN_CONFIG_CHANGED, name
            )
            return
        try:
            self._hook_bus.publish(PLUGIN_CONFIG_CHANGED, payload)
        except Exception:  # boundary: the write already happened, never undo it
            logger.warning(
                "could not publish %s for plugin '%s'", PLUGIN_CONFIG_CHANGED, name, exc_info=True
            )

    def _require_loader(self) -> UniversalPluginLoader:
        """Return the loader or raise the ``503`` of the contract."""
        if self._loader is None:
            raise PluginLoaderUnavailable()
        return self._loader

    def _record(self, name: str) -> PluginRecord:
        """Return the catalog record of ``name`` or raise :class:`PluginNotFound`."""
        record = self._require_loader().get_record(name)
        if record is None:
            raise PluginNotFound(name)
        return record

    def _instance(self, name: str) -> PwnPlugin:
        """Return a plugin instance to ask about its configuration.

        The loaded instance always wins. When the plugin is not loaded (disabled,
        or unable to load) a **disposable** one is built with the catalog's
        factory: ``on_load()`` is never called, the instance is not registered in
        the loader and it is dropped when the call ends.

        Raises:
            PluginNotFound: ``name`` is not in the catalog (``404``).
            PluginCannotRun: The catalog reports an error or the factory raises (``409``).
        """
        loader = self._require_loader()
        loaded = loader.get_plugin(name)
        if loaded is not None:
            return loaded
        record = self._record(name)
        if record.error:
            raise PluginCannotRun(name, record.error)
        if record.factory is None:
            raise PluginCannotRun(name, "the catalog has no factory for it")
        try:
            return record.factory()
        except Exception as exc:
            raise PluginCannotRun(
                name, f"instantiation failed ({type(exc).__name__}: {exc})"
            ) from None

    async def _schema_of(self, plugin: PwnPlugin, name: str) -> PluginConfigSchema:
        """Return the validated schema of ``plugin`` (empty when it declares none)."""
        declared = getattr(plugin, "config_schema", None)
        if declared is None:
            return PluginConfigSchema()
        schema = await _resolve(declared())
        if not isinstance(schema, PluginConfigSchema):
            raise InvalidConfigSchema(name, "config_schema() must return a PluginConfigSchema")
        try:
            validate_schema(schema)
        except InvalidPluginSchema as exc:
            raise InvalidConfigSchema(name, str(exc)) from None
        return schema

    def _method(self, plugin: PwnPlugin, name: str, method: str) -> Callable[..., Any]:
        """Return a plugin method, or raise the ``409`` that names the missing one."""
        handler = getattr(plugin, method, None)
        if handler is None or not callable(handler):
            raise MissingPluginMethod(name, method)
        return handler

    async def _settings_payload(
        self,
        plugin: PwnPlugin,
        schema: PluginConfigSchema,
        name: str,
        written: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Read the settings and render them, or render what was just written.

        Args:
            plugin: Instance to read from.
            schema: Already validated schema.
            name: Plugin name, published in the payload.
            written: Values a confirmed write just sent. Used only when the plugin
                has no ``config_read``: the response then mirrors the write, with
                the secret keys it wrote marked as configured.
        """
        reader = getattr(plugin, "config_read", None)
        if reader is None:
            if written is None:
                if schema.settings:
                    raise MissingPluginMethod(name, "config_read")
                reported: Mapping[str, Any] = {}
            else:
                reported = {**written}
                for key in secret_keys(schema.settings, written):
                    reported[f"{key}__set"] = True
        else:
            reported = await _resolve(reader()) or {}
        return {
            "plugin": name,
            "schema_version": schema.schema_version,
            "values": render_values(schema.settings, reported),
        }

    def _collection_spec(
        self, schema: PluginConfigSchema, name: str, collection: str
    ) -> CollectionSpec:
        """Return the declared collection or raise the ``404`` of the contract."""
        spec = schema.collection(collection)
        if spec is None:
            raise CollectionNotDeclared(name, collection)
        return spec

    def _validate_item_values(
        self,
        spec: CollectionSpec,
        collection: str,
        values: Mapping[str, Any],
        *,
        partial: bool,
    ) -> None:
        """Validate an item and qualify the field with its collection.

        The contract publishes the field as ``<collection>.<field>`` (e.g.
        ``webhooks.signing_key``) so a client with several collections on screen
        knows which form to point at.

        Raises:
            SchemaViolation: The values break the item schema (``422``).
        """
        try:
            validate_values(spec.item, values, partial=partial)
        except SchemaViolation as exc:
            field = f"{collection}.{exc.field}" if exc.field else collection
            raise SchemaViolation(field, exc.message) from None

    async def _reported_items(
        self, plugin: PwnPlugin, name: str, collection: str
    ) -> list[Any]:
        """Return the plugin's raw items of ``collection``."""
        lister = self._method(plugin, name, "collection_list")
        reported = await _resolve(lister(collection))
        return list(reported or [])

    def _collection_payload(
        self,
        schema: PluginConfigSchema,
        name: str,
        spec: CollectionSpec,
        reported: list[Any],
    ) -> dict[str, Any]:
        """Render a whole collection (``max_items`` included, so a client can show ``n/max``)."""
        return {
            "plugin": name,
            "collection": spec.name,
            "schema_version": schema.schema_version,
            "max_items": spec.max_items,
            "items": [self._render_item(spec, item, name) for item in reported],
        }

    def _render_item(
        self,
        spec: CollectionSpec,
        item: Any,
        name: str,
        *,
        fallback_id: str | None = None,
    ) -> dict[str, Any]:
        """Render one item as ``{"id": …, "values": …}``.

        Raises:
            RuntimeError: The plugin returned an item without an ``id`` and the
                caller had none to fall back to. It reaches the client as the
                fixed ``500`` body; the reason stays in the log.
        """
        reported = item if isinstance(item, Mapping) else {}
        item_id = reported.get("id") or fallback_id
        if not item_id:
            raise RuntimeError(f"plugin '{name}' returned a {spec.name} item with no id")
        return {"id": str(item_id), "values": render_values(spec.item, reported)}

    async def _run_long_action(
        self,
        name: str,
        action: str,
        runner: Callable[..., Any],
        parameters: dict[str, Any],
        task_id: str,
        store: Any,
    ) -> None:
        """Run a long action in its task and publish the outcome there.

        Any exception is a boundary (this runs inside a bare asyncio task): it is
        logged with its trace and the task is marked failed with a **fixed**
        error, so ``tasks.db`` never stores a traceback.
        """
        await store.update(task_id, status="running")
        try:
            result = await _resolve(runner(action, parameters))
        except Exception:  # boundary: nothing can propagate out of a tracked task
            logger.exception(
                "plugin action failed: plugin=%s action=%s task=%s", name, action, task_id
            )
            await store.update(
                task_id, status="failed", error=f"plugin '{name}' action '{action}' failed"
            )
            return
        payload = result if isinstance(result, dict) else {"result": result}
        await store.update(task_id, status="completed", result=payload)


async def _resolve(value: Any) -> Any:
    """Await ``value`` when the plugin returned an awaitable, else return it.

    Lets a plugin implement its configuration methods either way without the core
    having to guess (and without a coroutine silently reaching ``render_values``).
    """
    if inspect.isawaitable(value):
        return await value
    return value


__all__ = [
    "PLUGIN_ACTION_TASK_TYPE",
    "ActionNotDeclared",
    "CollectionFull",
    "CollectionNotDeclared",
    "InvalidConfigSchema",
    "ItemNotFound",
    "MissingPluginMethod",
    "PluginCannotRun",
    "PluginConfigError",
    "PluginConfigService",
    "PluginLoaderUnavailable",
    "PluginNotFound",
    "PluginNotLoaded",
    "TaskStoreUnavailable",
    "error_response",
]
