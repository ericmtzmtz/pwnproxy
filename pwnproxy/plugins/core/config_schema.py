"""The configuration contract a plugin publishes, as data.

A plugin declares what it needs (settings), what it keeps as a list (collections)
and what it can do on demand (actions). The declaration is a frozen value object
so the **server** can validate a request and render a response before —and
without— running plugin code: three clients (Web UI, MCP, CLI) read the same
schema and nobody reimplements a rule.

Three responsibilities live here, and nothing else:

* :func:`validate_schema` — the *vocabulary* a schema may use. A plugin that
  steps outside it gets ``409`` (its schema is not published at all).
* :func:`validate_values` — the *shape* of a write. A client that steps outside
  it gets ``422`` and the plugin never sees the request.
* :func:`render_values` — the *only* place that decides what is a secret. It is
  the single function every read path goes through, so a client cannot leak a
  secret it was never given.

Business rules are **not** here: they belong to the plugin, which reports them
with :class:`PluginValidationError` (translated to ``422`` with the plugin's own
message). This module does not know what a plugin means by "webhook" or by
"failing", and it must stay that way.

HTTP mapping of the exceptions in this module:

===========================  =====================================
Exception                    Status
===========================  =====================================
``InvalidPluginSchema``      ``409`` (the plugin is broken)
``SchemaViolation``          ``422`` (the client's write is invalid)
``PluginValidationError``    ``422`` (the plugin rejected the write)
``PluginItemNotFound``       ``404`` (the item is gone)
===========================  =====================================
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

#: Version of the schema shape. Growing it (a new field type, a new attribute)
#: means a new number, never a silent reinterpretation of the old one.
SCHEMA_VERSION = 1

#: Closed vocabulary of a field type. Adding one is a ``schema_version`` bump.
FIELD_TYPES: frozenset[str] = frozenset({"string", "integer", "number", "boolean", "enum", "array"})

#: Scopes a token can have (``api-local-token``): ``full`` writes secrets.
ACTION_SCOPES: frozenset[str] = frozenset({"agent", "full"})

#: Scope an action requires when it does not declare one (fail closed).
DEFAULT_ACTION_SCOPE = "full"

#: Only list items made of strings are supported today.
ARRAY_ITEM_TYPES: frozenset[str] = frozenset({"string"})

#: Fixed body of the ``403`` returned when a token without the ``full`` scope
#: tries to write a secret field. It replaces the generic
#: ``FORBIDDEN_SCOPE_DETAIL`` on this path only, because the client can act on
#: it: the schema is public, so naming the rule leaks nothing, and "save it from
#: the Web UI or the CLI" is the fix the operator needs.
SECRET_WRITE_REQUIRES_FULL_DETAIL = (
    "Secret fields can only be written with a token of scope 'full' (Web UI or CLI)"
)


class InvalidPluginSchema(Exception):
    """The plugin's schema breaks the vocabulary.

    The API translates it to ``409`` with
    ``plugin '<name>' declares an invalid configuration schema: <reason>`` and
    publishes **no** field of the invalid schema.

    Args:
        reason: What is wrong, in terms the plugin author can act on. It never
            carries a field *value* (a schema is public; a default that is not
            is rejected by :func:`validate_schema`).
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class SchemaViolation(Exception):
    """A write does not match the schema. The API translates it to ``422``.

    Args:
        field: Declared key that broke a rule, or ``""`` when the payload itself
            is not an object. The service prefixes it with the collection name
            for collection items (``webhooks.signing_key``).
        message: The rule that was broken. It never interpolates the value: the
            ``422`` body must be safe to paste into a ticket.
    """

    def __init__(self, field: str, message: str) -> None:
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}" if field else message)


class PluginValidationError(Exception):
    """A rule of the **plugin** rejected the operation. The API answers ``422``.

    Plugins raise this instead of inventing an HTTP status: the core publishes
    ``field`` and ``message`` exactly as given, without translating, wrapping or
    adding a traceback.

    Args:
        field: Field the plugin is complaining about (``""`` for the operation
            as a whole, e.g. "webhook names must be unique").
        message: The plugin's own message, shown to the client as-is.
    """

    def __init__(self, field: str, message: str) -> None:
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}" if field else message)


class PluginItemNotFound(Exception):
    """The plugin no longer has the item addressed by the request (``404``).

    ``collection_update`` and ``collection_delete`` may raise it; the service
    translates it to ``404`` with ``plugin '<name>' has no <collection> '<id>'``.

    Args:
        collection: Collection name the plugin was asked about.
        item_id: Identifier that no longer exists (or never did).
    """

    def __init__(self, collection: str, item_id: str) -> None:
        self.collection = collection
        self.item_id = item_id
        super().__init__(f"{collection}/{item_id}")


@dataclass(frozen=True)
class FieldSpec:
    """One declarable value: a setting, a collection item field or a parameter.

    Attributes:
        key: Name the client sends and the plugin reads. Unique inside its object.
        type: One of :data:`FIELD_TYPES`.
        help: Human-readable description, published to the clients as-is.
        required: Must be present when an object is *created* (a ``PATCH`` only
            validates the keys it sends).
        secret: Write-only. Only allowed on ``string``, so ``{"set": …}`` can
            never be confused with a value. See :func:`render_values`.
        read_only: The plugin owns the value (e.g. a ``status`` it recomputes); a
            client that sends it gets ``422``.
        default: Value the plugin reports when it has none. ``None`` means "no
            default declared"; a secret field cannot declare one, because the
            schema is published.
        choices: Allowed values of an ``enum``.
        minimum: Lower bound of an ``integer``/``number`` (inclusive).
        maximum: Upper bound of an ``integer``/``number`` (inclusive).
        max_length: Longest accepted ``string``, in characters.
        max_items: Longest accepted ``array``, in items.
        items: Type of the array's items; only ``"string"`` today.
    """

    key: str
    type: str
    help: str = ""
    required: bool = False
    secret: bool = False
    read_only: bool = False
    default: Any = None
    choices: Sequence[str] = ()
    minimum: int | float | None = None
    maximum: int | float | None = None
    max_length: int | None = None
    max_items: int | None = None
    items: str | None = None

    def __post_init__(self) -> None:
        # Normalise to a tuple so a frozen spec cannot be changed by mutating the
        # list the plugin passed in.
        if not isinstance(self.choices, tuple):
            object.__setattr__(self, "choices", tuple(self.choices or ()))

    def to_dict(self) -> dict[str, Any]:
        """Return the published form of this field.

        The booleans are always present (a client should not have to tell
        "absent" from ``false``); ``help`` and the type-specific attributes only
        when they carry something.
        """
        data: dict[str, Any] = {
            "key": self.key,
            "type": self.type,
            "required": self.required,
            "secret": self.secret,
            "read_only": self.read_only,
        }
        if self.help:
            data["help"] = self.help
        if self.default is not None:
            data["default"] = self.default
        if self.choices:
            data["choices"] = list(self.choices)
        if self.minimum is not None:
            data["minimum"] = self.minimum
        if self.maximum is not None:
            data["maximum"] = self.maximum
        if self.max_length is not None:
            data["max_length"] = self.max_length
        if self.max_items is not None:
            data["max_items"] = self.max_items
        if self.items is not None:
            data["items"] = self.items
        return data


@dataclass(frozen=True)
class CollectionSpec:
    """A list of items the plugin owns, each one shaped by ``item``.

    Attributes:
        name: Collection name, used in the route (``/collections/<name>``).
        item: Fields of one item. Every item has the same shape.
        max_items: Capacity of the collection. The core refuses a create at the
            cap with ``409`` **without** asking the plugin; the plugin's own
            policy (what it considers valid) still answers ``422``.
        help: Human-readable description, published to the clients.
    """

    name: str
    item: Sequence[FieldSpec] = ()
    max_items: int = 0
    help: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.item, tuple):
            object.__setattr__(self, "item", tuple(self.item or ()))

    def to_dict(self) -> dict[str, Any]:
        """Return the published form of this collection."""
        data: dict[str, Any] = {"name": self.name, "max_items": self.max_items}
        if self.help:
            data["help"] = self.help
        data["item"] = [spec.to_dict() for spec in self.item]
        return data


@dataclass(frozen=True)
class ActionSpec:
    """An operation the plugin can run on demand.

    Attributes:
        name: Action name, used in the route (``/actions/<name>``).
        parameters: Fields of the call. A parameter can never be ``secret``: the
            ``TaskStore`` persists the parameters of a long action, so a secret
            there would be a secret at rest outside the plugin's store. An action
            uses a secret the plugin already stores.
        long_running: ``True`` runs it through the ``TaskStore`` (``202`` plus a
            ``task_id``); ``False`` runs it inside the request (``200``).
        requires_scope: Token scope needed to run it; ``full`` when undeclared,
            because sending credentials somewhere is not an agent's call.
        help: Human-readable description, published to the clients.
    """

    name: str
    parameters: Sequence[FieldSpec] = ()
    long_running: bool = False
    requires_scope: str = DEFAULT_ACTION_SCOPE
    help: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.parameters, tuple):
            object.__setattr__(self, "parameters", tuple(self.parameters or ()))
        if not self.requires_scope:
            object.__setattr__(self, "requires_scope", DEFAULT_ACTION_SCOPE)

    def to_dict(self) -> dict[str, Any]:
        """Return the published form of this action."""
        data: dict[str, Any] = {
            "name": self.name,
            "long_running": self.long_running,
            "requires_scope": self.requires_scope,
        }
        if self.help:
            data["help"] = self.help
        data["parameters"] = [spec.to_dict() for spec in self.parameters]
        return data


@dataclass(frozen=True)
class PluginConfigSchema:
    """Everything a plugin declares about its configuration, in one value.

    Attributes:
        plugin: Name the plugin declares. The service publishes the catalog name
            instead, which is the one the routes accept; this field is for a
            plugin that builds its schema outside the catalog (tests, tooling).
        schema_version: Shape version, :data:`SCHEMA_VERSION` today.
        settings: Simple values (one object).
        collections: Lists of items.
        actions: Operations run on demand.
    """

    plugin: str = ""
    schema_version: int = SCHEMA_VERSION
    settings: Sequence[FieldSpec] = ()
    collections: Sequence[CollectionSpec] = ()
    actions: Sequence[ActionSpec] = ()

    def __post_init__(self) -> None:
        for name in ("settings", "collections", "actions"):
            if not isinstance(getattr(self, name), tuple):
                object.__setattr__(self, name, tuple(getattr(self, name) or ()))

    def to_dict(self) -> dict[str, Any]:
        """Return the published JSON of the whole schema.

        Exactly the four documented keys, nothing added or dropped, so a client
        can paint a form from it without knowing any plugin by name.
        """
        return {
            "plugin": self.plugin,
            "schema_version": self.schema_version,
            "settings": [spec.to_dict() for spec in self.settings],
            "collections": [spec.to_dict() for spec in self.collections],
            "actions": [spec.to_dict() for spec in self.actions],
        }

    def collection(self, name: str) -> CollectionSpec | None:
        """Return the collection called ``name``, or ``None`` when undeclared."""
        return next((spec for spec in self.collections if spec.name == name), None)

    def action(self, name: str) -> ActionSpec | None:
        """Return the action called ``name``, or ``None`` when undeclared."""
        return next((spec for spec in self.actions if spec.name == name), None)


def validate_schema(schema: PluginConfigSchema) -> None:
    """Check a declared schema against the vocabulary.

    Args:
        schema: What ``config_schema()`` returned.

    Raises:
        InvalidPluginSchema: The first broken rule, with the reason. The core
            answers ``409`` and publishes none of it, so a half-valid schema can
            never reach a client.
    """
    if not isinstance(schema, PluginConfigSchema):
        raise InvalidPluginSchema("config_schema() must return a PluginConfigSchema")
    if schema.schema_version != SCHEMA_VERSION:
        raise InvalidPluginSchema(
            f"unsupported schema_version {schema.schema_version!r} (expected {SCHEMA_VERSION})"
        )

    _validate_fields(schema.settings, where="settings")

    _validate_unique([spec.name for spec in schema.collections], kind="collection")
    for spec in schema.collections:
        if not isinstance(spec, CollectionSpec):
            raise InvalidPluginSchema("collections must be CollectionSpec instances")
        if not isinstance(spec.name, str) or not spec.name:
            raise InvalidPluginSchema("collection name must be a non-empty string")
        if spec.max_items < 1:
            raise InvalidPluginSchema(f"collection '{spec.name}' must declare max_items >= 1")
        _validate_fields(spec.item, where=f"collection '{spec.name}'")

    _validate_unique([spec.name for spec in schema.actions], kind="action")
    for spec in schema.actions:
        if not isinstance(spec, ActionSpec):
            raise InvalidPluginSchema("actions must be ActionSpec instances")
        if not isinstance(spec.name, str) or not spec.name:
            raise InvalidPluginSchema("action name must be a non-empty string")
        if spec.requires_scope not in ACTION_SCOPES:
            raise InvalidPluginSchema(
                f"action '{spec.name}' declares unknown requires_scope '{spec.requires_scope}'"
            )
        _validate_fields(spec.parameters, where=f"action '{spec.name}'", action=True)


def validate_values(
    fields: Sequence[FieldSpec],
    values: Mapping[str, Any],
    *,
    partial: bool,
) -> None:
    """Check the values of a write against ``fields`` before the plugin sees them.

    Args:
        fields: Declared fields of the object being written (settings or the
            ``item`` of a collection).
        values: Flat mapping sent by the client.
        partial: ``True`` for a ``PATCH`` (only the keys present are validated);
            ``False`` for a create, where every ``required`` field must be there.

    Raises:
        SchemaViolation: The first broken rule. The message names the rule, never
            the value, so the ``422`` body is safe to log or paste.
    """
    if not isinstance(values, Mapping):
        raise SchemaViolation("", "values must be an object")

    declared = {spec.key: spec for spec in fields}
    for key in values:
        if key not in declared:
            raise SchemaViolation(str(key), "unknown field")

    for spec in fields:
        if spec.key not in values:
            if spec.required and not partial:
                raise SchemaViolation(spec.key, "required field is missing")
            continue
        _validate_value(spec, values[spec.key])


def render_values(
    fields: Sequence[FieldSpec],
    reported: Mapping[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Build the ``{"value": …}`` / ``{"set": bool}`` form of a read.

    The single place that decides what is a secret. For a ``secret`` field the
    rendered value is ``{"set": bool}`` taken from ``"<key>__set"`` and **any
    value the plugin returned for that key is discarded** — a plugin that does
    not keep its half of the contract cannot leak through here. Keys the schema
    does not declare are not published at all.

    Args:
        fields: Declared fields of the object being read.
        reported: What the plugin returned (flat), or ``None``.

    Returns:
        The published mapping, in schema order.
    """
    source = reported if isinstance(reported, Mapping) else {}
    rendered: dict[str, dict[str, Any]] = {}
    for spec in fields:
        if spec.secret:
            rendered[spec.key] = {"set": bool(source.get(f"{spec.key}__set"))}
        elif spec.key in source:
            rendered[spec.key] = {"value": source[spec.key]}
    return rendered


def secret_keys(fields: Sequence[FieldSpec], values: Any) -> set[str]:
    """Return the secret keys present in ``values``.

    Called by the transport **before** validating the body: with an ``agent``
    token the request is rejected with ``403`` without looking at the values, so
    no ``422`` can ever describe a secret.

    Args:
        fields: Declared fields of the object being written.
        values: Whatever the client sent; anything that is not a mapping yields
            an empty set (the ``422`` for a malformed body comes later).

    Returns:
        Names of the secret fields that appear in ``values``.
    """
    if not isinstance(values, Mapping):
        return set()
    declared = {spec.key for spec in fields if spec.secret}
    return {str(key) for key in values if key in declared}


def action_scope(action: ActionSpec) -> str:
    """Return the token scope ``action`` requires (``full`` when undeclared).

    Args:
        action: Declared action.

    Returns:
        ``"full"`` or ``"agent"``.
    """
    return action.requires_scope or DEFAULT_ACTION_SCOPE


def _validate_unique(names: Sequence[str], *, kind: str) -> None:
    """Reject a repeated collection/action name."""
    seen: set[str] = set()
    for name in names:
        if name in seen:
            raise InvalidPluginSchema(f"duplicate {kind} name '{name}'")
        seen.add(name)


def _validate_fields(
    fields: Sequence[FieldSpec],
    *,
    where: str,
    action: bool = False,
) -> None:
    """Validate the field list of one object (settings, a collection item, an action)."""
    _validate_unique([spec.key for spec in fields], kind="field")
    for spec in fields:
        if not isinstance(spec, FieldSpec):
            raise InvalidPluginSchema(f"{where} fields must be FieldSpec instances")
        if not isinstance(spec.key, str) or not spec.key:
            raise InvalidPluginSchema(f"{where}: field key must be a non-empty string")
        if spec.type not in FIELD_TYPES:
            raise InvalidPluginSchema(f"field '{spec.key}' has unknown type '{spec.type}'")
        if action and spec.secret:
            raise InvalidPluginSchema(
                f"action parameter '{spec.key}' cannot be secret: "
                "a long action persists its parameters"
            )
        if action and spec.read_only:
            raise InvalidPluginSchema(f"action parameter '{spec.key}' cannot be read-only")
        _validate_attributes(spec)


def _validate_attributes(spec: FieldSpec) -> None:
    """Validate the type-specific attributes of one field."""
    name, kind = spec.key, spec.type

    if spec.secret and kind != "string":
        raise InvalidPluginSchema(
            f"field '{name}' is secret but its type is '{kind}' (only string fields can be secret)"
        )
    if spec.secret and spec.default is not None:
        raise InvalidPluginSchema(
            f"field '{name}' is secret and declares a default: the schema is published"
        )
    if spec.choices and kind != "enum":
        raise InvalidPluginSchema(f"field '{name}' declares choices but is not an enum")
    if kind == "enum" and not spec.choices:
        raise InvalidPluginSchema(f"enum field '{name}' must declare choices")
    if (spec.minimum is not None or spec.maximum is not None) and kind not in ("integer", "number"):
        raise InvalidPluginSchema(f"field '{name}' declares minimum/maximum but is not numeric")
    if spec.max_length is not None:
        if kind != "string":
            raise InvalidPluginSchema(f"field '{name}' declares max_length but is not a string")
        if spec.max_length < 1:
            raise InvalidPluginSchema(f"field '{name}' declares max_length < 1")
    if spec.max_items is not None or spec.items is not None:
        if kind != "array":
            raise InvalidPluginSchema(f"field '{name}' declares max_items/items but is not an array")
        if spec.max_items is not None and spec.max_items < 1:
            raise InvalidPluginSchema(f"field '{name}' declares max_items < 1")
        if spec.items is not None and spec.items not in ARRAY_ITEM_TYPES:
            raise InvalidPluginSchema(
                f"field '{name}' declares unsupported array items '{spec.items}' (only string)"
            )


def _validate_value(spec: FieldSpec, value: Any) -> None:
    """Validate one value against its field spec (raises :class:`SchemaViolation`)."""
    key = spec.key
    if spec.read_only:
        raise SchemaViolation(key, "read-only field")
    if value is None:
        raise SchemaViolation(key, "null is not a value")

    if spec.type == "string":
        if not isinstance(value, str):
            raise SchemaViolation(key, "expected a string")
        if spec.max_length is not None and len(value) > spec.max_length:
            raise SchemaViolation(key, f"string is longer than {spec.max_length} characters")
    elif spec.type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise SchemaViolation(key, "expected an integer")
        _validate_range(spec, value)
    elif spec.type == "number":
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise SchemaViolation(key, "expected a number")
        _validate_range(spec, value)
    elif spec.type == "boolean":
        if not isinstance(value, bool):
            raise SchemaViolation(key, "expected a boolean")
    elif spec.type == "enum":
        if value not in spec.choices:
            raise SchemaViolation(key, "value is not one of the declared choices")
    elif spec.type == "array":
        if not isinstance(value, list | tuple):
            raise SchemaViolation(key, "expected an array")
        if spec.max_items is not None and len(value) > spec.max_items:
            raise SchemaViolation(key, f"array is longer than {spec.max_items} items")
        if spec.items == "string" and any(not isinstance(item, str) for item in value):
            raise SchemaViolation(key, "array items must be strings")


def _validate_range(spec: FieldSpec, value: int | float) -> None:
    """Validate the inclusive bounds of a numeric value."""
    if spec.minimum is not None and value < spec.minimum:
        raise SchemaViolation(spec.key, f"value is below the minimum {spec.minimum}")
    if spec.maximum is not None and value > spec.maximum:
        raise SchemaViolation(spec.key, f"value is above the maximum {spec.maximum}")
