"""Contract tests for ``pwnproxy.plugins.core.config_schema``.

Three things are proven here, one file per responsibility:

* the vocabulary a schema may use (:func:`validate_schema`);
* the shape of a write (:func:`validate_values`) — including the negative case of
  every rule, because a validator that accepts one bad value protects nothing;
* the rendering (:func:`render_values`) — the single function that decides what is
  a secret, so the canary of the test must not survive it even when the plugin
  "reports" it as a normal value.

The scope helpers (:func:`secret_keys` / :func:`action_scope`) are covered too:
they run *before* validation, and that ordering is what keeps an ``agent`` token
from being told anything about a secret it cannot write.
"""

from __future__ import annotations

import pytest

from pwnproxy.plugins.core.config_schema import (
    ACTION_SCOPES,
    DEFAULT_ACTION_SCOPE,
    FIELD_TYPES,
    SCHEMA_VERSION,
    SECRET_WRITE_REQUIRES_FULL_DETAIL,
    ActionSpec,
    CollectionSpec,
    FieldSpec,
    InvalidPluginSchema,
    PluginConfigSchema,
    SchemaViolation,
    action_scope,
    render_values,
    secret_keys,
    validate_schema,
    validate_values,
)

#: Canary used everywhere a value could escape: it must never appear in output.
CANARY = "CANARIO-3f7c1b"


def _settings() -> list[FieldSpec]:
    return [
        FieldSpec(key="environment", type="enum", choices=["lab", "staging"], default="lab", help="Dónde corre."),
        FieldSpec(key="retries", type="integer", minimum=0, maximum=5),
    ]


def _schema(**overrides) -> PluginConfigSchema:
    """Return a valid schema, with ``overrides`` replacing its parts."""
    parts = {
        "plugin": "example-checker",
        "schema_version": SCHEMA_VERSION,
        "settings": _settings(),
        "collections": [
            CollectionSpec(
                name="webhooks",
                help="Webhooks de prueba.",
                max_items=5,
                item=[
                    FieldSpec(key="name", type="string", required=True, max_length=64),
                    FieldSpec(key="events", type="array", items="string", max_items=32),
                    FieldSpec(key="status", type="enum", choices=["active", "failing"], read_only=True),
                    FieldSpec(key="signing_key", type="string", max_length=4096, secret=True),
                ],
            )
        ],
        "actions": [
            ActionSpec(
                name="send_test",
                long_running=True,
                help="Manda un webhook de prueba a una URL.",
                parameters=[
                    FieldSpec(key="name", type="string", required=True),
                    FieldSpec(key="payload", type="string", required=True, max_length=8192),
                ],
            )
        ],
    }
    parts.update(overrides)
    return PluginConfigSchema(**parts)


class TestConstants:
    def test_the_vocabulary_is_the_documented_one(self):
        assert (SCHEMA_VERSION, sorted(FIELD_TYPES), sorted(ACTION_SCOPES), DEFAULT_ACTION_SCOPE) == (
            1,
            ["array", "boolean", "enum", "integer", "number", "string"],
            ["agent", "full"],
            "full",
        )

    def test_the_secret_write_message_is_its_own_text(self):
        """D8 decision: this 403 is not the generic scope message."""
        from pwnproxy.transport.rest.auth import FORBIDDEN_SCOPE_DETAIL

        assert SECRET_WRITE_REQUIRES_FULL_DETAIL == (
            "Secret fields can only be written with a token of scope 'full' (Web UI or CLI)"
        )
        assert SECRET_WRITE_REQUIRES_FULL_DETAIL != FORBIDDEN_SCOPE_DETAIL

    def test_a_plugin_can_import_the_contract_from_base(self):
        """A.1.2: plugins import from ``pwnproxy.plugins.core.base``, not internals."""
        from pwnproxy.plugins.core import base, config_schema

        assert [
            getattr(base, name) is getattr(config_schema, name)
            for name in (
                "SCHEMA_VERSION",
                "ActionSpec",
                "CollectionSpec",
                "FieldSpec",
                "InvalidPluginSchema",
                "PluginConfigSchema",
                "PluginItemNotFound",
                "PluginValidationError",
                "SchemaViolation",
            )
        ] == [True] * 9


class TestSchemaVocabulary:
    # @escenario plugin-config/esquema-versionado/el-esquema-declarado-se-publica-completo
    def test_a_valid_schema_is_accepted_and_published_field_by_field(self):
        schema = _schema()

        validate_schema(schema)

        assert schema.to_dict() == {
            "plugin": "example-checker",
            "schema_version": 1,
            "settings": [
                {
                    "key": "environment",
                    "type": "enum",
                    "required": False,
                    "secret": False,
                    "read_only": False,
                    "help": "Dónde corre.",
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
            ],
            "collections": [
                {
                    "name": "webhooks",
                    "max_items": 5,
                    "help": "Webhooks de prueba.",
                    "item": [
                        {
                            "key": "name",
                            "type": "string",
                            "required": True,
                            "secret": False,
                            "read_only": False,
                            "max_length": 64,
                        },
                        {
                            "key": "events",
                            "type": "array",
                            "required": False,
                            "secret": False,
                            "read_only": False,
                            "max_items": 32,
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
                            "max_length": 4096,
                        },
                    ],
                }
            ],
            "actions": [
                {
                    "name": "send_test",
                    "long_running": True,
                    "requires_scope": "full",
                    "help": "Manda un webhook de prueba a una URL.",
                    "parameters": [
                        {
                            "key": "name",
                            "type": "string",
                            "required": True,
                            "secret": False,
                            "read_only": False,
                        },
                        {
                            "key": "payload",
                            "type": "string",
                            "required": True,
                            "secret": False,
                            "read_only": False,
                            "max_length": 8192,
                        },
                    ],
                }
            ],
        }

    # @escenario plugin-config/esquema-versionado/un-plugin-sin-esquema-responde-un-esquema-vacio
    def test_the_default_schema_is_the_empty_one(self):
        assert PluginConfigSchema().to_dict() == {
            "plugin": "",
            "schema_version": 1,
            "settings": [],
            "collections": [],
            "actions": [],
        }
        validate_schema(PluginConfigSchema())

    def test_an_action_without_requires_scope_defaults_to_full(self):
        schema = _schema(actions=[ActionSpec(name="ping")])

        validate_schema(schema)

        assert schema.to_dict()["actions"][0]["requires_scope"] == "full"
        assert action_scope(schema.actions[0]) == "full"

    def test_the_schema_is_an_immutable_tuple_even_if_a_list_was_passed(self):
        fields = [FieldSpec(key="a", type="string")]
        schema = PluginConfigSchema(settings=fields)
        fields.append(FieldSpec(key="b", type="string"))

        assert [spec.key for spec in schema.settings] == ["a"]

    # @escenario plugin-config/esquema-versionado/un-esquema-invalido-no-se-publica
    @pytest.mark.parametrize(
        ("overrides", "reason"),
        [
            ({"schema_version": 2}, "unsupported schema_version 2 (expected 1)"),
            (
                {"settings": [FieldSpec(key="retries", type="integer", secret=True)]},
                "field 'retries' is secret but its type is 'integer' (only string fields can be secret)",
            ),
            (
                {"settings": [FieldSpec(key="environment", type="string", choices=["lab"])]},
                "field 'environment' declares choices but is not an enum",
            ),
            (
                {"settings": [FieldSpec(key="environment", type="enum")]},
                "enum field 'environment' must declare choices",
            ),
            (
                {"settings": [FieldSpec(key="retries", type="integer", max_length=4)]},
                "field 'retries' declares max_length but is not a string",
            ),
            (
                {"settings": [FieldSpec(key="retries", type="integer", items="string")]},
                "field 'retries' declares max_items/items but is not an array",
            ),
            (
                {"settings": [FieldSpec(key="events", type="array", items="integer")]},
                "field 'events' declares unsupported array items 'integer' (only string)",
            ),
            (
                {"settings": [FieldSpec(key="name", type="string", minimum=1)]},
                "field 'name' declares minimum/maximum but is not numeric",
            ),
            (
                {"settings": [FieldSpec(key="name", type="float")]},
                "field 'name' has unknown type 'float'",
            ),
            (
                {"settings": [FieldSpec(key="name", type="string"), FieldSpec(key="name", type="string")]},
                "duplicate field name 'name'",
            ),
            (
                {"settings": [FieldSpec(key="auth_header", type="string", secret=True, default="x")]},
                "field 'auth_header' is secret and declares a default: the schema is published",
            ),
            (
                {"collections": [CollectionSpec(name="ids", max_items=0)]},
                "collection 'ids' must declare max_items >= 1",
            ),
            (
                {
                    "collections": [
                        CollectionSpec(name="ids", max_items=1),
                        CollectionSpec(name="ids", max_items=1),
                    ]
                },
                "duplicate collection name 'ids'",
            ),
            (
                {"actions": [ActionSpec(name="run"), ActionSpec(name="run")]},
                "duplicate action name 'run'",
            ),
            (
                {"actions": [ActionSpec(name="run", requires_scope="root")]},
                "action 'run' declares unknown requires_scope 'root'",
            ),
        ],
    )
    def test_an_invalid_schema_is_rejected_with_its_reason(self, overrides, reason):
        with pytest.raises(InvalidPluginSchema) as excinfo:
            validate_schema(_schema(**overrides))

        assert str(excinfo.value) == reason

    def test_a_secret_action_parameter_is_rejected(self):
        """D7: a long action persists its parameters, so a secret cannot travel there."""
        schema = _schema(
            actions=[
                ActionSpec(
                    name="send_test",
                    parameters=[FieldSpec(key="signing_key", type="string", secret=True)],
                )
            ]
        )

        with pytest.raises(InvalidPluginSchema) as excinfo:
            validate_schema(schema)

        assert str(excinfo.value) == (
            "action parameter 'signing_key' cannot be secret: a long action persists its parameters"
        )

    def test_a_read_only_action_parameter_is_rejected(self):
        schema = _schema(
            actions=[
                ActionSpec(name="send_test", parameters=[FieldSpec(key="status", type="string", read_only=True)])
            ]
        )

        with pytest.raises(InvalidPluginSchema) as excinfo:
            validate_schema(schema)

        assert str(excinfo.value) == "action parameter 'status' cannot be read-only"

    def test_something_that_is_not_a_schema_is_rejected(self):
        with pytest.raises(InvalidPluginSchema) as excinfo:
            validate_schema({"schema_version": 1})

        assert str(excinfo.value) == "config_schema() must return a PluginConfigSchema"

    def test_an_empty_field_key_is_rejected(self):
        with pytest.raises(InvalidPluginSchema) as excinfo:
            validate_schema(_schema(settings=[FieldSpec(key="", type="string")]))

        assert str(excinfo.value) == "settings: field key must be a non-empty string"


class TestValidateValues:
    # @escenario plugin-config/validacion-antes-del-plugin/clave-desconocida
    def test_an_undeclared_key_is_rejected(self):
        with pytest.raises(SchemaViolation) as excinfo:
            validate_values(_settings(), {"no_existe": 1}, partial=True)

        assert (excinfo.value.field, excinfo.value.message) == ("no_existe", "unknown field")

    def test_a_valid_write_passes(self):
        validate_values(_settings(), {"environment": "lab", "retries": 2}, partial=True)
        validate_values(_settings(), {}, partial=True)

    # @escenario plugin-config/validacion-antes-del-plugin/tipo-enum-rango-y-longitud
    @pytest.mark.parametrize(
        ("spec", "value", "message"),
        [
            (FieldSpec(key="f", type="integer"), "texto", "expected an integer"),
            (FieldSpec(key="f", type="integer"), True, "expected an integer"),
            (FieldSpec(key="f", type="number"), "texto", "expected a number"),
            (FieldSpec(key="f", type="string"), 7, "expected a string"),
            (FieldSpec(key="f", type="boolean"), "yes", "expected a boolean"),
            (FieldSpec(key="f", type="enum", choices=["a", "b"]), "c", "value is not one of the declared choices"),
            (FieldSpec(key="f", type="integer", minimum=2), 1, "value is below the minimum 2"),
            (FieldSpec(key="f", type="number", maximum=1.5), 2, "value is above the maximum 1.5"),
            (FieldSpec(key="f", type="string", max_length=3), "abcd", "string is longer than 3 characters"),
            (FieldSpec(key="f", type="array", max_items=1), ["a", "b"], "array is longer than 1 items"),
            (FieldSpec(key="f", type="array", items="string"), ["a", 1], "array items must be strings"),
            (FieldSpec(key="f", type="array"), {"a": 1}, "expected an array"),
            (FieldSpec(key="f", type="string", read_only=True), "x", "read-only field"),
            (FieldSpec(key="f", type="string"), None, "null is not a value"),
        ],
    )
    def test_each_rule_rejects_its_value_without_echoing_it(self, spec, value, message):
        with pytest.raises(SchemaViolation) as excinfo:
            validate_values([spec], {"f": value}, partial=True)

        assert (excinfo.value.field, excinfo.value.message) == ("f", message)

    # @escenario plugin-config/secretos-de-solo-escritura/el-error-de-validacion-no-repite-el-valor
    def test_a_too_long_secret_is_rejected_without_the_value(self):
        fields = [FieldSpec(key="signing_key", type="string", max_length=8, secret=True)]

        with pytest.raises(SchemaViolation) as excinfo:
            validate_values(fields, {"signing_key": CANARY}, partial=True)

        assert (excinfo.value.field, excinfo.value.message) == (
            "signing_key",
            "string is longer than 8 characters",
        )
        assert CANARY not in str(excinfo.value)

    # @escenario plugin-config/validacion-antes-del-plugin/escritura-parcial
    def test_a_partial_write_only_validates_the_keys_it_sends(self):
        fields = [FieldSpec(key="name", type="string", required=True), FieldSpec(key="note", type="string")]

        validate_values(fields, {"note": "solo esto"}, partial=True)

    def test_a_create_requires_every_required_field(self):
        fields = [FieldSpec(key="name", type="string", required=True)]

        with pytest.raises(SchemaViolation) as excinfo:
            validate_values(fields, {}, partial=False)

        assert (excinfo.value.field, excinfo.value.message) == ("name", "required field is missing")

    def test_a_non_object_payload_is_rejected(self):
        with pytest.raises(SchemaViolation) as excinfo:
            validate_values(_settings(), ["environment"], partial=True)

        assert (excinfo.value.field, excinfo.value.message) == ("", "values must be an object")


class TestRenderValues:
    # @escenario plugin-config/secretos-de-solo-escritura/la-lectura-no-trae-el-valor
    def test_a_secret_is_published_as_set_and_a_normal_value_as_value(self):
        fields = [
            FieldSpec(key="environment", type="string"),
            FieldSpec(key="signing_key", type="string", secret=True),
            FieldSpec(key="auth_header", type="string", secret=True),
        ]

        rendered = render_values(
            fields,
            {"environment": "lab", "signing_key__set": True, "auth_header__set": False},
        )

        assert rendered == {
            "environment": {"value": "lab"},
            "signing_key": {"set": True},
            "auth_header": {"set": False},
        }

    # @escenario plugin-config/secretos-de-solo-escritura/un-plugin-que-devuelve-el-secreto-no-lo-publica
    def test_a_plugin_that_reports_the_secret_does_not_publish_it(self):
        fields = [FieldSpec(key="signing_key", type="string", secret=True)]

        rendered = render_values(fields, {"signing_key": CANARY, "signing_key__set": True})

        assert rendered == {"signing_key": {"set": True}}
        assert CANARY not in str(rendered)

    # @escenario plugin-config/secretos-de-solo-escritura/un-plugin-que-devuelve-el-secreto-no-lo-publica
    def test_a_secret_with_no_marker_is_not_configured_even_when_a_value_came(self):
        fields = [FieldSpec(key="signing_key", type="string", secret=True)]

        assert render_values(fields, {"signing_key": CANARY}) == {"signing_key": {"set": False}}

    def test_keys_the_schema_does_not_declare_are_dropped(self):
        fields = [FieldSpec(key="environment", type="string")]

        assert render_values(fields, {"environment": "lab", "no_existe": CANARY}) == {
            "environment": {"value": "lab"}
        }

    def test_a_declared_key_the_plugin_did_not_report_is_absent(self):
        fields = [FieldSpec(key="environment", type="string"), FieldSpec(key="retries", type="integer")]

        assert render_values(fields, {"environment": "lab"}) == {"environment": {"value": "lab"}}

    def test_nothing_reported_renders_only_the_secrets_as_unset(self):
        fields = [FieldSpec(key="environment", type="string"), FieldSpec(key="signing_key", type="string", secret=True)]

        assert render_values(fields, None) == {"signing_key": {"set": False}}


class TestScopeHelpers:
    # @escenario plugin-config/alcance-full-para-secretos/agent-no-escribe-un-secreto
    def test_secret_keys_finds_only_secret_keys_that_are_present(self):
        fields = [
            FieldSpec(key="environment", type="string"),
            FieldSpec(key="signing_key", type="string", secret=True),
            FieldSpec(key="auth_header", type="string", secret=True),
        ]

        assert secret_keys(fields, {"environment": "lab", "signing_key": CANARY}) == {"signing_key"}
        assert secret_keys(fields, {"environment": "lab"}) == set()

    def test_secret_keys_tolerates_a_malformed_body(self):
        """It runs before validation, so it cannot assume a mapping."""
        fields = [FieldSpec(key="signing_key", type="string", secret=True)]

        assert secret_keys(fields, ["signing_key"]) == set()
        assert secret_keys(fields, None) == set()

    def test_action_scope_returns_the_declared_one(self):
        assert action_scope(ActionSpec(name="run", requires_scope="agent")) == "agent"
        assert action_scope(ActionSpec(name="run", requires_scope="full")) == "full"
