"""``pwnproxy plugin config|action``: the CLI as the third client of the contract.

The command talks to the API with the ``full`` token, prints what the server
renders (a secret as ``set``/``unset``, never a value) and shows the server's
``detail`` when it refuses. So the interesting cases are: a secret that never
reaches the terminal, a partial ``PATCH``, an error that keeps its ``field`` and
its ``message``, and a long action that reports its ``task_id`` instead of
blocking the shell.

The API is an ``httpx.MockTransport`` behind the real
:func:`pwnproxy.shared.api_client.create_sync_api_client`, so the Bearer token,
the base URL and the request bodies are the ones the CLI really builds.
"""

from __future__ import annotations

import importlib
import json

import httpx
import pytest
from typer.testing import CliRunner

from apps.terminal.cli import app
from apps.terminal.cli import plugin_config as cli
from pwnproxy.shared.api_client import create_sync_api_client
from pwnproxy.shared.api_token import write_token

#: Value of the secret in the tests. If it shows up in an output, a secret leaked.
CANARY = "CANARIO-5b83c1"

#: The ``full`` token the CLI has to send; it goes to a temporary config dir.
FULL_TOKEN = "cli-full-token-8d2f1c"

PLUGIN = "example-checker"
SCHEMA_PATH = f"/api/v1/plugins/{PLUGIN}/schema"
SETTINGS_PATH = f"/api/v1/plugins/{PLUGIN}/settings"
COLLECTION_PATH = f"/api/v1/plugins/{PLUGIN}/collections/webhooks"

#: The schema of the contract, as the server publishes it.
SCHEMA = {
    "plugin": PLUGIN,
    "schema_version": 1,
    "settings": [
        {
            "key": "environment",
            "type": "enum",
            "required": False,
            "secret": False,
            "read_only": False,
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
                {"key": "name", "type": "string", "required": True, "secret": False},
                {"key": "events", "type": "array", "items": "string", "secret": False},
                {"key": "signing_key", "type": "string", "secret": True},
            ],
        }
    ],
    "actions": [
        {
            "name": "ping",
            "long_running": False,
            "requires_scope": "full",
            "parameters": [{"key": "name", "type": "string"}],
        },
        {
            "name": "send_test",
            "long_running": True,
            "requires_scope": "full",
            "parameters": [{"key": "payload", "type": "string"}],
        },
    ],
}

#: The settings the server renders. ``signing_key`` also carries a ``value`` here on
#: purpose: the API never sends one (``render_values`` refuses to), and this file
#: proves the CLI would not print it if it ever did — it decides by the ``set``
#: key, not by "is there a value to show".
SETTINGS = {
    "plugin": PLUGIN,
    "schema_version": 1,
    "values": {
        "environment": {"value": "lab"},
        "retries": {"value": 1},
        "signing_key": {"set": True, "value": CANARY},
    },
}

COLLECTION = {
    "plugin": PLUGIN,
    "collection": "webhooks",
    "schema_version": 1,
    "max_items": 2,
    "items": [
        {
            "id": "app",
            "values": {
                "name": {"value": "app"},
                "events": {"value": []},
                "signing_key": {"set": False},
            },
        },
        {
            "id": "ci",
            "values": {
                "name": {"value": "ci"},
                "events": {"value": ["app.lab", "ci.lab"]},
                "signing_key": {"set": True, "value": CANARY},
            },
        },
    ],
}


class FakeApi:
    """An in-memory API behind ``httpx.MockTransport``.

    Routes are keyed by ``(method, path)``; an unregistered route answers ``599``
    so a wrong URL in the CLI fails the test instead of passing silently.
    """

    def __init__(self) -> None:
        self.replies: dict[tuple[str, str], tuple[int, object]] = {}
        self.seen: list[dict[str, object]] = []

    def handler(self, request):
        body = json.loads(request.content) if request.content else None
        self.seen.append(
            {
                "method": request.method,
                "path": request.url.path,
                "body": body,
                "authorization": request.headers.get("Authorization"),
            }
        )
        status, reply = self.replies.get(
            (request.method, request.url.path),
            (599, {"detail": f"unexpected {request.method} {request.url.path}"}),
        )
        if status == 204:
            return httpx.Response(204, request=request)
        return httpx.Response(status, json=reply, request=request)

    def routes(self) -> list[tuple[str, str, object]]:
        """The requests made, as ``(method, path, body)`` (no token in the way)."""
        return [(r["method"], r["path"], r["body"]) for r in self.seen]


@pytest.fixture
def api(tmp_path, monkeypatch):
    """Serve the CLI from :class:`FakeApi` (the real client, a mock transport).

    The ``full`` token lives in a **temporary** config dir: the CLI reads the
    token from the file, and nothing here may touch ``~/.pwnproxy``.
    """
    monkeypatch.setenv("PWNPROXY_CONFIG_DIR", str(tmp_path))
    write_token("full", FULL_TOKEN)
    fake = FakeApi()

    def transport_client(**kwargs):
        return create_sync_api_client(transport=httpx.MockTransport(fake.handler), **kwargs)

    monkeypatch.setattr(cli, "create_sync_api_client", transport_client)
    return fake


def run(*args: str, stdin: str | None = None):
    """Invoke ``pwnproxy plugin …`` the way the shell does."""
    return CliRunner().invoke(app, ["plugin", *args], input=stdin)


# --------------------------------------------------------------------------- show


def test_show_prints_the_schema_and_a_secret_as_set(api):
    """A secret says ``set``; its value is not printed even when it is in the body."""
    api.replies[("GET", SCHEMA_PATH)] = (200, SCHEMA)
    api.replies[("GET", SETTINGS_PATH)] = (200, SETTINGS)

    result = run("config", "show", PLUGIN)

    assert result.exit_code == 0
    assert CANARY not in result.output
    assert result.output == (
        f"Plugin:  {PLUGIN}\n"
        "Schema:  version 1\n"
        "Settings:\n"
        "  environment: lab\n"
        "  retries: 1\n"
        "  signing_key: set\n"
        "Collections:\n"
        "  webhooks: max 2 items\n"
        "Actions:\n"
        "  ping: inline, scope full\n"
        "  send_test: long-running, scope full\n"
    )


def test_show_sends_the_full_token_and_reads_both_routes(api):
    """The CLI is a ``full`` client: reading a secret is allowed, writing it needs it."""
    api.replies[("GET", SCHEMA_PATH)] = (200, SCHEMA)
    api.replies[("GET", SETTINGS_PATH)] = (200, SETTINGS)

    run("config", "show", PLUGIN)

    assert api.routes() == [("GET", SCHEMA_PATH, None), ("GET", SETTINGS_PATH, None)]
    assert {request["authorization"] for request in api.seen} == {f"Bearer {FULL_TOKEN}"}


def test_show_with_a_collection_lists_the_items(api):
    api.replies[("GET", SCHEMA_PATH)] = (200, SCHEMA)
    api.replies[("GET", COLLECTION_PATH)] = (200, COLLECTION)

    result = run("config", "show", PLUGIN, "--collection", "webhooks")

    assert result.exit_code == 0
    assert CANARY not in result.output
    assert result.output == (
        "Collection: webhooks (2/2)\n"
        "  app:\n"
        "    events: (empty)\n"
        "    name: app\n"
        "    signing_key: unset\n"
        "  ci:\n"
        "    events: app.lab, ci.lab\n"
        "    name: ci\n"
        "    signing_key: set\n"
    )
    assert api.routes() == [("GET", SCHEMA_PATH, None), ("GET", COLLECTION_PATH, None)]


def test_show_says_so_when_the_plugin_declares_nothing(api):
    """The six bundled scanners declare no schema: silent would be a bug."""
    api.replies[("GET", "/api/v1/plugins/sqli/schema")] = (
        200,
        {"plugin": "sqli", "schema_version": 1, "settings": [], "collections": [], "actions": []},
    )

    result = run("config", "show", "sqli")

    assert result.exit_code == 0
    assert result.output == ("Plugin:  sqli\nConfig:  none declared by the plugin\n")
    assert api.routes() == [("GET", "/api/v1/plugins/sqli/schema", None)]


# ---------------------------------------------------------------------- settings


def test_set_patches_only_the_keys_given(api):
    """A partial ``PATCH``: the keys that were not named do not travel."""
    api.replies[("GET", SCHEMA_PATH)] = (200, SCHEMA)
    api.replies[("PATCH", SETTINGS_PATH)] = (
        200,
        {
            "plugin": PLUGIN,
            "schema_version": 1,
            "values": {
                "environment": {"value": "staging"},
                "retries": {"value": 3},
                "signing_key": {"set": True},
            },
        },
    )

    result = run("config", "set", PLUGIN, "retries=3", "environment=staging")

    assert result.exit_code == 0
    assert api.routes() == [
        ("GET", SCHEMA_PATH, None),
        ("PATCH", SETTINGS_PATH, {"values": {"retries": 3, "environment": "staging"}}),
    ]
    assert result.output == (
        f"Updated {PLUGIN}: retries, environment\n"
        "  environment: staging\n"
        "  retries: 3\n"
        "  signing_key: set\n"
    )


def test_set_reads_a_secret_from_stdin_and_never_prints_it(api):
    """``KEY=-``: the value goes to the API and not to the history nor the terminal."""
    api.replies[("GET", SCHEMA_PATH)] = (200, SCHEMA)
    api.replies[("PATCH", SETTINGS_PATH)] = (200, SETTINGS)

    result = run("config", "set", PLUGIN, "signing_key=-", stdin=f"{CANARY}\n")

    assert result.exit_code == 0
    assert api.routes() == [
        ("GET", SCHEMA_PATH, None),
        ("PATCH", SETTINGS_PATH, {"values": {"signing_key": CANARY}}),
    ]
    assert CANARY not in result.output
    assert result.output == (
        f"Updated {PLUGIN}: signing_key\n"
        "  environment: lab\n"
        "  retries: 1\n"
        "  signing_key: set\n"
    )


def test_set_without_a_value_fails_before_touching_the_api(api):
    """A typo (``retries`` without ``=``) is a usage error, not a silent empty write."""
    api.replies[("GET", SCHEMA_PATH)] = (200, SCHEMA)

    result = run("config", "set", PLUGIN, "retries")

    assert (result.exit_code, result.output) == (1, "Expected KEY=VALUE, got 'retries'\n")
    assert api.routes() == [("GET", SCHEMA_PATH, None)]


# ------------------------------------------------------------------------ errors


def test_secret_write_forbidden_shows_the_server_message(api):
    """A ``403`` is printed verbatim: it says where a secret can be written."""
    detail = "Secret fields can only be written with a token of scope 'full' (Web UI or CLI)"
    api.replies[("GET", SCHEMA_PATH)] = (200, SCHEMA)
    api.replies[("PATCH", SETTINGS_PATH)] = (403, {"detail": detail})

    result = run("config", "set", PLUGIN, f"signing_key={CANARY}")

    assert (result.exit_code, result.output) == (1, f"{detail}\n")
    assert CANARY not in result.output


def test_validation_error_shows_the_field_and_the_message(api):
    """``422`` is ``{"field", "message"}``: the CLI prints both, not a traceback."""
    api.replies[("GET", SCHEMA_PATH)] = (200, SCHEMA)
    api.replies[("PATCH", SETTINGS_PATH)] = (
        422,
        {"detail": {"field": "retries", "message": "must be at most 5"}},
    )

    result = run("config", "set", PLUGIN, "retries=9")

    assert (result.exit_code, result.output) == (1, "retries: must be at most 5\n")
    assert "Traceback" not in result.output


def test_undeclared_collection_shows_the_server_404(api):
    api.replies[("GET", SCHEMA_PATH)] = (200, SCHEMA)
    api.replies[("GET", f"/api/v1/plugins/{PLUGIN}/collections/nope")] = (
        404,
        {"detail": f"plugin '{PLUGIN}' declares no collection 'nope'"},
    )

    result = run("config", "collection", "list", PLUGIN, "nope")

    assert (result.exit_code, result.output) == (
        1,
        f"plugin '{PLUGIN}' declares no collection 'nope'\n",
    )


def test_rejected_token_gets_the_shared_explanation(api):
    """A ``401`` is not "the command broke": it says how to see the token."""
    api.replies[("GET", SCHEMA_PATH)] = (401, {"detail": "Missing or invalid API token"})

    result = run("config", "show", PLUGIN)

    assert result.exit_code == 1
    assert "API rejected the token (401)" in result.output
    assert "pwnproxy api token" in result.output


def test_a_503_without_a_token_explains_how_to_create_one(api):
    """The auth ``503`` (no token file at all) is the one that talks about tokens."""
    from pwnproxy.transport.rest.auth import NO_TOKEN_DETAIL

    api.replies[("GET", SCHEMA_PATH)] = (503, {"detail": NO_TOKEN_DETAIL})

    result = run("config", "show", PLUGIN)

    assert result.exit_code == 1
    assert "The API has no token configured (503)" in result.output
    assert "pwnproxy api token" in result.output


def test_a_plugin_503_keeps_its_own_reason(api):
    """No task store is not "no token": repeating the credential text would lie."""
    detail = "No task store in this process for a long-running action"
    api.replies[("GET", SCHEMA_PATH)] = (200, SCHEMA)
    api.replies[("POST", f"/api/v1/plugins/{PLUGIN}/actions/send_test")] = (
        503,
        {"detail": detail},
    )

    result = run("action", "run", PLUGIN, "send_test")

    assert (result.exit_code, result.output) == (1, f"{detail}\n")


def test_api_down_says_so_without_a_traceback(monkeypatch):
    """No answer at all is "cannot reach the API", not a broken command."""

    def refuse(request):
        raise httpx.ConnectError("Connection refused", request=request)

    monkeypatch.setattr(
        cli,
        "create_sync_api_client",
        lambda **kwargs: create_sync_api_client(
            transport=httpx.MockTransport(refuse), **kwargs
        ),
    )

    result = run("config", "show", PLUGIN)

    assert (result.exit_code, "Cannot reach the pwnproxy API" in result.output) == (1, True)
    assert "Traceback" not in result.output


# -------------------------------------------------------------------- collection


def test_collection_add_creates_and_renders_the_item(api):
    api.replies[("GET", SCHEMA_PATH)] = (200, SCHEMA)
    api.replies[("POST", COLLECTION_PATH)] = (
        201,
        {
            "id": "app",
            "values": {
                "name": {"value": "app"},
                "events": {"value": ["app.lab"]},
                "signing_key": {"set": True},
            },
        },
    )

    result = run(
        "config",
        "collection",
        "add",
        PLUGIN,
        "webhooks",
        "name=app",
        "events=app.lab",
        "signing_key=-",
        stdin=f"{CANARY}\n",
    )

    assert result.exit_code == 0
    assert api.routes() == [
        ("GET", SCHEMA_PATH, None),
        (
            "POST",
            COLLECTION_PATH,
            {"values": {"name": "app", "events": ["app.lab"], "signing_key": CANARY}},
        ),
    ]
    assert CANARY not in result.output
    assert result.output == (
        "Created webhooks/app\n"
        "    events: app.lab\n"
        "    name: app\n"
        "    signing_key: set\n"
    )


def test_collection_remove_deletes_the_item(api):
    api.replies[("DELETE", f"{COLLECTION_PATH}/app")] = (204, None)

    result = run("config", "collection", "remove", PLUGIN, "webhooks", "app")

    assert (result.exit_code, result.output) == (0, "Removed webhooks/app\n")
    assert api.routes() == [("DELETE", f"{COLLECTION_PATH}/app", None)]


def test_collection_update_reports_the_item_back(api):
    api.replies[("GET", SCHEMA_PATH)] = (200, SCHEMA)
    api.replies[("PATCH", f"{COLLECTION_PATH}/ci")] = (
        200,
        {
            "id": "ci",
            "values": {
                "name": {"value": "ci"},
                "events": {"value": ["app.lab"]},
                "signing_key": {"set": False},
            },
        },
    )

    result = run(
        "config", "collection", "update", PLUGIN, "webhooks", "ci", "events=app.lab"
    )

    assert result.exit_code == 0
    assert api.routes() == [
        ("GET", SCHEMA_PATH, None),
        ("PATCH", f"{COLLECTION_PATH}/ci", {"values": {"events": ["app.lab"]}}),
    ]
    assert result.output == (
        "Updated webhooks/ci\n"
        "    events: app.lab\n"
        "    name: ci\n"
        "    signing_key: unset\n"
    )


# ----------------------------------------------------------------------- actions


def test_action_run_short_prints_the_result(api):
    api.replies[("GET", SCHEMA_PATH)] = (200, SCHEMA)
    api.replies[("POST", f"/api/v1/plugins/{PLUGIN}/actions/ping")] = (
        200,
        {"plugin": PLUGIN, "action": "ping", "status": "completed",
         "result": {"reachable": True, "status_code": 200}},
    )

    result = run("action", "run", PLUGIN, "ping", "name=app")

    assert result.exit_code == 0
    assert api.routes() == [
        ("GET", SCHEMA_PATH, None),
        (
            "POST",
            f"/api/v1/plugins/{PLUGIN}/actions/ping",
            {"parameters": {"name": "app"}},
        ),
    ]
    assert result.output == (
        "Status:  completed\n"
        "Result:\n"
        "{\n"
        '  "reachable": true,\n'
        '  "status_code": 200\n'
        "}\n"
    )


def test_action_run_long_prints_the_task_and_how_to_read_it(api):
    """A long action does not block the shell: it hands back the ``task_id``."""
    api.replies[("GET", SCHEMA_PATH)] = (200, SCHEMA)
    api.replies[("POST", f"/api/v1/plugins/{PLUGIN}/actions/send_test")] = (
        202,
        {"plugin": PLUGIN, "action": "send_test", "status": "running", "task_id": "task-42"},
    )

    result = run("action", "run", PLUGIN, "send_test")

    assert result.exit_code == 0
    assert api.routes() == [
        ("GET", SCHEMA_PATH, None),
        ("POST", f"/api/v1/plugins/{PLUGIN}/actions/send_test", {"parameters": {}}),
    ]
    assert result.output == (
        "Status:  running\n"
        "Task:    task-42\n"
        "Read it with: pwnproxy plugin action status task-42\n"
    )


def test_action_status_reads_the_task(api):
    api.replies[("GET", "/api/v1/tasks/task-42")] = (
        200,
        {"task_id": "task-42", "type": "plugin_action", "status": "completed",
         "result": {"reachable": True}},
    )

    result = run("action", "status", "task-42")

    assert result.exit_code == 0
    assert api.routes() == [("GET", "/api/v1/tasks/task-42", None)]
    assert result.output == (
        "Status:  completed\n"
        "Result:\n"
        "{\n"
        '  "reachable": true\n'
        "}\n"
    )


def test_action_status_shows_a_failed_task_without_a_trace(api):
    api.replies[("GET", "/api/v1/tasks/task-42")] = (
        200,
        {"task_id": "task-42", "type": "plugin_action", "status": "failed",
         "error": "plugin 'example-checker' failed"},
    )

    result = run("action", "status", "task-42")

    assert (result.exit_code, result.output) == (
        0,
        "Status:  failed\nError:   plugin 'example-checker' failed\n",
    )


# ------------------------------------------------------------------------ routes

#: What the CLI calls, as the routers of section A declare it. A route that is
#: renamed or moved makes this fail instead of failing at a user's terminal.
CLI_ROUTES = {
    "plugin_config": [
        ("GET", "/api/v1/plugins/{name}/schema"),
        ("PATCH", "/api/v1/plugins/{name}/settings"),
        ("GET", "/api/v1/plugins/{name}/collections/{collection}"),
        ("POST", "/api/v1/plugins/{name}/collections/{collection}"),
        ("PATCH", "/api/v1/plugins/{name}/collections/{collection}/{item_id}"),
        ("DELETE", "/api/v1/plugins/{name}/collections/{collection}/{item_id}"),
        ("POST", "/api/v1/plugins/{name}/actions/{action}"),
    ],
    "tasks": [("GET", "/api/v1/tasks/{task_id}")],
}


def test_every_path_the_cli_calls_exists_in_the_real_routers():
    """The parameters differ per route; the path and the verb may not."""
    missing = []
    for module_name, expected in CLI_ROUTES.items():
        router = importlib.import_module(f"pwnproxy.transport.rest.{module_name}").router
        declared = {
            (method, route.path) for route in router.routes for method in route.methods
        }
        missing += [row for row in expected if row not in declared]
    assert missing == []
