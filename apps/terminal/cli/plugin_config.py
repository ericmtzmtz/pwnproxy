"""``pwnproxy plugin config|action`` — a plugin's configuration, over the API.

A plugin publishes what it needs (``GET …/schema``), keeps its own store and
enforces its own rules; this module is only the third client of that contract
(the Web UI and the MCP are the other two), so it decides nothing:

* **It prints what the server says.** Settings and collection items arrive as
  ``{"value": …}`` / ``{"set": bool}``; a secret is printed as ``set``/``unset``
  and its value is never in the response to begin with, so it cannot be printed
  by accident.
* **It writes only what was asked for.** ``set`` sends a ``PATCH`` with the keys
  named on the command line: a key that is not named is not touched, so a secret
  never has to be re-sent (no route of the API returns one).
* **``KEY=-`` reads the value from stdin**, one line per key. A credential in ``argv``
  ends up in the shell history and in ``ps``; stdin keeps it out of both. Nothing is echoed: this is not an interactive prompt.
* **The errors are the server's.** ``401``/``503`` get the shared explanation of
  :func:`pwnproxy.shared.api_client.auth_error_message`; ``403``/``404``/``409``/
  ``422`` print the ``detail`` as it came (``field: message`` for a validation
  error) and exit ``1`` with no traceback. A ``503`` that is not the token one
  (no loader, no task store in the process) keeps its own ``detail``: telling a
  user to check the token would be false.

The client is :func:`pwnproxy.shared.api_client.create_sync_api_client`, whose
Bearer token is the ``full`` one (``api-token``) — writing a secret needs it, and
the MCP, which holds ``agent``, deliberately cannot.

Two consequences worth knowing:

* a write asks for the schema first, because the CLI has to know the *type* of a
  value to send it as the server expects (``retries=3`` is the integer ``3``, not
  the string ``"3"``; ``events=a,b`` is the list ``["a", "b"]``). An undeclared key
  travels as text on purpose: the server answers ``422`` naming it, which is the
  message the user needs and the only one that cannot drift from the contract.
* a long action is not waited for: it prints the ``task_id`` and the command that
  reads it (``pwnproxy plugin action status``), which is the same ``GET
  /api/v1/tasks/{id}`` the Web UI polls.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import httpx
import typer

from pwnproxy.shared.api_client import auth_error_message, create_sync_api_client

config_app = typer.Typer(
    help="Read and write the configuration a plugin declares", no_args_is_help=True
)
collection_app = typer.Typer(
    help="List, add, change and remove the items of a collection", no_args_is_help=True
)
action_app = typer.Typer(
    help="Run a plugin action and read the task it may leave behind", no_args_is_help=True
)
config_app.add_typer(collection_app, name="collection")

#: Seconds the CLI waits for one call (a short action may take a while).
TIMEOUT = 30.0

#: Help of every command that takes ``KEY=VALUE`` arguments (ASCII, for a console).
PAIRS_HELP = "KEY=VALUE ... ; KEY=- reads one line from stdin (for secrets)"


# --------------------------------------------------------------------- plumbing


def _client() -> httpx.Client:
    """Build the API client (``full`` token). Tests replace this factory."""
    return create_sync_api_client(timeout=TIMEOUT)


def _error_text(response: httpx.Response) -> str:
    """Return the message to show for a failed response.

    ``401`` always gets the shared explanation of the credential
    (:func:`pwnproxy.shared.api_client.auth_error_message`) — it is the only
    thing a ``401`` can mean. A ``503`` is ambiguous: the auth middleware sends
    it when the API has no token at all, and a plugin route sends it when the
    process has no loader or no task store. The token wording is only used when
    the body is really the auth one, so a ``503`` of the plugin never tells the
    user to look for a token that is fine.

    Args:
        response: Response with a ``4xx``/``5xx`` status.

    Returns:
        The message for a rejected credential, ``field: message`` for the ``422``
        shape, and otherwise the server's ``detail`` verbatim.
    """
    detail = _detail(response)
    message = auth_error_message(response)
    if message is not None and not (
        response.status_code == 503 and detail != _no_token_detail()
    ):
        return message
    if isinstance(detail, dict):
        field, text = detail.get("field"), detail.get("message")
        if field and text:
            return f"{field}: {text}"
        return str(text or json.dumps(detail))
    if detail:
        return str(detail)
    return f"{response.status_code} {response.reason_phrase}: {response.text}".strip()


def _detail(response: httpx.Response) -> Any:
    """Return the parsed ``detail`` of an error response (``None`` when absent)."""
    try:
        return response.json().get("detail")
    except (ValueError, AttributeError):
        return None


def _no_token_detail() -> str:
    """Return the body the auth middleware sends with its token ``503``.

    Imported here and not at module level: the CLI is a client, and pulling
    FastAPI into every invocation of ``pwnproxy plugin`` to compare one string
    would be a cost paid by all commands for a rare error.
    """
    from pwnproxy.transport.rest.auth import NO_TOKEN_DETAIL

    return NO_TOKEN_DETAIL


def _call(client: httpx.Client, method: str, path: str, **kwargs: Any) -> Any:
    """Send one request and return its JSON body (``None`` for a ``204``).

    Raises:
        typer.Exit: ``1`` after printing the reason — the server's ``detail``, or
            "cannot reach the API" when there is no answer at all.
    """
    try:
        response = client.request(method, path, **kwargs)
    except httpx.HTTPError as exc:
        typer.echo(
            f"Cannot reach the pwnproxy API ({exc.__class__.__name__}: {exc}) — is it running?",
            err=True,
        )
        raise typer.Exit(1) from None
    if response.status_code >= 400:
        typer.echo(_error_text(response), err=True)
        raise typer.Exit(1)
    if response.status_code == 204:
        return None
    return response.json()


# ------------------------------------------------------------------------ values


def _stdin_value(key: str) -> str:
    """Read one line from stdin for ``key`` (``KEY=-``).

    Reads a line —not the whole stream— so a command can carry several
    ``KEY=-`` arguments and each one consumes exactly one line.
    """
    line = sys.stdin.readline()
    if not line:
        typer.echo(f"No value on stdin for {key!r} (expected one line)", err=True)
        raise typer.Exit(1)
    return line.rstrip("\r\n")


def _pairs(items: list[str]) -> dict[str, str]:
    """Turn ``KEY=VALUE`` arguments into a mapping, resolving ``KEY=-``."""
    values: dict[str, str] = {}
    for item in items:
        key, separator, raw = item.partition("=")
        if not separator or not key:
            typer.echo(f"Expected KEY=VALUE, got {item!r}", err=True)
            raise typer.Exit(1)
        values[key] = _stdin_value(key) if raw == "-" else raw
    return values


def _bad_value(key: str, raw: str, expected: str) -> None:
    """Report a value that cannot be of the declared type and exit ``1``."""
    typer.echo(f"{key}: expected {expected}, got {raw!r}", err=True)
    raise typer.Exit(1)


def _coerce_value(key: str, raw: str, field: dict[str, Any] | None) -> Any:
    """Convert one ``KEY=VALUE`` text to the JSON type its field declares.

    ``string``/``enum`` stay text (the server validates the choices); an
    undeclared key stays text too — the server answers ``422`` naming it.
    """
    kind = (field or {}).get("type", "string")
    if kind == "boolean":
        lowered = raw.strip().lower()
        if lowered in {"true", "false"}:
            return lowered == "true"
        _bad_value(key, raw, "true or false")
    if kind in {"integer", "number"}:
        try:
            return int(raw) if kind == "integer" else float(raw)
        except ValueError:
            _bad_value(key, raw, f"a{'n' if kind == 'number' else ''} {kind}")
    if kind == "array":
        return [part.strip() for part in raw.split(",") if part.strip()]
    return raw


def _coerce(values: dict[str, str], fields: list[dict[str, Any]]) -> dict[str, Any]:
    """Convert every value to its declared type (see :func:`_coerce_value`)."""
    declared = {field["key"]: field for field in fields}
    return {key: _coerce_value(key, raw, declared.get(key)) for key, raw in values.items()}


# --------------------------------------------------------------------- rendering


def _render(entry: dict[str, Any] | None) -> str:
    """Render one ``{"value": …}`` / ``{"set": bool}`` entry as text.

    A ``{"set": bool}`` entry is a secret: it says ``set``/``unset`` and never
    looks for a value anywhere.
    """
    if not entry:
        return "(unset)"
    if "set" in entry:
        return "set" if entry["set"] else "unset"
    value = entry.get("value")
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ", ".join(str(part) for part in value) or "(empty)"
    if value is None:
        return "(unset)"
    return str(value)


def _settings_lines(fields: list[dict[str, Any]], values: dict[str, Any]) -> list[str]:
    """One ``  key: value`` line per declared setting, in key order."""
    return [
        f"  {field['key']}: {_render(values.get(field['key']))}"
        for field in sorted(fields, key=lambda field: field["key"])
    ]


def _item_lines(values: dict[str, Any]) -> list[str]:
    """One ``    key: value`` line per item field, in key order."""
    return [f"    {key}: {_render(values[key])}" for key in sorted(values)]


def _echo(header: str, lines: list[str]) -> None:
    """Print a section header and its lines (already indented)."""
    typer.echo(header)
    for line in lines:
        typer.echo(line)


def _declared(schema: dict[str, Any], kind: str, name: str) -> dict[str, Any] | None:
    """Return the ``kind`` spec (``collections``/``actions``) called ``name``."""
    return next((spec for spec in schema.get(kind, []) if spec.get("name") == name), None)


def _collection_fields(schema: dict[str, Any], collection: str) -> list[dict[str, Any]]:
    """Item fields of ``collection`` (empty when undeclared: the server answers ``404``)."""
    declared = _declared(schema, "collections", collection)
    return list(declared.get("item", [])) if declared else []


def _action_parameters(schema: dict[str, Any], action: str) -> list[dict[str, Any]]:
    """Parameters of ``action`` (empty when undeclared: the server answers ``404``)."""
    declared = _declared(schema, "actions", action)
    return list(declared.get("parameters", [])) if declared else []


def _print_collection(data: dict[str, Any]) -> None:
    """Print a collection response: its ``n/max`` counter and one block per item."""
    typer.echo(f"Collection: {data['collection']} ({len(data['items'])}/{data['max_items']})")
    for item in data["items"]:
        _echo(f"  {item['id']}:", _item_lines(item["values"]))


def _print_result(value: Any) -> None:
    """Print a result (or a task's result) as JSON."""
    typer.echo("Result:")
    typer.echo(json.dumps(value, indent=2, default=str))


def _print_action(result: dict[str, Any]) -> None:
    """Print a short action's result or a long one's ``task_id`` and how to read it."""
    typer.echo(f"Status:  {result.get('status', 'completed')}")
    task_id = result.get("task_id")
    if task_id:
        typer.echo(f"Task:    {task_id}")
        typer.echo(f"Read it with: pwnproxy plugin action status {task_id}")
        return
    _print_result(result.get("result"))


# ---------------------------------------------------------------------- commands


@config_app.command("show")
def show(
    name: str = typer.Argument(..., help="Plugin name as the catalog reports it"),
    collection: str | None = typer.Option(
        None, "--collection", "-c", help="Show one collection instead of the settings"
    ),
) -> None:
    """Print a plugin's schema and values (a secret as set/unset).

    Without --collection it prints the settings; with it, the items of that
    collection. Nothing of the output is derived from a secret.
    """
    client = _client()
    try:
        schema = _call(client, "GET", f"/plugins/{name}/schema")
        if collection:
            _print_collection(_call(client, "GET", f"/plugins/{name}/collections/{collection}"))
            return
        if not (schema["settings"] or schema["collections"] or schema["actions"]):
            typer.echo(f"Plugin:  {name}")
            typer.echo("Config:  none declared by the plugin")
            return
        settings = _call(client, "GET", f"/plugins/{name}/settings")
    finally:
        client.close()

    typer.echo(f"Plugin:  {name}")
    typer.echo(f"Schema:  version {schema['schema_version']}")
    if schema["settings"]:
        _echo("Settings:", _settings_lines(schema["settings"], settings["values"]))
    if schema["collections"]:
        _echo(
            "Collections:",
            [f"  {spec['name']}: max {spec['max_items']} items" for spec in schema["collections"]],
        )
    if schema["actions"]:
        _echo("Actions:", [f"  {_action_line(spec)}" for spec in schema["actions"]])


def _action_line(spec: dict[str, Any]) -> str:
    """Describe one action: ``name: long-running|inline, scope <scope>``."""
    timing = "long-running" if spec.get("long_running") else "inline"
    return f"{spec['name']}: {timing}, scope {spec.get('requires_scope', 'full')}"


@config_app.command("set")
def set_settings(
    name: str = typer.Argument(..., help="Plugin name as the catalog reports it"),
    pairs: list[str] = typer.Argument(..., help=PAIRS_HELP),
) -> None:
    """Write the settings named on the command line (a partial PATCH)."""
    client = _client()
    try:
        schema = _call(client, "GET", f"/plugins/{name}/schema")
        values = _coerce(_pairs(pairs), schema["settings"])
        result = _call(client, "PATCH", f"/plugins/{name}/settings", json={"values": values})
    finally:
        client.close()

    typer.echo(f"Updated {name}: {', '.join(values)}")
    for line in _settings_lines(schema["settings"], result["values"]):
        typer.echo(line)


@collection_app.command("list")
def collection_list(
    name: str = typer.Argument(..., help="Plugin name as the catalog reports it"),
    collection: str = typer.Argument(..., help="Collection name as the schema declares it"),
) -> None:
    """Print one collection with its items."""
    client = _client()
    try:
        _print_collection(_call(client, "GET", f"/plugins/{name}/collections/{collection}"))
    finally:
        client.close()


@collection_app.command("add")
def collection_add(
    name: str = typer.Argument(..., help="Plugin name as the catalog reports it"),
    collection: str = typer.Argument(..., help="Collection name as the schema declares it"),
    pairs: list[str] | None = typer.Argument(None, help=PAIRS_HELP),
) -> None:
    """Create one item (409 when the collection is full)."""
    client = _client()
    try:
        schema = _call(client, "GET", f"/plugins/{name}/schema")
        values = _coerce(_pairs(pairs or []), _collection_fields(schema, collection))
        item = _call(
            client,
            "POST",
            f"/plugins/{name}/collections/{collection}",
            json={"values": values},
        )
    finally:
        client.close()

    typer.echo(f"Created {collection}/{item['id']}")
    for line in _item_lines(item["values"]):
        typer.echo(line)


@collection_app.command("update")
def collection_update(
    name: str = typer.Argument(..., help="Plugin name as the catalog reports it"),
    collection: str = typer.Argument(..., help="Collection name as the schema declares it"),
    item_id: str = typer.Argument(..., help="Id of the item, as `list` prints it"),
    pairs: list[str] | None = typer.Argument(None, help=PAIRS_HELP),
) -> None:
    """Change the fields named on the command line (a partial PATCH of one item)."""
    client = _client()
    try:
        schema = _call(client, "GET", f"/plugins/{name}/schema")
        values = _coerce(_pairs(pairs or []), _collection_fields(schema, collection))
        item = _call(
            client,
            "PATCH",
            f"/plugins/{name}/collections/{collection}/{item_id}",
            json={"values": values},
        )
    finally:
        client.close()

    typer.echo(f"Updated {collection}/{item_id}")
    for line in _item_lines(item["values"]):
        typer.echo(line)


@collection_app.command("remove")
def collection_remove(
    name: str = typer.Argument(..., help="Plugin name as the catalog reports it"),
    collection: str = typer.Argument(..., help="Collection name as the schema declares it"),
    item_id: str = typer.Argument(..., help="Id of the item, as `list` prints it"),
) -> None:
    """Delete one item (404 when it is already gone)."""
    client = _client()
    try:
        _call(client, "DELETE", f"/plugins/{name}/collections/{collection}/{item_id}")
    finally:
        client.close()

    typer.echo(f"Removed {collection}/{item_id}")


@action_app.command("run")
def action_run(
    name: str = typer.Argument(..., help="Plugin name as the catalog reports it"),
    action: str = typer.Argument(..., help="Action name as the schema declares it"),
    pairs: list[str] | None = typer.Argument(None, help=PAIRS_HELP),
) -> None:
    """Run an action: its result inline, or its task_id when it is long.

    A long action is not waited for here: it prints the task_id and the
    command that reads it, so the shell is not blocked by a job.
    """
    client = _client()
    try:
        schema = _call(client, "GET", f"/plugins/{name}/schema")
        parameters = _coerce(_pairs(pairs or []), _action_parameters(schema, action))
        result = _call(
            client,
            "POST",
            f"/plugins/{name}/actions/{action}",
            json={"parameters": parameters},
        )
    finally:
        client.close()

    _print_action(result)


@action_app.command("status")
def action_status(
    task_id: str = typer.Argument(..., help="Task id printed by a long action"),
) -> None:
    """Print the status of a task (a long action's result once it finished)."""
    client = _client()
    try:
        task = _call(client, "GET", f"/tasks/{task_id}")
    finally:
        client.close()

    typer.echo(f"Status:  {task.get('status')}")
    if task.get("error"):
        typer.echo(f"Error:   {task['error']}")
    if task.get("result") is not None:
        _print_result(task["result"])


__all__ = ["PAIRS_HELP", "TIMEOUT", "action_app", "collection_app", "config_app"]
