"""``pwnproxy api token`` — show (and rotate) the token the local API asks for.

The API has no other way in: every route except ``GET /api/v1/health`` wants
``Authorization: Bearer <token>``, and the WebSocket wants the token in the
``pwnproxy-token.`` subprotocol. So this command is the answer to "I need the
token", for the user and for the scripts:

* **no arguments** — prints the ``full`` token (``api-token``), the file it came
  from and the Web UI URL with the token in the fragment, which is how the UI is
  opened without pasting anything.
* **``--scope agent``** — prints the ``agent`` token (``mcp-token``) and no URL:
  the MCP does not open a browser.
* **``--rotate``** — new token, written atomically with the restrictive
  permissions of :func:`pwnproxy.shared.api_token.write_token`. Old clients get
  ``401`` on their next request (the server re-reads the file every time);
  WebSockets already open survive until they reconnect.

Decisions worth knowing:

* The token file is normally created when the API starts. If the API has never
  run, ``--scope api`` (the default) **creates** ``api-token`` here instead of
  answering "no token yet": the command is what the panel and the Web UI tell you
  to run, so it must produce something. ``--scope agent`` does **not** create
  ``mcp-token``: that file only exists for the MCP, and creating agent
  credentials because somebody asked for a UI token would hand out a second key.
* With ``PWNPROXY_API_TOKEN`` defined, the server accepts that value and it wins
  over the file, so ``--rotate`` refuses to touch ``api-token`` (the old value
  would keep working anyway): the message says to unset the variable.
* Output is plain text, one field per line, no rich markup and no wrapping: the
  dev scripts parse ``Token:`` from it and print only the URL.
"""

from __future__ import annotations

import os
from pathlib import Path

import typer

from pwnproxy.shared.api_token import (
    API_TOKEN_FILE,
    MCP_TOKEN_FILE,
    SCOPE_AGENT,
    SCOPE_FULL,
    TOKEN_ENV,
    generate_token,
    read_token,
    rotate_token,
    token_path,
    write_token,
)
from pwnproxy.shared.ports import DEFAULT_WEB_PORT

#: Values accepted by ``--scope`` and the token scope each one means.
SCOPE_CHOICES: dict[str, str] = {"api": SCOPE_FULL, "agent": SCOPE_AGENT}

app = typer.Typer(
    help="Local API token: show it (with the Web UI URL) or rotate it",
    no_args_is_help=True,
)


def _resolve_scope(scope: str) -> str:
    """Map the ``--scope`` value to an internal scope.

    Args:
        scope: ``"api"`` or ``"agent"``.

    Returns:
        ``"full"`` or ``"agent"``.

    Raises:
        typer.BadParameter: ``scope`` is neither of the two accepted values.
    """
    try:
        return SCOPE_CHOICES[scope]
    except KeyError:
        raise typer.BadParameter(
            f"{scope!r} is not a scope; use one of {', '.join(SCOPE_CHOICES)}"
        ) from None


def web_ui_url(token: str, web_port: int = DEFAULT_WEB_PORT) -> str:
    """Return the Web UI URL that carries ``token`` in the fragment.

    The fragment is never sent to a server, so this is the one URL the token may
    appear in.

    Args:
        token: Token to embed.
        web_port: Port the Web UI is served on.

    Returns:
        ``http://127.0.0.1:<web_port>/#token=<token>``.
    """
    return f"http://127.0.0.1:{web_port}/#token={token}"


def _env_token() -> str:
    """Return ``PWNPROXY_API_TOKEN`` (stripped) or ``""`` when it is not set."""
    return (os.environ.get(TOKEN_ENV) or "").strip()


def _create_if_missing(scope: str) -> tuple[str, bool]:
    """Return the token of ``scope``, creating ``api-token`` when absent.

    Args:
        scope: ``"full"`` or ``"agent"``.

    Returns:
        ``(token, created)``; ``created`` says whether this call wrote the file.

    Raises:
        FileNotFoundError: ``scope`` is ``"agent"`` and there is no token: the
            API creates ``mcp-token`` on start, and this command deliberately
            does not mint agent credentials on its own.
    """
    current = read_token(scope)
    if current is not None:
        return current, False
    if scope == SCOPE_AGENT:
        raise FileNotFoundError(str(token_path(SCOPE_AGENT)))
    token = generate_token()
    write_token(scope, token)
    return token, True


def _show(scope: str, current: str, *, created: bool) -> None:
    """Print the token, the file it lives in and the Web UI URL.

    Args:
        scope: ``"full"`` or ``"agent"``.
        current: The token to print.
        created: Whether this command had to create the token file.
    """
    typer.echo(f"Token:   {current}")
    typer.echo(f"File:    {token_path(scope)}")
    if created:
        typer.echo(
            "Note:    the file did not exist; this command created it with the same "
            "restricted permissions the API uses."
        )
    if scope == SCOPE_FULL:
        typer.echo(f"Web UI:  {web_ui_url(current)}")


def _rotate(scope: str, *, env_token: str) -> None:
    """Write a new token for ``scope`` and report what breaks.

    Args:
        scope: ``"full"`` or ``"agent"``.
        env_token: Value of ``PWNPROXY_API_TOKEN``, already stripped.

    Raises:
        typer.Exit: ``scope`` is ``full`` and the environment variable is set:
            the server would keep accepting the old (env) token, so rotating the
            file would be a lie.
    """
    if scope == SCOPE_FULL and env_token:
        typer.echo(
            f"{TOKEN_ENV} is set: the API accepts that value and this command will not "
            f"touch {token_path(SCOPE_FULL)}.",
            err=True,
        )
        typer.echo(
            f"Unset {TOKEN_ENV} (and restart the API) if you want to rotate the file.",
            err=True,
        )
        raise typer.Exit(1)
    path: Path = token_path(scope)
    token = rotate_token(scope)
    typer.echo(f"Rotated: {path}")
    typer.echo(f"Token:   {token}")
    typer.echo(
        "Old clients get 401 on their next request; WebSockets already open keep "
        "working until they reconnect."
    )
    if scope == SCOPE_FULL:
        typer.echo(f"Web UI:  {web_ui_url(token)}")


@app.command("token")
def token(
    scope: str = typer.Option(
        "api",
        "--scope",
        help=f"Which token: 'api' ({API_TOKEN_FILE}, Web UI/TUI/CLI) or 'agent' ({MCP_TOKEN_FILE}, MCP)",
    ),
    rotate: bool = typer.Option(
        False,
        "--rotate",
        help="Generate a new token (old clients will receive 401)",
    ),
) -> None:
    """Show the local API token, or rotate it.

    Plain text, one field per line: ``pwnproxy api token`` prints the token, the
    file it lives in and the Web UI URL that carries it in the fragment.
    """
    internal_scope = _resolve_scope(scope)
    env_token = _env_token()
    if rotate:
        _rotate(internal_scope, env_token=env_token)
        return
    if internal_scope == SCOPE_FULL and env_token:
        typer.echo(f"Token:   {env_token}")
        typer.echo(f"Source:  {TOKEN_ENV} (this value wins over {token_path(internal_scope)})")
        typer.echo(f"Web UI:  {web_ui_url(env_token)}")
        return
    try:
        current, created = _create_if_missing(internal_scope)
    except FileNotFoundError as exc:
        typer.echo(f"No agent token yet: {exc} does not exist.", err=True)
        typer.echo(
            "The API creates it when it starts — run 'pwnproxy start' (or 'poetry run "
            "pwnproxy start') once, then retry.",
            err=True,
        )
        raise typer.Exit(1) from None
    _show(internal_scope, current, created=created)


__all__ = [
    "SCOPE_CHOICES",
    "app",
    "token",
    "web_ui_url",
]
