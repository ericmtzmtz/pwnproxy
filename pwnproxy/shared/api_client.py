"""``httpx`` client for the local API, with the token already attached.

Every in-process client of the REST API (the TUI today; the CLI when it needs
it) has to send ``Authorization: Bearer <token>``. Building that by hand in each
screen — as the TUI does today with a fresh ``httpx.AsyncClient()`` per call —
means one place will forget it, and the failure mode is a ``401`` that looks
like a broken API.

This module is the single seam: it reads the token from
``pwnproxy.shared.api_token`` (file or ``PWNPROXY_API_TOKEN``) **once per client
instance** and puts it in the client's default headers. It lives in ``shared/``
because ``shared/`` may not import ``plugins/`` (nor ``transport/``), and the
transport layer imports it, not the other way round.

It also owns the **messages** for a rejected credential
(:func:`auth_error_message`, :func:`websocket_error_message`): a ``401``/``503``
or a ``4401`` close has to say "run ``pwnproxy api token``", and that sentence has
to be the same in the TUI, in the Intruder screen and in whatever client comes
next. Keeping it here also keeps ``pwnproxy/`` from importing ``apps/`` just to
share a string (``tests/architecture/test_layering.py``).

A token rotated while a client is alive is not picked up by that client: build a
new one (the API itself re-reads the file on every request, so the server side
needs no restart).
"""

from __future__ import annotations

import os

import httpx

from pwnproxy.shared.api_token import (
    SCOPE_FULL,
    TOKEN_ENV,
    WS_SUBPROTOCOL,
    WS_TOKEN_PREFIX,
    WS_UNAUTHORIZED_CLOSE_CODE,
    read_token,
)
from pwnproxy.shared.ports import DEFAULT_API_BASE

#: Default timeout for a local API call, in seconds.
DEFAULT_TIMEOUT = 10.0

#: What the user has to run to see the token again. Shared by every client and by
#: both transports, so HTTP and WebSocket failures ask for the same thing.
TOKEN_HELP = "run 'pwnproxy api token' in another terminal to see the token"

__all__ = [
    "DEFAULT_TIMEOUT",
    "TOKEN_HELP",
    "api_headers",
    "auth_error_message",
    "create_api_client",
    "create_sync_api_client",
    "websocket_error_message",
    "websocket_subprotocols",
]


def api_headers(scope: str = SCOPE_FULL) -> dict[str, str]:
    """Return the auth headers for ``scope`` (empty when there is no token).

    Args:
        scope: ``"full"`` (``api-token``/env) or ``"agent"`` (``mcp-token``).

    Returns:
        ``{"Authorization": "Bearer <token>"}``, or ``{}`` when no token is
        configured — the API then answers ``401``/``503`` and the caller shows
        the real error instead of a fake success.
    """
    token = read_token(scope)
    return {"Authorization": f"Bearer {token}"} if token else {}


def websocket_subprotocols(scope: str = SCOPE_FULL) -> list[str]:
    """Return the subprotocols a client must offer to open a WebSocket.

    Args:
        scope: Which token to offer (``"full"`` for the TUI, ``"agent"`` for the
            MCP).

    Returns:
        ``["pwnproxy", "pwnproxy-token.<token>"]``, or just ``["pwnproxy"]``
        when no token is configured (the server closes with ``4401``).
    """
    token = read_token(scope)
    if not token:
        return [WS_SUBPROTOCOL]
    return [WS_SUBPROTOCOL, f"{WS_TOKEN_PREFIX}{token}"]


def create_api_client(
    base_url: str | None = None,
    scope: str = SCOPE_FULL,
    timeout: float = DEFAULT_TIMEOUT,
    **kwargs,
) -> httpx.AsyncClient:
    """Build an ``httpx.AsyncClient`` pointed at the API, with the token set.

    Args:
        base_url: Overrides :data:`pwnproxy.shared.ports.DEFAULT_API_BASE`.
        scope: Which token to send (``"full"`` by default).
        timeout: Per-request timeout in seconds.
        **kwargs: Forwarded to ``httpx.AsyncClient`` (``transport``, ``headers``…).

    Returns:
        A client whose default headers carry ``Authorization: Bearer``.
    """
    headers = {**api_headers(scope), **kwargs.pop("headers", {})}
    return httpx.AsyncClient(base_url=base_url or DEFAULT_API_BASE, timeout=timeout, headers=headers, **kwargs)


def create_sync_api_client(
    base_url: str | None = None,
    scope: str = SCOPE_FULL,
    timeout: float = DEFAULT_TIMEOUT,
    **kwargs,
) -> httpx.Client:
    """Synchronous twin of :func:`create_api_client` (CLI, scripts).

    Same arguments and semantics; returns an ``httpx.Client``.
    """
    headers = {**api_headers(scope), **kwargs.pop("headers", {})}
    return httpx.Client(base_url=base_url or DEFAULT_API_BASE, timeout=timeout, headers=headers, **kwargs)


def auth_error_message(response: httpx.Response) -> str | None:
    """Return a plain-language message when ``response`` rejects the token.

    Clients call this *before* they decide what to do with a status they do not
    expect: a ``401`` means "the token is wrong, here is how to see it", not "the
    API is broken", and that sentence has to be the same everywhere.

    Args:
        response: Response of any API call.

    Returns:
        ``None`` for every status the caller handles itself, otherwise:

        * ``401`` — the token is missing, wrong or rotated: say how to see it.
        * ``503`` — the API has no token at all (files deleted): say how to
          recreate it.
    """
    if response.status_code == 401:
        return (
            f"API rejected the token (401) — {TOKEN_HELP}, then restart the app. "
            "If it was rotated, run 'pwnproxy api token --rotate' first."
        )
    if response.status_code == 503:
        return (
            "The API has no token configured (503) — run 'pwnproxy api token': "
            "it creates the token file the API expects."
        )
    return None


def websocket_error_message(close_code: int | None, detail: str) -> str:
    """Return the message for a failed WebSocket connection.

    Args:
        close_code: Close code the server sent, when it sent one (``4401`` means
            the token is missing or invalid).
        detail: Fallback description of the failure (``host:port - error``).

    Returns:
        A message that names the fix for a ``4401`` and passes ``detail`` through
        unchanged for any other failure. When ``PWNPROXY_API_TOKEN`` is set the
        message says so: that value wins over the file, so editing the file does
        not fix the rejection.
    """
    if close_code == WS_UNAUTHORIZED_CLOSE_CODE:
        message = f"API rejected the WebSocket token (close {WS_UNAUTHORIZED_CLOSE_CODE}) — {TOKEN_HELP}"
        if (os.environ.get(TOKEN_ENV) or "").strip():
            return f"{message}. {TOKEN_ENV} is set: it wins over the token file."
        return f"{message}, then restart the app."
    return detail

