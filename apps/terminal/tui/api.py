"""The TUI's API client: one factory, and the token messages come from ``shared``.

The dashboard used to build ``http://{host}:{api_port}/api/v1/...`` by hand and
open a fresh ``httpx.AsyncClient()`` per call (nine of them in ``app.py``, the
session picker included, and two in ``scope_widget.py``). That worked while the
API had no authentication; with a bearer token it is one text field somebody
forgets to touch, and the failure mode is a bare ``401`` that looks like a broken
API.

So the TUI gets its client from here — :func:`create_client` wraps
:func:`pwnproxy.shared.api_client.create_api_client`, which reads the token
(``~/.pwnproxy/api-token`` or ``PWNPROXY_API_TOKEN``) and sets the default header.
The **messages** for a rejected credential are re-exported from
``pwnproxy.shared.api_client``: the TUI, the Intruder screen and any future client
have to say the same thing, and that sentence lives in ``shared/`` so the core
never has to import ``apps/`` to reuse it.

The token is read **once per client instance**: a rotation while the dashboard is
running makes the next request fail with ``401`` and the message says what to do
(restart the app to pick up the new token — restarting is cheap).
"""

from __future__ import annotations

import httpx

from pwnproxy.shared.api_client import (
    TOKEN_HELP,
    auth_error_message,
    create_api_client,
    websocket_error_message,
)

#: Base path the client is pointed at; every call uses a path relative to it.
API_PATH = "/api/v1"

#: Timeout of a TUI API call, in seconds (the sessions list can be slow on a
#: big database, and it is the user's own machine either way).
DEFAULT_TIMEOUT = 10.0

__all__ = [
    "API_PATH",
    "DEFAULT_TIMEOUT",
    "TOKEN_HELP",
    "api_base_url",
    "auth_error_message",
    "create_client",
    "websocket_error_message",
]


def api_base_url(host: str, api_port: int) -> str:
    """Return the API base URL for a bind host and port.

    Args:
        host: Host the API listens on (the TUI is told ``127.0.0.1``).
        api_port: API port.

    Returns:
        ``http://<host>:<port>/api/v1``.
    """
    return f"http://{host}:{api_port}{API_PATH}"


def create_client(host: str, api_port: int, timeout: float = DEFAULT_TIMEOUT) -> httpx.AsyncClient:
    """Build the TUI's ``httpx.AsyncClient``, with the token already attached.

    Args:
        host: Host the API listens on.
        api_port: API port.
        timeout: Per-request timeout in seconds.

    Returns:
        A client whose default headers carry ``Authorization: Bearer`` (empty
        when no token is configured — the API then answers ``401``/``503`` and
        the caller shows the real error).
    """
    return create_api_client(base_url=api_base_url(host, api_port), timeout=timeout)
