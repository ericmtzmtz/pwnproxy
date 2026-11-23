"""Authentication for the local API: a bearer token in HTTP, a subprotocol in WS.

The API listens on ``127.0.0.1`` and also serves ``--host 0.0.0.0``; the port was
the only thing protecting it, and any local process (or any web page pointing a
``fetch`` at ``127.0.0.1``) could stop the proxy, delete findings or launch
scans. Now every request carries ``Authorization: Bearer <token>`` except the
two paths a client needs *before* it has a token:

* ``GET /api/v1/health`` — the ``dev.ps1``/``dev.sh``/Docker probe. Returns
  nothing sensitive.
* ``/docs`` — the API reference page. It embeds the schema so it needs no
  protected ``fetch``; the list of routes is public (AGPL repository).

``OPTIONS`` (CORS preflight) carries no data and the browser cannot attach
``Authorization`` to it, so it is not authenticated either.

Failure modes, all closed:

* no token anywhere (files deleted, no ``PWNPROXY_API_TOKEN``) → ``503`` with a
  message that says how to fix it. Letting requests through would turn an
  accidental delete into an open API.
* missing/invalid token → ``401`` with a **fixed** body (never "missing" vs
  "wrong": no oracle) and ``WWW-Authenticate``.

A middleware is used instead of a ``Depends`` per router on purpose: with
fifteen routers and more coming, the route somebody forgets to decorate is a
silent hole. ``tests/api/test_auth.py`` walks ``app.routes`` and every
``WebSocketRoute`` to prove nothing was missed.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.websockets import WebSocket

from pwnproxy.shared.api_token import (
    WS_SUBPROTOCOL,
    WS_TOKEN_PREFIX,
    WS_UNAUTHORIZED_CLOSE_CODE,
    find_token,
    load_server_tokens,
)

logger = logging.getLogger(__name__)

#: Paths served **without** a token. Exact matches, each one justified above.
AUTH_EXEMPT_PATHS: frozenset[str] = frozenset({"/api/v1/health", "/docs"})

#: HTTP methods served without a token (CORS preflight).
AUTH_EXEMPT_METHODS: frozenset[str] = frozenset({"OPTIONS"})

#: Fixed body for a missing or invalid token.
MISSING_TOKEN_DETAIL = "Missing or invalid API token"

#: Fixed body when no token source exists at all.
NO_TOKEN_DETAIL = "No API token configured — run 'pwnproxy api token'"

#: Fixed body when the token's scope is too small. Never names the scope.
FORBIDDEN_SCOPE_DETAIL = "This token does not grant access to this resource"

#: Challenge header sent with every ``401``.
WWW_AUTHENTICATE = 'Bearer realm="pwnproxy"'

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class WhoamiResponse(BaseModel):
    """Answer of ``GET /api/v1/auth/whoami``."""

    scope: str


def _bearer_token(authorization: str | None) -> str | None:
    """Extract the token from an ``Authorization`` header value.

    Args:
        authorization: Raw header value, e.g. ``"Bearer abc"``.

    Returns:
        The token, or ``None`` when the header is absent, uses another scheme
        (``Basic``…) or carries an empty value.
    """
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return None
    return value.strip() or None


def _unauthorized(detail: str, status_code: int) -> JSONResponse:
    """Build the fixed error response for a failed authentication."""
    return JSONResponse(
        {"detail": detail},
        status_code=status_code,
        headers={"WWW-Authenticate": WWW_AUTHENTICATE},
    )


def authenticate_request(request: Request) -> JSONResponse | None:
    """Authenticate ``request``, publishing its scope for the handlers.

    Args:
        request: Incoming HTTP request.

    Returns:
        ``None`` when the request is authenticated (``request.state.scope`` and
        ``request.state.token_source`` are set); otherwise the response to send
        — ``503`` when there is no token configured at all, ``401`` otherwise.
    """
    match = find_token(_bearer_token(request.headers.get("authorization")))
    if match is None:
        if not load_server_tokens():
            return _unauthorized(NO_TOKEN_DETAIL, 503)
        return _unauthorized(MISSING_TOKEN_DETAIL, 401)
    scope, source = match
    request.state.scope = scope
    request.state.token_source = source
    return None


async def api_auth_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Any]]
) -> Any:
    """Starlette HTTP middleware that enforces the token on every route.

    Registered *inside* ``CORSMiddleware`` so a ``401``/``503`` still carries the
    CORS headers a browser needs to read the status (otherwise the Web UI would
    see an opaque network error instead of the ``401`` that tells it to ask for
    a token again).
    """
    if request.method in AUTH_EXEMPT_METHODS or request.url.path in AUTH_EXEMPT_PATHS:
        return await call_next(request)
    error = authenticate_request(request)
    if error is not None:
        return error
    return await call_next(request)


def require_scope(scope: str):
    """Return a dependency that rejects tokens with a smaller scope.

    Usable as ``Depends(require_scope("full"))``. Today no route uses it: the
    plugin-configuration routes of the next change will, so an ``agent`` token
    (the MCP) cannot read or write client credentials.

    Args:
        scope: Required scope, ``"full"`` or ``"agent"``.

    Returns:
        A dependency callable raising ``403`` with a fixed message.
    """

    def dependency(request: Request) -> None:
        if getattr(request.state, "scope", None) != scope:
            raise HTTPException(
                status_code=403,
                detail=FORBIDDEN_SCOPE_DETAIL,
                headers={"WWW-Authenticate": WWW_AUTHENTICATE},
            )

    return dependency


def _websocket_token(ws: WebSocket) -> str | None:
    """Return the token offered in ``Sec-WebSocket-Protocol``, if any.

    The query string is **never** read: it ends up in access logs, ``Referer``
    and shell history.
    """
    for protocol in ws.scope.get("subprotocols") or []:
        if protocol.startswith(WS_TOKEN_PREFIX):
            return protocol[len(WS_TOKEN_PREFIX):]
    return None


async def authorize_websocket(ws: WebSocket) -> bool:
    """Authenticate a WebSocket handshake and accept the connection.

    On success the socket is accepted answering the ``pwnproxy`` subprotocol
    (never the one carrying the token) and ``ws.state.scope`` is set. On failure
    the socket is accepted and immediately closed with ``4401``: accepting first
    is the convention this module already uses for the room errors (``4403``/
    ``4404``) and lets the browser see a close code instead of a generic failed
    handshake.

    Args:
        ws: The incoming WebSocket.

    Returns:
        ``True`` when authenticated (the handler may keep the connection),
        ``False`` when it was closed with ``4401`` and the handler must return.
    """
    match = find_token(_websocket_token(ws))
    if match is None:
        await ws.accept()
        await ws.close(code=WS_UNAUTHORIZED_CLOSE_CODE)
        return False
    scope, source = match
    ws.state.scope = scope
    ws.state.token_source = source
    await ws.accept(subprotocol=WS_SUBPROTOCOL)
    return True


@router.get(
    "/whoami",
    response_model=WhoamiResponse,
    summary="Scope of the token being used",
    description="Lets the MCP and the CLI diagnose 'wrong token' without guessing.",
)
async def whoami(request: Request) -> WhoamiResponse:
    """Return the scope of the token that authenticated this request."""
    scope = getattr(request.state, "scope", None)
    if scope is None:
        # Fail closed: reaching here means the middleware did not run.
        raise HTTPException(status_code=401, detail=MISSING_TOKEN_DETAIL)
    return WhoamiResponse(scope=scope)


__all__ = [
    "AUTH_EXEMPT_METHODS",
    "AUTH_EXEMPT_PATHS",
    "FORBIDDEN_SCOPE_DETAIL",
    "MISSING_TOKEN_DETAIL",
    "NO_TOKEN_DETAIL",
    "WWW_AUTHENTICATE",
    "api_auth_middleware",
    "authenticate_request",
    "authorize_websocket",
    "require_scope",
    "router",
    "whoami",
]
