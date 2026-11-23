"""The API tokens: where they live, how they are created, read, rotated and checked.

There are two tokens with the same format and different reach ("scope"):

* ``api-token`` → :data:`SCOPE_FULL`: the Web UI, the TUI, the CLI, Docker, CI.
* ``mcp-token`` → :data:`SCOPE_AGENT`: the MCP server, which must not be able to
  read or write plugin credentials (the next change's routes will require
  ``full``).

Both are ``secrets.token_urlsafe(32)`` — 43 characters of ``[A-Za-z0-9_-]``, so
the value is a valid ``Sec-WebSocket-Protocol`` token without escaping anything.
The file holds the token and nothing else: a trailing newline would break
``curl -H "Authorization: Bearer $(cat …)"``.

Where: :func:`pwnproxy.shared.config_dir.config_dir` (``PWNPROXY_CONFIG_DIR`` or
``~/.pwnproxy``). ``PWNPROXY_API_TOKEN`` is an extra *``full``* token that is
never written to disk (the CI path).

The file is re-read on every authentication attempt on purpose: 43 bytes cost
microseconds and rotation becomes immediate across processes — the CLI runs in a
different process than the API, so there is no in-memory state to invalidate.
"""

from __future__ import annotations

import contextlib
import logging
import os
import secrets
import tempfile
from pathlib import Path

from pwnproxy.shared.api_acl import restrict_to_current_user
from pwnproxy.shared.config_dir import config_dir

logger = logging.getLogger(__name__)

#: File name of the ``full``-scope token.
API_TOKEN_FILE = "api-token"
#: File name of the ``agent``-scope token.
MCP_TOKEN_FILE = "mcp-token"

#: Scope of ``api-token`` and of ``PWNPROXY_API_TOKEN``.
SCOPE_FULL = "full"
#: Scope of ``mcp-token``.
SCOPE_AGENT = "agent"

#: Environment variable that adds a ``full`` token without touching the disk.
TOKEN_ENV = "PWNPROXY_API_TOKEN"

#: Entropy of a generated token, in bytes (43 characters once url-safe encoded).
TOKEN_BYTES = 32

#: Every scope known to the server, in the order they are created.
SCOPES: tuple[str, ...] = (SCOPE_FULL, SCOPE_AGENT)

#: Subprotocol the server accepts and answers (never the one carrying the token).
WS_SUBPROTOCOL = "pwnproxy"
#: Prefix of the subprotocol that carries the token: ``pwnproxy-token.<token>``.
#: The browser cannot send headers on a ``WebSocket`` and the query string ends
#: up in access logs, so the token travels here.
WS_TOKEN_PREFIX = "pwnproxy-token."
#: Close code the server uses when a WebSocket offers no valid token.
WS_UNAUTHORIZED_CLOSE_CODE = 4401

_FILE_FOR_SCOPE: dict[str, str] = {SCOPE_FULL: API_TOKEN_FILE, SCOPE_AGENT: MCP_TOKEN_FILE}

__all__ = [
    "API_TOKEN_FILE",
    "MCP_TOKEN_FILE",
    "SCOPES",
    "SCOPE_AGENT",
    "SCOPE_FULL",
    "TOKEN_BYTES",
    "TOKEN_ENV",
    "WS_SUBPROTOCOL",
    "WS_TOKEN_PREFIX",
    "WS_UNAUTHORIZED_CLOSE_CODE",
    "ensure_tokens",
    "find_token",
    "generate_token",
    "load_server_tokens",
    "read_token",
    "rotate_token",
    "scope_for",
    "token_path",
    "write_token",
]


def generate_token() -> str:
    """Return a fresh random token (``TOKEN_BYTES`` bytes, url-safe)."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def token_path(scope: str = SCOPE_FULL) -> Path:
    """Return the file that holds the token of ``scope``.

    Args:
        scope: ``"full"`` (``api-token``) or ``"agent"`` (``mcp-token``).

    Returns:
        ``<config_dir>/api-token`` or ``<config_dir>/mcp-token``.

    Raises:
        ValueError: ``scope`` is neither of the two known scopes.
    """
    try:
        name = _FILE_FOR_SCOPE[scope]
    except KeyError:
        raise ValueError(
            f"unknown token scope {scope!r}; expected one of {', '.join(SCOPES)}"
        ) from None
    return config_dir() / name


def read_token(scope: str = SCOPE_FULL) -> str | None:
    """Return the token stored for ``scope``, or ``None`` when there is none.

    The value is stripped, so a file the user edited (or a Windows editor that
    added a newline) still works. An empty file counts as "no token".
    """
    path = token_path(scope)
    try:
        content = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning("Could not read token file %s: %s", path, exc)
        return None
    return content or None


def write_token(scope: str, token: str) -> Path:
    """Write ``token`` for ``scope`` atomically and restrict the file.

    The content goes to a temporary file in the same directory and is moved over
    the destination with :func:`os.replace`, so a crash never leaves a truncated
    token. The destination is then restricted to the current user (``0600`` on
    POSIX, a single-ACE protected DACL on Windows); a refusal is logged and does
    not raise.

    Args:
        scope: ``"full"`` or ``"agent"``.
        token: Value to store; written verbatim, without a trailing newline.

    Returns:
        The path that now holds ``token``.

    Raises:
        OSError: the directory or the file cannot be written.
    """
    path = token_path(scope)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(token)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise
    restrict_to_current_user(path)
    return path


def ensure_tokens() -> dict[str, Path]:
    """Create the token files that do not exist yet and return their paths.

    Called when the API server starts — never on import and never from a GET:
    a module that creates files at import time breaks ``--help`` and every test.
    Existing tokens are **not** rotated.

    Returns:
        ``{scope: path}`` for both scopes.
    """
    paths: dict[str, Path] = {}
    for scope in SCOPES:
        path = token_path(scope)
        if read_token(scope) is None:
            write_token(scope, generate_token())
            logger.info("Created %s token file: %s", scope, path)
        paths[scope] = path
    return paths


def rotate_token(scope: str = SCOPE_FULL) -> str:
    """Generate a new token for ``scope``, write it and return it.

    The previous value stops authenticating on the next request because the
    server re-reads the file; WebSockets already open keep working (the token
    was checked during the handshake).
    """
    token = generate_token()
    write_token(scope, token)
    return token


def _token_entries() -> list[tuple[str, str, str]]:
    """Return ``(token, scope, source)`` for every configured token.

    ``source`` is ``"env"``, ``"api-token"`` or ``"mcp-token"`` — the value the
    auth layer publishes as ``request.state.token_source``. The environment
    variable comes first so it wins if it repeats a file value.
    """
    entries: list[tuple[str, str, str]] = []
    env_token = (os.environ.get(TOKEN_ENV) or "").strip()
    if env_token:
        entries.append((env_token, SCOPE_FULL, "env"))
    for scope in SCOPES:
        token = read_token(scope)
        if token:
            entries.append((token, scope, _FILE_FOR_SCOPE[scope]))
    return entries


def load_server_tokens() -> dict[str, str]:
    """Return ``{token: scope}`` for every token the server should accept.

    That is ``PWNPROXY_API_TOKEN`` (``full``) plus both files, when they exist
    and are non-empty. Nothing is created here: reading is a read.
    """
    tokens: dict[str, str] = {}
    for token, scope, _source in _token_entries():
        tokens.setdefault(token, scope)
    return tokens


def find_token(token: str | None) -> tuple[str, str] | None:
    """Return ``(scope, source)`` for a received token, or ``None``.

    The comparison is :func:`secrets.compare_digest` over the UTF-8 bytes of
    every candidate — never ``==`` and never a length shortcut. Encoding first
    keeps a non-ASCII input from raising instead of simply not matching.
    """
    if not token:
        return None
    received = token.encode("utf-8")
    for candidate, scope, source in _token_entries():
        if secrets.compare_digest(candidate.encode("utf-8"), received):
            return scope, source
    return None


def scope_for(token: str | None) -> str | None:
    """Return the scope of ``token`` (``"full"``/``"agent"``) or ``None``."""
    match = find_token(token)
    return match[0] if match else None
