"""Single source of truth for every default port pwnproxy listens on.

Why one module: the proxy, the API, the Web UI dev server, the SSRF callback
server and the Docker images all defaulted to their own copy of a number, so a
port collision could only be fixed in six places (and the Web UI kept printing
a stale one). Every surface imports from here now, and
``tests/architecture/test_ports.py`` fails if a literal sneaks back in.

The ports are high (17xxx) on purpose: on Windows the dynamic TCP range can
start as low as 1024, so the classic proxy/API ports sit inside the ephemeral
range and get taken by other processes at random.

Every value below is only a *default*. The CLI flags (``--proxy-port``,
``--api-port``, ``--callback-port``) and the environment variables
(``PWNPROXY_PROXY_PORT``, ``PWNPROXY_API_PORT``, ``WEB_PORT``,
``CALLBACK_PORT`` for Compose, ``PUBLIC_API_BASE`` for the Web UI) keep working
exactly as before.
"""

from __future__ import annotations

DEFAULT_PROXY_PORT = 17170
DEFAULT_API_PORT = 17171
DEFAULT_WEB_PORT = 17172
DEFAULT_CALLBACK_PORT = 17173

#: Host the API binds and the Web UI talks to by default.
DEFAULT_HOST = "127.0.0.1"

#: Base URL of the REST API, derived from the API port (never written twice).
DEFAULT_API_BASE = f"http://{DEFAULT_HOST}:{DEFAULT_API_PORT}/api/v1"

__all__ = [
    "DEFAULT_API_BASE",
    "DEFAULT_API_PORT",
    "DEFAULT_CALLBACK_PORT",
    "DEFAULT_HOST",
    "DEFAULT_PROXY_PORT",
    "DEFAULT_WEB_PORT",
]
