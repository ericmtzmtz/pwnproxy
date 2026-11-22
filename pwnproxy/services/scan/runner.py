"""One-shot scan runner shared by the CLI and the REST API.

Sends a single request to a target, wraps the exchange in a :class:`Flow` and
runs every scanner the loader has. It lives under ``services/`` — not in
``apps/terminal/cli/scan.py`` — because ``pwnproxy.transport.rest.tasks`` needs
it and the transport layer must not import the CLI (enforced by
``tests/architecture/test_layering.py``).

The CLI keeps a thin wrapper around this function for the console output; the
runner itself prints nothing so it is safe to call from a background task.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

import httpx

from pwnproxy.plugins.core.base import Finding
from pwnproxy.shared.models import Flow

logger = logging.getLogger(__name__)


async def scan_target(
    loader: Any,
    target: str,
    timeout: int,
    extra_headers: dict[str, str] | None = None,
    method: str = "GET",
    body: str | None = None,
) -> list[Finding]:
    """Request ``target`` once and run every loaded scanner on the flow.

    Args:
        loader: A ``PluginLoader`` with the scanners already loaded.
        target: URL to fetch.
        timeout: HTTP timeout in seconds.
        extra_headers: Headers to send on top of the ``Host`` derivation.
        method: HTTP method (already upper-cased by the caller).
        body: Raw request body; ignored by the caller for GET/HEAD.

    Returns:
        Every finding produced by the loaded scanners.

    Raises:
        httpx.HTTPError: the target could not be fetched.
    """
    start = time.monotonic()

    headers = {"host": httpx.URL(target).host or ""}
    if extra_headers:
        headers.update(extra_headers)

    body_bytes = body.encode() if body else None
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout), follow_redirects=True) as client:
        resp = await client.request(method, target, headers=headers, content=body_bytes)

    flow = Flow(
        id=str(uuid.uuid4()),
        method=method,
        url=target,
        request_headers=headers,
        request_body=body_bytes,
        status_code=resp.status_code,
        response_headers=dict(resp.headers),
        response_body=resp.content,
        duration_ms=(time.monotonic() - start) * 1000,
        tls=target.startswith("https"),
    )

    return await loader.run_scan(flow)
