"""The dashboard's two WebSocket streams, authenticated by subprotocol.

The browser cannot set headers on a ``WebSocket`` and the TUI could, but the
server accepts exactly one way: the token travels in
``Sec-WebSocket-Protocol`` as ``pwnproxy-token.<token>`` (see
``pwnproxy.shared.api_token``), and a missing or invalid token is answered with
close code ``4401``. Both streams therefore offer
:func:`pwnproxy.shared.api_client.websocket_subprotocols`, and a ``4401`` is
reported through ``on_error`` with the command that fixes it — not as a silent
retry loop.

Retries are unchanged: any other failure keeps the exponential backoff and calls
``on_error`` with the connection detail.
"""

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Callable

import websockets
from websockets.exceptions import WebSocketException

from apps.terminal.tui.api import websocket_error_message
from pwnproxy.shared.api_client import websocket_subprotocols
from pwnproxy.shared.api_token import WS_UNAUTHORIZED_CLOSE_CODE

logger = logging.getLogger(__name__)

WS_RETRY_DELAY = 2.0
WS_MAX_RETRY = 60.0


def _close_code(exc: BaseException) -> int | None:
    """Return the WebSocket close code carried by ``exc``, when there is one.

    ``websockets`` exposes it as ``ConnectionClosed.code``; ``getattr`` keeps the
    helper working with the plain ``OSError``/``WebSocketException`` this module
    also catches (and with a fake exception in the tests).
    """
    code = getattr(exc, "code", None)
    return code if isinstance(code, int) else None


async def _stream(
    url: str,
    label: str,
    retry_delay: float,
    max_retry: float,
    on_error: Callable[[str], None] | None,
) -> AsyncIterator[dict]:
    """Yield decoded messages from ``url``, reconnecting forever.

    Args:
        url: ``ws://`` URL of the stream.
        label: Short name used in the log lines (``traffic``, ``findings``).
        retry_delay: First retry delay, in seconds.
        max_retry: Cap for the exponential backoff, in seconds.
        on_error: Optional callback; receives a message that a human can act on
            (a ``4401`` says how to see the token, anything else names the
            connection error).

    Yields:
        One decoded JSON object per message.
    """
    retry = retry_delay
    while True:
        try:
            async with websockets.connect(
                url,
                subprotocols=websocket_subprotocols(),
                ping_interval=20,
            ) as ws:
                retry = retry_delay
                async for raw in ws:
                    try:
                        yield json.loads(raw)
                    except json.JSONDecodeError:
                        logger.warning("%s ws: invalid json", label)
        except (OSError, WebSocketException) as e:
            code = _close_code(e)
            detail = f"{url} - {e}"
            logger.debug("%s ws: %s (retry %.0fs)", label, detail, retry)
            if on_error:
                on_error(websocket_error_message(code, detail))
            await asyncio.sleep(retry)
            retry = min(retry * 1.5, max_retry)


async def stream_traffic(
    host: str,
    api_port: int,
    on_error: Callable[[str], None] | None = None,
) -> AsyncIterator[dict]:
    """Stream ``/ws/traffic`` (proxy flows as they are stored).

    A ``4401`` close means the token was missing or invalid: ``on_error``
    receives the command that shows it (``pwnproxy api token``) and the stream
    keeps retrying, so the dashboard recovers once the token is fixed.
    """
    url = f"ws://{host}:{api_port}/ws/traffic"
    async for message in _stream(
        url, "traffic", WS_RETRY_DELAY, WS_MAX_RETRY, on_error
    ):
        yield message


async def stream_findings(
    host: str,
    api_port: int,
    on_error: Callable[[str], None] | None = None,
) -> AsyncIterator[dict]:
    """Stream ``/ws/findings``; same authentication and error rules as traffic."""
    url = f"ws://{host}:{api_port}/ws/findings"
    async for message in _stream(
        url, "findings", WS_RETRY_DELAY, WS_MAX_RETRY, on_error
    ):
        yield message


__all__ = [
    "WS_MAX_RETRY",
    "WS_RETRY_DELAY",
    "WS_UNAUTHORIZED_CLOSE_CODE",
    "stream_findings",
    "stream_traffic",
]
