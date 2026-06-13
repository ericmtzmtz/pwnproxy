import asyncio
import json
import logging
from typing import AsyncIterator, Callable, Optional

import websockets

logger = logging.getLogger(__name__)

WS_RETRY_DELAY = 2.0
WS_MAX_RETRY = 60.0


async def stream_traffic(
    host: str,
    api_port: int,
    on_error: Optional[Callable[[str], None]] = None,
) -> AsyncIterator[dict]:
    url = f"ws://{host}:{api_port}/ws/traffic"
    retry = WS_RETRY_DELAY
    while True:
        try:
            async with websockets.connect(url, ping_interval=20) as ws:
                retry = WS_RETRY_DELAY
                async for raw in ws:
                    try:
                        yield json.loads(raw)
                    except json.JSONDecodeError:
                        logger.warning("traffic ws: invalid json")
        except (OSError, websockets.WebSocketException) as e:
            msg = f"{host}:{api_port} - {e}"
            logger.debug("traffic ws: %s (retry %.0fs)", e, retry)
            if on_error:
                on_error(msg)
            await asyncio.sleep(retry)
            retry = min(retry * 1.5, WS_MAX_RETRY)


async def stream_findings(
    host: str,
    api_port: int,
    on_error: Optional[Callable[[str], None]] = None,
) -> AsyncIterator[dict]:
    url = f"ws://{host}:{api_port}/ws/findings"
    retry = WS_RETRY_DELAY
    while True:
        try:
            async with websockets.connect(url, ping_interval=20) as ws:
                retry = WS_RETRY_DELAY
                async for raw in ws:
                    try:
                        yield json.loads(raw)
                    except json.JSONDecodeError:
                        logger.warning("findings ws: invalid json")
        except (OSError, websockets.WebSocketException) as e:
            msg = f"{host}:{api_port} - {e}"
            logger.debug("findings ws: %s (retry %.0fs)", e, retry)
            if on_error:
                on_error(msg)
            await asyncio.sleep(retry)
            retry = min(retry * 1.5, WS_MAX_RETRY)
