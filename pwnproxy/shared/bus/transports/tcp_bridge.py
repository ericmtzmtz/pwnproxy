from __future__ import annotations

import asyncio
import json
import logging
from asyncio import StreamReader, StreamWriter
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class TcpBridgeServer:
    """TCP server that sends published events to connected clients as JSON lines."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self._host = host
        self._port = port
        self._server: Optional[asyncio.AbstractServer] = None
        self._writers: set[StreamWriter] = set()
        self._lock = asyncio.Lock()

    @property
    def port(self) -> int:
        return self._port

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._on_connect, self._host, self._port)
        self._port = self._server.sockets[0].getsockname()[1]
        logger.info("TcpBridgeServer listening on %s:%s", self._host, self._port)
        return self._port

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def publish(self, topic: str, data: dict) -> None:
        payload = (json.dumps({"topic": topic, "data": data}) + "\n").encode()
        async with self._lock:
            dead: set[StreamWriter] = set()
            for w in self._writers:
                try:
                    w.write(payload)
                    await w.drain()
                except Exception:
                    dead.add(w)
            self._writers -= dead

    async def _on_connect(self, reader: StreamReader, writer: StreamWriter) -> None:
        self._writers.add(writer)
        try:
            # Keep connection alive — client sends heartbeat newlines
            while True:
                line = await reader.readline()
                if not line:
                    break
        except Exception:
            pass
        finally:
            self._writers.discard(writer)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


class TcpBridgeClient:
    """TCP client that connects to a TcpBridgeServer and forwards events to a callback."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        on_event: Optional[Callable[[str, Any], None]] = None,
    ):
        self._host = host
        self._port = port
        self._on_event = on_event
        self._task: Optional[asyncio.Task] = None

    @property
    def port(self) -> int:
        return self._port

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None

    async def _run(self) -> None:
        while True:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self._host, self._port), timeout=10
                )
                logger.info("TcpBridgeClient connected to %s:%s", self._host, self._port)
                try:
                    while True:
                        line = await reader.readline()
                        if not line:
                            logger.warning("TcpBridgeClient connection closed by server")
                            break
                        text = line.decode().strip()
                        if not text:
                            continue
                        msg = json.loads(text)
                        if self._on_event:
                            self._on_event(msg["topic"], msg["data"])
                except Exception:
                    pass
                finally:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
            except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
                logger.debug("TcpBridgeClient waiting for server...")
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("TcpBridgeClient error: %s", e)
                await asyncio.sleep(1)
