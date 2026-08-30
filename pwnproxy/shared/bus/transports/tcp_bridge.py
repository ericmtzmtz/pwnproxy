from __future__ import annotations

import asyncio
import json
import logging
from asyncio import StreamReader, StreamWriter
from typing import Any, Callable, Optional

from pwnproxy.shared.bus.qos import QoSClassifiedQueue
from pwnproxy.shared.bus.topics import QoSClass, TOPIC_QOS, DEFAULT_QOS

logger = logging.getLogger(__name__)


class _ClientQueues:
    """Per-client QoS queue set + consumer task."""

    __slots__ = ("critical", "important", "best_effort", "_task", "_writer")

    def __init__(self, writer: StreamWriter) -> None:
        self.critical = QoSClassifiedQueue(QoSClass.CRITICAL)
        self.important = QoSClassifiedQueue(QoSClass.IMPORTANT)
        self.best_effort = QoSClassifiedQueue(QoSClass.BEST_EFFORT)
        self._task: asyncio.Task | None = None
        self._writer = writer

    def enqueue(self, topic: str, data: dict, qos: QoSClass) -> bool:
        if qos == QoSClass.CRITICAL:
            return self.critical.put_nowait(topic, data)
        if qos == QoSClass.IMPORTANT:
            return self.important.put_nowait(topic, data)
        return self.best_effort.put_nowait(topic, data)

    @property
    def total_qsize(self) -> int:
        return self.critical.qsize + self.important.qsize + self.best_effort.qsize

    @property
    def total_dropped(self) -> int:
        return self.critical.dropped + self.important.dropped + self.best_effort.dropped

    @property
    def total_coalesced(self) -> int:
        return self.critical.coalesced + self.important.coalesced + self.best_effort.coalesced

    def close(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()


class TcpBridgeServer:
    """TCP server that sends published events to connected clients as JSON lines.

    Events are classified by QoS (from topics.TOPIC_QOS) and routed to per-client
    bounded queues. A consumer task drains each queue with policies:

    - CRITICAL: retry in-memory with backoff; never dropped by policy.
    - IMPORTANT: coalesce by key (latest value per key wins).
    - BEST_EFFORT: drop on full with metrics.

    The producer (publish()) never blocks.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self._host = host
        self._port = port
        self._server: Optional[asyncio.AbstractServer] = None
        self._client_queues: dict[StreamWriter, _ClientQueues] = {}
        self._lock = asyncio.Lock()

    @property
    def port(self) -> int:
        return self._port

    @property
    def clients(self) -> int:
        return len(self._client_queues)

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._on_connect, self._host, self._port)
        self._port = self._server.sockets[0].getsockname()[1]
        logger.info("TcpBridgeServer listening on %s:%s", self._host, self._port)
        return self._port

    async def stop(self) -> None:
        # Stop all consumer tasks
        async with self._lock:
            for cq in self._client_queues.values():
                cq.close()
            self._client_queues.clear()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def publish(self, topic: str, data: dict) -> None:
        """Publish event to all connected clients. Non-blocking."""
        qos = TOPIC_QOS.get(topic, DEFAULT_QOS)
        async with self._lock:
            dead: set[StreamWriter] = set()
            for writer, cq in self._client_queues.items():
                if writer.is_closing():
                    dead.add(writer)
                    continue
                cq.enqueue(topic, data, qos)
            for w in dead:
                cq = self._client_queues.pop(w, None)
                if cq:
                    cq.close()

    async def _on_connect(self, reader: StreamReader, writer: StreamWriter) -> None:
        cq = _ClientQueues(writer)
        async with self._lock:
            self._client_queues[writer] = cq
        cq._task = asyncio.create_task(self._consume(reader, writer, cq))
        try:
            # Keep connection alive — client sends heartbeat newlines
            while True:
                line = await reader.readline()
                if not line:
                    break
        except Exception:
            pass
        finally:
            cq.close()
            async with self._lock:
                self._client_queues.pop(writer, None)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _consume(
        self, reader: StreamReader, writer: StreamWriter, cq: _ClientQueues
    ) -> None:
        """Consumer loop: drain all 3 QoS queues, write JSON lines to client.

        Priority: CRITICAL > IMPORTANT > BEST_EFFORT. Aging prevents
        starvation: after _STARVATION_LIMIT consecutive cycles where a
        lower-priority queue was ready but skipped, it gets forced serve.
        Uses non-blocking peek + selective dequeue to avoid event loss.
        """
        _STARVATION_LIMIT = 4
        starve_i = 0
        starve_b = 0
        log_every = 0
        try:
            while not writer.is_closing():
                # Non-blocking check which queues have data
                c_has = cq.critical.has_data
                i_has = cq.important.has_data
                b_has = cq.best_effort.has_data

                if not (c_has or i_has or b_has):
                    await asyncio.sleep(0.1)
                    cq.critical.retry_tick()
                    starve_i = 0
                    starve_b = 0
                    continue

                # Aging: increment starve counter when lower-priority ready
                # but CRITICAL also ready (would win without aging)
                starve_i = (starve_i + 1) if (i_has and c_has) else 0
                starve_b = (starve_b + 1) if (b_has and c_has) else 0

                # Select queue with aging, then dequeue from it.
                # Note: QoSClassifiedQueue.get() has its own internal timeout
                # (0.5s) and retries, so we don't wrap it with wait_for.
                topic: str | None = None
                data: dict | None = None
                try:
                    if i_has and starve_i >= _STARVATION_LIMIT:
                        topic, data = await cq.important.get()
                        starve_i = 0
                    elif b_has and starve_b >= _STARVATION_LIMIT:
                        topic, data = await cq.best_effort.get()
                        starve_b = 0
                    elif c_has:
                        topic, data = await cq.critical.get()
                    elif i_has:
                        topic, data = await cq.important.get()
                    elif b_has:
                        topic, data = await cq.best_effort.get()
                except asyncio.TimeoutError:
                    # Queue appeared ready but timed out — race between
                    # has_data check and get(). Safe to skip.
                    continue
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.debug("TcpBridge dequeue unexpected error: %s", exc, exc_info=True)
                    continue

                if topic is None:
                    continue

                # Advance retry buffer on every dequeue cycle
                cq.critical.retry_tick()

                # Build and send payload (including qos_class for wire visibility)
                qos_class = TOPIC_QOS.get(topic, DEFAULT_QOS).value
                payload = (
                    json.dumps(
                        {"topic": topic, "data": data, "qos_class": qos_class},
                        default=str,
                    )
                    + "\n"
                ).encode()
                try:
                    writer.write(payload)
                    await writer.drain()
                except Exception:
                    logger.debug("TcpBridge client write failed, dropping event")
                    break  # _on_connect will clean up

                # Periodic metrics log (every 200 events per client)
                log_every += 1
                if log_every >= 200:
                    log_every = 0
                    total_dropped = cq.total_dropped
                    total_coalesced = cq.total_coalesced
                    if total_dropped or total_coalesced:
                        logger.info(
                            "TcpBridge queue metrics: qsize=%d dropped=%d coalesced=%d "
                            "(c=%d/%d i=%d/%d b=%d/%d)",
                            cq.total_qsize,
                            total_dropped,
                            total_coalesced,
                            cq.critical.qsize, cq.critical.maxsize,
                            cq.important.qsize, cq.important.maxsize,
                            cq.best_effort.qsize, cq.best_effort.maxsize,
                        )
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.debug("TcpBridge consumer error: %s", exc)


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
