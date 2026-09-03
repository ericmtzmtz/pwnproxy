from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Any

from pwnproxy.shared.bus import Envelope, MessageBus
from pwnproxy.shared.bus.qos import QoSClassifiedQueue
from pwnproxy.shared.bus.topics import DEFAULT_QOS, HOOKBUS_QOS

logger = logging.getLogger(__name__)


class InProcessBus(MessageBus):
    """In-process topic bus with per-subscriber bounded QoS queues.

    Each subscriber owns a ``QoSClassifiedQueue`` whose class comes from the
    topic's QoS mapping. Publishing is non-blocking (``put_nowait``): a slow
    consumer never stalls the producer — BEST_EFFORT events may drop under
    pressure, IMPORTANT coalesce, CRITICAL retry in-memory until drained.
    """

    def __init__(self):
        self._subscribers: dict[str, list[QoSClassifiedQueue]] = {}

    async def publish(self, topic: str, data: Any, *, source: str = "") -> None:
        for q in self._subscribers.get(topic, []):
            q.put_nowait(topic, data)

    def subscribe(self, topic: str) -> AsyncIterator[Envelope]:
        qos = HOOKBUS_QOS.get(topic, DEFAULT_QOS)
        q: QoSClassifiedQueue = QoSClassifiedQueue(qos)
        self._subscribers.setdefault(topic, []).append(q)
        return self._iter_queue(q)

    async def _iter_queue(self, q: QoSClassifiedQueue) -> AsyncIterator[Envelope]:
        try:
            while True:
                try:
                    topic, data = await q.get()
                except asyncio.TimeoutError:
                    # Empty period — QoS get raises ~every 0.5s; keep blocking
                    # so `async for` waits for the next event (Queue contract).
                    continue
                yield Envelope(topic=topic, data=data)
        except asyncio.CancelledError:
            pass

    def subscriber_count(self, topic: str) -> int:
        return len(self._subscribers.get(topic, []))
