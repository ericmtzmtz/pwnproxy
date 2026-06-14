from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Any

from pwnproxy.shared.bus import Envelope, MessageBus

logger = logging.getLogger(__name__)


class InProcessBus(MessageBus):
    def __init__(self):
        self._subscribers: dict[str, list[asyncio.Queue]] = {}

    async def publish(self, topic: str, data: Any, *, source: str = "") -> None:
        envelope = Envelope(topic=topic, data=data, source=source)
        for q in self._subscribers.get(topic, []):
            await q.put(envelope)

    def subscribe(self, topic: str) -> AsyncIterator[Envelope]:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(topic, []).append(q)
        return self._iter_queue(q)

    async def _iter_queue(self, q: asyncio.Queue) -> AsyncIterator[Envelope]:
        try:
            while True:
                yield await q.get()
        except asyncio.CancelledError:
            pass

    def subscriber_count(self, topic: str) -> int:
        return len(self._subscribers.get(topic, []))
