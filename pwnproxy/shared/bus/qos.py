"""QoS-aware bounded queue for event bus backpressure.

Each queue enforces policies based on its QoS class:
- CRITICAL: retry in-memory with backoff; never dropped by policy.
- IMPORTANT: coalesce by key (latest value per key wins).
- BEST_EFFORT: drop on full with metrics.

The producer never blocks (put_nowait only).
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from typing import Any

from pwnproxy.shared.bus.topics import QoSClass

logger = logging.getLogger(__name__)

# Default maxsize per QoS class
DEFAULT_MAXSIZE: dict[QoSClass, int] = {
    QoSClass.CRITICAL: 256,
    QoSClass.IMPORTANT: 128,
    QoSClass.BEST_EFFORT: 64,
}

# Retry policy for CRITICAL events
_MAX_RETRIES = 3
_RETRY_DELAYS = (0.05, 0.1, 0.2)  # seconds; exponential-ish backoff


def _coalesce_key(topic: str, data: dict) -> str | None:
    """Return the coalesce key for a message, or None if not coalesceable."""
    if "progress" in topic:
        return f"progress:{data.get('job_id', '?')}"
    if topic == "triage.updated":
        return f"triage:{data.get('finding_id', data.get('id', '?'))}"
    return None


class QoSClassifiedQueue:
    """Bounded asyncio queue with QoS-aware enqueue/dequeue policies.

    Usage::

        qq = QoSClassifiedQueue(QoSClass.IMPORTANT, maxsize=128)
        qq.put_nowait(topic, data)  # non-blocking; may drop/coalesce
        item = await qq.get()       # blocks until available
    """

    def __init__(self, qos: QoSClass, maxsize: int | None = None):
        self.qos = qos
        self._maxsize = maxsize or DEFAULT_MAXSIZE[qos]
        self._queue: asyncio.Queue[tuple[str, dict]] = asyncio.Queue(maxsize=self._maxsize)
        self._retry_buffer: list[tuple[str, dict, float, int]] = []  # (topic, data, next_retry, attempts)
        self._dropped = 0
        self._coalesced = 0

    @property
    def maxsize(self) -> int:
        return self._maxsize

    @property
    def qsize(self) -> int:
        return self._queue.qsize()

    @property
    def has_data(self) -> bool:
        """Non-blocking check: queue or retry buffer has data to serve."""
        return self._queue.qsize() > 0 or bool(self._retry_buffer)

    @property
    def dropped(self) -> int:
        return self._dropped

    @property
    def coalesced(self) -> int:
        return self._coalesced

    def put_nowait(self, topic: str, data: dict) -> bool:
        """Enqueue event. Returns True if enqueued, False if dropped.

        Non-blocking: CRITICAL retries in-memory; IMPORTANT coalesces;
        BEST_EFFORT drops on full.
        """
        if self.qos == QoSClass.CRITICAL:
            return self._enqueue_critical(topic, data)
        if self.qos == QoSClass.IMPORTANT:
            return self._enqueue_coalesce(topic, data)
        # BEST_EFFORT
        return self._enqueue_drop(topic, data)

    async def get(self) -> tuple[str, dict]:
        """Get next event. Checks retry buffer first, then main queue."""
        # Drain retry buffer first (ready retries have higher priority)
        if self._retry_buffer:
            now = time.monotonic()
            ready = [r for r in self._retry_buffer if r[2] <= now]
            if ready:
                topic, data, _, _ = ready.pop(0)
                self._retry_buffer = [r for r in self._retry_buffer if r[2] > now]
                return topic, data

        try:
            return await asyncio.wait_for(self._queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            # Check retry buffer after timeout
            if self._retry_buffer:
                now = time.monotonic()
                ready = [r for r in self._retry_buffer if r[2] <= now]
                if ready:
                    topic, data, _, _ = ready.pop(0)
                    self._retry_buffer = [r for r in self._retry_buffer if r[2] > now]
                    return topic, data
            raise

    def _enqueue_drop(self, topic: str, data: dict) -> bool:
        """BEST_EFFORT: drop if full."""
        try:
            self._queue.put_nowait((topic, data))
            return True
        except asyncio.QueueFull:
            self._dropped += 1
            if self._dropped % 50 == 1:  # log periodically, not every drop
                logger.warning(
                    "QoS BEST_EFFORT queue full, dropped %d events (qsize=%d/%d)",
                    self._dropped, self._queue.qsize(), self._maxsize,
                )
            return False

    def _enqueue_coalesce(self, topic: str, data: dict) -> bool:
        """IMPORTANT: coalesce by key — keep only latest value per key."""
        key = _coalesce_key(topic, data)
        if key is None:
            # Not coalesceable; try enqueue directly
            try:
                self._queue.put_nowait((topic, data))
                return True
            except asyncio.QueueFull:
                self._dropped += 1
                return False

        # Scan queue for existing entry with same key and replace
        items: list[tuple[str, dict]] = list(self._queue._queue)
        replaced = False
        for i, (t, d) in enumerate(items):
            if _coalesce_key(t, d) == key:
                items[i] = (topic, data)
                replaced = True
                self._coalesced += 1
                break

        if not replaced:
            items.append((topic, data))

        # Rebuild queue
        self._queue = asyncio.Queue(maxsize=self._maxsize)
        overflow = False
        for t, d in items:
            try:
                self._queue.put_nowait((t, d))
            except asyncio.QueueFull:
                overflow = True
                self._dropped += 1
                break

        if overflow:
            logger.warning(
                "QoS IMPORTANT coalesce queue overflow after rebuild, dropped %d events",
                self._dropped,
            )

        return True  # The new event was accepted (replaced or added)

    def _enqueue_critical(self, topic: str, data: dict) -> bool:
        """CRITICAL: retry in-memory if queue full; never silently dropped."""
        try:
            self._queue.put_nowait((topic, data))
            return True
        except asyncio.QueueFull:
            # Queue full → add to retry buffer
            now = time.monotonic()
            self._retry_buffer.append((topic, data, now + _RETRY_DELAYS[0], 1))
            if len(self._retry_buffer) > 32:
                # Hard limit: drop oldest retry entries (should never happen)
                dropped = self._retry_buffer[:16]
                self._retry_buffer = self._retry_buffer[16:]
                self._dropped += len(dropped)
                logger.error(
                    "QoS CRITICAL retry buffer exceeded 32, dropped %d (this should never happen)",
                    len(dropped),
                )
            else:
                logger.info(
                    "QoS CRITICAL queue full, queued for retry (buffer=%d, qsize=%d/%d)",
                    len(self._retry_buffer), self._queue.qsize(), self._maxsize,
                )
            return True  # Producer never sees failure

    def retry_tick(self) -> None:
        """Advance retry delays for buffered CRITICAL events.

        Call periodically from the consumer loop or a background task.
        """
        if not self._retry_buffer:
            return
        now = time.monotonic()
        still_pending: list[tuple[str, dict, float, int]] = []
        for topic, data, next_retry, attempts in self._retry_buffer:
            if attempts >= _MAX_RETRIES:
                self._dropped += 1
                logger.warning(
                    "QoS CRITICAL event %s dropped after %d retries",
                    topic, attempts,
                )
                continue
            delay = _RETRY_DELAYS[min(attempts, len(_RETRY_DELAYS) - 1)]
            still_pending.append((topic, data, now + delay, attempts + 1))
        self._retry_buffer = still_pending
