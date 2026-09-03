import asyncio
import logging
from typing import Any, Callable, Dict, List, Optional, Set

from pwnproxy.shared.bus.qos import QoSClassifiedQueue
from pwnproxy.shared.bus.topics import DEFAULT_QOS, HOOKBUS_QOS

logger = logging.getLogger(__name__)

# Pending-message buffer cap for channels with no subscribers yet. Bounded so a
# publisher that outruns its first subscriber cannot grow memory without limit.
_PENDING_CAP = 200


class _HookChannelQueue:
    """Per-subscriber queue adapter: QoS enqueue + plain-data dequeue.

    HookBus is fan-out per channel (each subscriber gets every event). Each
    ``register`` creates one of these backed by a ``QoSClassifiedQueue`` whose
    class comes from the channel's QoS mapping. The channel/topic is constant
    for the whole queue, so ``get()`` unwraps and returns only the payload —
    preserving the pre-QoS contract every consumer relies on
    (``await queue.get()`` → data).
    """

    def __init__(self, channel: str, qos_queue: QoSClassifiedQueue):
        self._channel = channel
        self._q = qos_queue

    def put_nowait(self, data: Any) -> bool:
        return self._q.put_nowait(self._channel, data)

    def get_nowait(self) -> Any:
        """Non-blocking dequeue of a single payload; raises QueueEmpty if none."""
        _topic, data = self._q.get_nowait()
        return data

    async def get(self) -> Any:
        """Block until a payload is available, returning only the data.

        ``QoSClassifiedQueue.get()`` raises ``TimeoutError`` every ~0.5s while
        the queue is empty (its internal wait_for also services the CRITICAL
        retry buffer). Consumers of HookBus expect a blocking ``asyncio.Queue``
        contract, so we loop on the empty-timeout instead of propagating it.
        """
        while True:
            try:
                _topic, data = await self._q.get()
                return data
            except asyncio.TimeoutError:
                # Empty period — QoS get raises periodically; keep blocking.
                continue

    @property
    def qsize(self) -> int:
        return self._q.qsize

    @property
    def has_data(self) -> bool:
        return self._q.has_data

    @property
    def dropped(self) -> int:
        return self._q.dropped

    @property
    def coalesced(self) -> int:
        return self._q.coalesced


class HookBus:
    """Async event bus with dynamic channel registration and QoS backpressure.

    Every subscriber of a channel owns a bounded queue classified by the
    channel's QoS mapping (CRITICAL persist/retry, IMPORTANT coalesce,
    BEST_EFFORT drop). Publishing never blocks the producer and never silently
    drops CRITICAL events (they retry in-memory until the consumer drains).
    """

    def __init__(self):
        self._subscribers: Dict[str, List[_HookChannelQueue]] = {}
        self._subscriber_counts: Dict[str, int] = {}
        self._pending: Dict[str, List[Any]] = {}
        self._warned_channels: Set[str] = set()


    def set_scope_filter(self, filter_fn: Optional[Callable[[Any], bool]]) -> None:
        import warnings
        warnings.warn("HookBus.set_scope_filter() is deprecated. Use FlowFilter instead.", DeprecationWarning, stacklevel=2)


    def register_channel(self, channel_name: str) -> None:
        if channel_name not in self._subscribers:
            self._subscribers[channel_name] = []
            self._subscriber_counts[channel_name] = 0

    def register(self, channel_name: str) -> _HookChannelQueue:
        self.register_channel(channel_name)
        qos = HOOKBUS_QOS.get(channel_name, DEFAULT_QOS)
        queue = _HookChannelQueue(channel_name, QoSClassifiedQueue(qos))
        self._subscribers[channel_name].append(queue)
        self._subscriber_counts[channel_name] += 1
        pending = self._pending.pop(channel_name, [])
        for msg in pending:
            try:
                queue.put_nowait(msg)
            except Exception:
                logger.debug("could not deliver pending message to %s", channel_name, exc_info=True)
        return queue

    def publish(self, channel_name: str, data: Any) -> None:
        if channel_name not in self._subscribers or self._subscriber_counts.get(channel_name, 0) == 0:
            pending = self._pending.setdefault(channel_name, [])
            pending.append(data)
            overflow = len(pending) - _PENDING_CAP
            if overflow > 0:
                # Bounded: drop the OLDEST buffered messages (keep the newest),
                # with a metric/log.
                del pending[:overflow]
                logger.warning(
                    "HookBus pending buffer for '%s' exceeded %d; dropped %d oldest buffered message(s) (no subscriber yet)",
                    channel_name, _PENDING_CAP, overflow,
                )
            if channel_name not in self._warned_channels:
                logger.warning(f"Publishing to empty channel '{channel_name}'")
                self._warned_channels.add(channel_name)
            return

        for queue in self._subscribers[channel_name]:
            try:
                queue.put_nowait(data)
            except Exception:
                logger.debug("HookBus enqueue failed for '%s'", channel_name, exc_info=True)

    def get_subscriber_count(self, channel_name: str) -> int:
        return self._subscriber_counts.get(channel_name, 0)

    def get_channel_stats(self) -> Dict[str, int]:
        return dict(self._subscriber_counts)

    def has_subscribers(self, channel_name: str) -> bool:
        return self._subscriber_counts.get(channel_name, 0) > 0
