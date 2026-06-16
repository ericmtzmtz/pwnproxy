import asyncio
import logging
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class HookBus:
    """Async event bus with dynamic channel registration."""

    def __init__(self, maxsize: int = 1000):
        self.maxsize = maxsize
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}
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

    def register(self, channel_name: str) -> asyncio.Queue:
        self.register_channel(channel_name)
        queue = asyncio.Queue(maxsize=self.maxsize)
        self._subscribers[channel_name].append(queue)
        self._subscriber_counts[channel_name] += 1
        pending = self._pending.pop(channel_name, [])
        for msg in pending:
            try:
                queue.put_nowait(msg)
            except asyncio.QueueFull:
                try:
                    queue.get_nowait()
                    queue.put_nowait(msg)
                except asyncio.QueueEmpty:
                    pass
        return queue

    def publish(self, channel_name: str, data: Any) -> None:
        if channel_name not in self._subscribers or self._subscriber_counts.get(channel_name, 0) == 0:
            self._pending.setdefault(channel_name, []).append(data)
            if channel_name not in self._warned_channels:
                logger.warning(f"Publishing to empty channel '{channel_name}'")
                self._warned_channels.add(channel_name)
            return

        for queue in self._subscribers[channel_name]:
            try:
                queue.put_nowait(data)
            except asyncio.QueueFull:
                try:
                    queue.get_nowait()
                    queue.put_nowait(data)
                    logger.warning(f"HookBus queue overflow for '{channel_name}'")
                except asyncio.QueueEmpty:
                    pass

    def get_subscriber_count(self, channel_name: str) -> int:
        return self._subscriber_counts.get(channel_name, 0)

    def get_channel_stats(self) -> Dict[str, int]:
        return dict(self._subscriber_counts)

    def has_subscribers(self, channel_name: str) -> bool:
        return self._subscriber_counts.get(channel_name, 0) > 0
