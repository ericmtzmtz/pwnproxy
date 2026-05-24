import asyncio
import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class HookBus:
    """Async event bus for proxy lifecycle events."""
    
    ALLOWED_HOOK_TYPES = {"request", "response", "error", "done"}
    
    def __init__(self, maxsize: int = 1000):
        self.maxsize = maxsize
        self._subscribers: Dict[str, List[asyncio.Queue]] = {
            hook_type: [] for hook_type in self.ALLOWED_HOOK_TYPES
        }
        self._scope_filter: Optional[Callable[[Any], bool]] = None

    def set_scope_filter(self, filter_fn: Optional[Callable[[Any], bool]]) -> None:
        self._scope_filter = filter_fn

    def register(self, hook_type: str) -> asyncio.Queue:
        """Register a subscriber for a specific hook type."""
        if hook_type not in self.ALLOWED_HOOK_TYPES:
            raise ValueError(f"Unknown hook type: {hook_type}")
        
        queue = asyncio.Queue(maxsize=self.maxsize)
        self._subscribers[hook_type].append(queue)
        return queue

    def publish(self, hook_type: str, flow: Any) -> None:
        """Publish a flow to all subscribers of the hook type."""
        if hook_type not in self.ALLOWED_HOOK_TYPES:
            raise ValueError(f"Unknown hook type: {hook_type}")

        if self._scope_filter and not self._scope_filter(flow):
            return
            
        for queue in self._subscribers[hook_type]:
            try:
                queue.put_nowait(flow)
            except asyncio.QueueFull:
                # Drop oldest item to make room
                try:
                    queue.get_nowait()
                    queue.put_nowait(flow)
                    logger.warning(f"HookBus queue overflow for '{hook_type}'. Dropped oldest event.")
                except asyncio.QueueEmpty:
                    # Should be impossible, but handle just in case
                    pass
