import asyncio
import logging
from typing import Optional

import mitmproxy.http

from pwnproxy.core.models import Flow

logger = logging.getLogger(__name__)


class InterceptorAddon:
    """Mitmproxy addon that intercepts flows for user inspection."""

    def __init__(self, output_queue: asyncio.Queue):
        self._output_queue = output_queue
        self._intercepted: dict[str, mitmproxy.http.HTTPFlow] = {}
        self._enabled: bool = True

    @property
    def enabled(self) -> bool:
        return self._enabled

    def set_enabled(self, value: bool) -> None:
        self._enabled = value

    def request(self, f: mitmproxy.http.HTTPFlow) -> None:
        if not self._enabled:
            return
        f.intercept()
        self._intercepted[f.id] = f
        pwn_flow = Flow.from_mitmproxy(f)
        self._output_queue.put_nowait(pwn_flow)

    def response(self, f: mitmproxy.http.HTTPFlow) -> None:
        if not self._enabled:
            return
        f.intercept()
        self._intercepted[f.id] = f
        pwn_flow = Flow.from_mitmproxy(f)
        self._output_queue.put_nowait(pwn_flow)

    def resume(self, flow_id: str) -> Optional[mitmproxy.http.HTTPFlow]:
        f = self._intercepted.pop(flow_id, None)
        if f is None:
            logger.warning(f"resume: flow {flow_id} not found")
            return None
        f.resume()
        return f

    def kill(self, flow_id: str) -> Optional[mitmproxy.http.HTTPFlow]:
        f = self._intercepted.pop(flow_id, None)
        if f is None:
            logger.warning(f"kill: flow {flow_id} not found")
            return None
        f.kill()
        return f

    def resume_all(self) -> None:
        for flow_id in list(self._intercepted.keys()):
            self.resume(flow_id)

    def pending_count(self) -> int:
        return len(self._intercepted)
