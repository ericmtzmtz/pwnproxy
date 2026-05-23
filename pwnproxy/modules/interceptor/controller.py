import asyncio
import copy
import logging
from dataclasses import dataclass
from typing import Callable, Optional

from pwnproxy.core.models import Flow
from pwnproxy.modules.interceptor.addon import InterceptorAddon

logger = logging.getLogger(__name__)


@dataclass
class FlowSnapshot:
    """Immutable snapshot of a flow at intercept time, used for diff comparison."""
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: Optional[bytes]
    status_code: Optional[int]
    response_headers: Optional[dict[str, str]]
    response_body: Optional[bytes]

    @classmethod
    def from_flow(cls, flow: Flow) -> "FlowSnapshot":
        return cls(
            method=flow.method,
            url=flow.url,
            request_headers=copy.deepcopy(flow.request_headers),
            request_body=flow.request_body,
            status_code=flow.status_code,
            response_headers=copy.deepcopy(flow.response_headers)
            if flow.response_headers else None,
            response_body=flow.response_body,
        )


class InterceptorController:
    """Manages intercepted flows: queuing, display dispatch, user actions."""

    def __init__(self, addon: InterceptorAddon, on_intercepted: Callable[[Flow], None]):
        self._addon = addon
        self._on_intercepted = on_intercepted
        self._pending: dict[str, Flow] = {}
        self._snapshots: dict[str, FlowSnapshot] = {}
        self._consumer_task: Optional[asyncio.Task] = None

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    @property
    def enabled(self) -> bool:
        return self._addon.enabled

    def start(self) -> None:
        self._consumer_task = asyncio.create_task(self._consume_loop())

    def stop(self) -> None:
        if self._consumer_task:
            self._consumer_task.cancel()
            self._consumer_task = None

    async def _consume_loop(self) -> None:
        while True:
            try:
                flow: Flow = await self._addon._output_queue.get()
                self._handle_intercepted(flow)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Interceptor consume error: {e}", exc_info=True)

    def _handle_intercepted(self, flow: Flow) -> None:
        self._pending[flow.id] = flow
        self._snapshots[flow.id] = FlowSnapshot.from_flow(flow)
        self._on_intercepted(flow)

    def forward(self, flow_id: str) -> None:
        self._addon.resume(flow_id)
        self._pending.pop(flow_id, None)
        self._snapshots.pop(flow_id, None)

    def forward_with_edits(self, flow_id: str, edited: Flow) -> None:
        mflow = self._addon.resume(flow_id)
        if mflow is None:
            return
        if mflow.request:
            mflow.request.method = edited.method
            mflow.request.url = edited.url
            mflow.request.headers.clear()
            for k, v in edited.request_headers.items():
                mflow.request.headers[k] = v
            mflow.request.content = edited.request_body
        if mflow.response and edited.status_code is not None:
            mflow.response.status_code = edited.status_code
            mflow.response.headers.clear()
            if edited.response_headers:
                for k, v in edited.response_headers.items():
                    mflow.response.headers[k] = v
            mflow.response.content = edited.response_body
        self._pending.pop(flow_id, None)
        self._snapshots.pop(flow_id, None)

    def drop(self, flow_id: str) -> None:
        self._addon.kill(flow_id)
        self._pending.pop(flow_id, None)
        self._snapshots.pop(flow_id, None)

    def toggle(self) -> None:
        new_state = not self._addon.enabled
        self._addon.set_enabled(new_state)
        if not new_state:
            self._addon.resume_all()
            self._pending.clear()
            self._snapshots.clear()
        logger.info(f"Interceptor toggled {'ON' if new_state else 'OFF'}")

    def get_snapshot(self, flow_id: str) -> Optional[FlowSnapshot]:
        return self._snapshots.get(flow_id)
