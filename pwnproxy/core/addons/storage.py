import asyncio
import logging
from typing import Callable, Optional
import mitmproxy.http
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.core.db import FlowRecord
from pwnproxy.core.models import Flow

logger = logging.getLogger(__name__)


class StorageAddon:
    """Mitmproxy addon that persists completed flows to SQLite asynchronously."""

    def __init__(self, db_engine: AsyncEngine, scope_filter: Optional[Callable[[Flow], bool]] = None, hook_bus=None, capture_enabled_fn: Optional[Callable[[], bool]] = None):
        self.db_engine = db_engine
        self.scope_filter = scope_filter
        self.hook_bus = hook_bus
        self._capture_enabled_fn = capture_enabled_fn
        self.session_factory = sessionmaker(
            self.db_engine, class_=AsyncSession, expire_on_commit=False
        )
        self._background_tasks = set()

    def response(self, f: mitmproxy.http.HTTPFlow):
        try:
            if self._capture_enabled_fn and not self._capture_enabled_fn():
                return
            pwn_flow = Flow.from_mitmproxy(f)
            if self.scope_filter and not self.scope_filter(pwn_flow):
                return
            task = asyncio.create_task(self._store_flow(pwn_flow))
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)
        except Exception as e:
            logger.error(f"StorageAddon.response() error: {e}", exc_info=True)

    async def _store_flow(self, flow: Flow) -> None:
        try:
            record = FlowRecord(
                method=flow.method,
                url=flow.url,
                request_headers=flow.request_headers,
                request_body=flow.request_body,
                request_body_truncated=flow.request_body_truncated,
                status_code=flow.status_code,
                response_headers=flow.response_headers,
                response_body=flow.response_body,
                response_body_truncated=flow.response_body_truncated,
                duration_ms=flow.duration_ms,
                error=flow.error,
                tls=flow.tls,
            )
            
            async with self.session_factory() as session:
                session.add(record)
                await session.commit()
                db_id = record.id

            if self.hook_bus:
                self.hook_bus.publish("flow_stored", {
                    "id": db_id,
                    "method": flow.method,
                    "url": flow.url,
                    "status_code": flow.status_code,
                })
        except Exception as e:
            logger.error(f"Failed to store flow {flow.id}: {e}", exc_info=True)
