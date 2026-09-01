import asyncio
import logging
import os
from typing import Callable, Optional
import mitmproxy.http
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.shared.db import FlowRecord
from pwnproxy.shared.models import Flow

logger = logging.getLogger(__name__)

_AUTO_SCAN = os.environ.get("PWNPROXY_AUTO_SCAN", "true").lower() != "false"



class StorageAddon:
    """Mitmproxy addon that persists completed flows to SQLite asynchronously.
    
    When PWNPROXY_AUTO_SCAN=true (default), also publishes "done" events
    so scanners automatically process every captured flow.
    """

    def __init__(self, db_engine: AsyncEngine, hook_bus=None, flow_filter=None):
        self.db_engine = db_engine
        
        self.hook_bus = hook_bus
        # Optional FlowFilter gates persistence + flow_stored/done emission.
        # When None (default), all flows are stored (legacy behavior).
        self._flow_filter = flow_filter
        
        self._auto_scan = _AUTO_SCAN
        self.session_factory = sessionmaker(
            self.db_engine, class_=AsyncSession, expire_on_commit=False
        )
        self._background_tasks = set()

    def _in_scope(self, url: str) -> bool:
        if self._flow_filter is None:
            return True
        return self._flow_filter.allow(url)

    def response(self, f: mitmproxy.http.HTTPFlow):
        if not self._in_scope(f.request.url):
            logger.debug("StorageAddon: out of scope, skipping %s", f.request.url)
            return
        try:
            pwn_flow = Flow.from_mitmproxy(f)
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
                if self._auto_scan:
                    self.hook_bus.publish("done", {
                        "id": str(db_id),
                        "method": flow.method,
                        "url": flow.url,
                        "request_headers": flow.request_headers,
                        "request_body": flow.request_body,
                        "status_code": flow.status_code,
                        "response_headers": flow.response_headers,
                        "response_body": flow.response_body,
                        "duration_ms": flow.duration_ms,
                        "tls": flow.tls,
                        "error": flow.error,
                    })
        except Exception as e:
            logger.error(f"Failed to store flow {flow.id}: {e}", exc_info=True)
