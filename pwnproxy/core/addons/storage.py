import asyncio
import logging
import mitmproxy.http
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.core.db import FlowRecord, truncate_body
from pwnproxy.core.models import Flow

logger = logging.getLogger(__name__)


class StorageAddon:
    """Mitmproxy addon that persists completed flows to SQLite asynchronously."""

    def __init__(self, db_engine: AsyncEngine):
        self.db_engine = db_engine
        self.session_factory = sessionmaker(
            self.db_engine, class_=AsyncSession, expire_on_commit=False
        )
        self._background_tasks = set()

    def done(self, f: mitmproxy.http.HTTPFlow):
        """Called when a flow completes (successful or error)."""
        # We need to run the db insert concurrently without blocking mitmproxy's event loop
        # Convert it to our internal model first to avoid threading/asyncio issues with mitmproxy objects
        pwn_flow = Flow.from_mitmproxy(f)
        task = asyncio.create_task(self._store_flow(pwn_flow))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _store_flow(self, flow: Flow) -> None:
        try:
            req_body, req_trunc = truncate_body(flow.request_body)
            res_body, res_trunc = truncate_body(flow.response_body)

            record = FlowRecord(
                method=flow.method,
                url=flow.url,
                request_headers=flow.request_headers,
                request_body=req_body,
                request_body_truncated=req_trunc,
                status_code=flow.status_code,
                response_headers=flow.response_headers,
                response_body=res_body,
                response_body_truncated=res_trunc,
                duration_ms=flow.duration_ms,
                error=flow.error,
                tls=flow.tls,
            )
            
            async with self.session_factory() as session:
                session.add(record)
                await session.commit()
        except Exception as e:
            logger.error(f"Failed to store flow {flow.id}: {e}", exc_info=True)
