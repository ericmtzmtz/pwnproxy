"""Re-publish crawl flows into the session's traffic.db (2nd writer pattern).

The crawler worker publishes ``crawler.flow`` events; the main process
persists them as normal ``FlowRecord`` rows and emits ``flow_stored`` so
History / WS live / scanners see them like real proxy traffic. If the job
was started with ``scan_while_crawl``, a ``done`` event is also published
so (future) auto-scan consumers can act on it.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.shared.db import FlowRecord

logger = logging.getLogger(__name__)


async def persist_crawl_flow(traffic_engine, hook_bus, data: dict) -> Optional[int]:
    """Persist a ``crawler.flow`` payload into ``traffic.db``.

    Returns the new ``FlowRecord`` id, or ``None`` if persistence failed
    (the crawl continues; the flow is only lost from History).
    Publishes ``flow_stored`` always, and ``done`` only when
    ``_scan_while_crawl`` is set in the payload.
    """
    try:
        body = data.get("response_body")
        body_bytes = (
            body.encode("utf-8", errors="replace")
            if isinstance(body, str)
            else body
        )
        factory = sessionmaker(traffic_engine, class_=AsyncSession, expire_on_commit=False)
        record = FlowRecord(
            method=data.get("method", "GET"),
            url=data.get("url", ""),
            request_headers=data.get("request_headers") or {},
            request_body=data.get("request_body"),
            request_body_truncated=data.get("request_body_truncated", False),
            status_code=data.get("status_code"),
            response_headers=data.get("response_headers") or {},
            response_body=body_bytes,
            response_body_truncated=data.get("response_body_truncated", False),
            duration_ms=data.get("duration_ms"),
            error=data.get("error"),
            tls=data.get("tls", False),
        )
        async with factory() as session:
            session.add(record)
            await session.commit()
            db_id = record.id
    except Exception as exc:
        logger.debug("could not persist crawl flow: %s", exc)
        return None

    hook_bus.publish("flow_stored", {
        "id": db_id,
        "method": data.get("method", "GET"),
        "url": data.get("url", ""),
        "status_code": data.get("status_code"),
    })
    if data.get("_scan_while_crawl"):
        hook_bus.publish("done", {
            "id": str(db_id),
            "method": data.get("method", "GET"),
            "url": data.get("url", ""),
            "request_headers": data.get("request_headers") or {},
            "request_body": data.get("request_body"),
            "status_code": data.get("status_code"),
            "response_headers": data.get("response_headers") or {},
            "response_body": data.get("response_body"),
            "duration_ms": data.get("duration_ms"),
            "tls": data.get("tls", False),
            "error": data.get("error"),
        })
    return db_id
