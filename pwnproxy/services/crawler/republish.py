"""Re-publish crawl flows into the session's traffic.db (2nd writer pattern).

The crawler worker publishes ``crawler.flow`` events; the main process
persists them as normal ``FlowRecord`` rows and emits ``flow_stored`` so
History / WS live see them like real proxy traffic. If the job was started with
``scan_while_crawl``, a ``done`` event is also published so the auto-scan
consumers act on it — but only when the scope allows active scanning and the
crawled URL is in scope (``scan_gate``, i.e. ``FlowFilter.allow_active_scan``).
Storage is never gated.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.shared.db import FlowRecord

logger = logging.getLogger(__name__)


async def persist_crawl_flow(traffic_engine, hook_bus, data: dict, *, scan_gate=None) -> int | None:
    """Persist a ``crawler.flow`` payload into ``traffic.db``.

    Returns the new ``FlowRecord`` id, or ``None`` if persistence failed
    (the crawl continues; the flow is only lost from History).
    Publishes ``flow_stored`` always, and ``done`` — the auto-scan delivery —
    only when ``_scan_while_crawl`` is set **and** ``scan_gate`` allows it.

    Args:
        traffic_engine: Async engine of the session's ``traffic.db``.
        hook_bus: Main-process ``HookBus``.
        data: ``crawler.flow`` payload sent by the crawler worker.
        scan_gate: ``FlowFilter`` holding the session scope, asked through
            ``allow_active_scan``. Defaults to ``None``, which **blocks** the
            ``done`` event: a caller that forgets the gate loses auto-scan
            (visible, harmless) instead of scanning a host nobody authorised.
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

    flow_stored_payload: dict[str, Any] = {
        "id": db_id,
        "method": data.get("method", "GET"),
        "url": data.get("url", ""),
        "status_code": data.get("status_code"),
    }
    if data.get("session_id"):
        flow_stored_payload["session_id"] = data["session_id"]
    hook_bus.publish("flow_stored", flow_stored_payload)
    scan_allowed = scan_gate is not None and scan_gate.allow_active_scan(
        data.get("url", "")
    )
    if data.get("_scan_while_crawl") and scan_allowed:
        done_payload: dict[str, Any] = {
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
        }
        if data.get("session_id"):
            done_payload["session_id"] = data["session_id"]
        hook_bus.publish("done", done_payload)
    return db_id
