import logging
from typing import Dict, List

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.shared.db import FlowRecord

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["scanners"])

VALID_SCANNERS: Dict[str, str] = {
    "sqli": "scan_findings",
    "xss": "xss_findings",
    "lfi": "lfi_findings",
    "xxe": "xxe_findings",
    "ssrf": "ssrf_findings",
}


class TriggerRequest(BaseModel):
    flow_id: int
    scanners: List[str]


class FlowTriggerRequest(BaseModel):
    id: str
    method: str
    url: str
    request_headers: Dict[str, str] = {}
    request_body: str | None = None
    status_code: int | None = None
    response_headers: Dict[str, str] = {}
    response_body: str | None = None


@router.post("/scanners/trigger-flow")
async def trigger_scanners_for_flow(request: Request, body: FlowTriggerRequest):
    hook_bus = request.app.state.hook_bus
    if hook_bus is None:
        raise HTTPException(status_code=503, detail="HookBus not available")
    from pwnproxy.shared.models import Flow as FlowModel
    f = FlowModel(
        id=body.id,
        method=body.method,
        url=body.url,
        request_headers=body.request_headers,
        request_body=body.request_body.encode("utf-8") if body.request_body else None,
        status_code=body.status_code,
        response_headers=body.response_headers,
        response_body=body.response_body.encode("utf-8") if body.response_body else None,
    )
    hook_bus.publish("done", f)
    return {"status": "scanning", "flow_id": body.id}


@router.post("/scanners/trigger")
async def trigger_scanners(request: Request, body: TriggerRequest):
    traffic_engine = request.app.state.session_manager.get_traffic_engine()
    traffic_factory = sessionmaker(traffic_engine, class_=AsyncSession, expire_on_commit=False)

    async with traffic_factory() as session:
        result = await session.execute(
            select(FlowRecord).where(FlowRecord.id == body.flow_id)
        )
        flow = result.scalar_one_or_none()

    if flow is None:
        raise HTTPException(status_code=404, detail=f"Flow {body.flow_id} not found")

    unknown = [s for s in body.scanners if s.lower() not in VALID_SCANNERS]
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scanner(s): {unknown}. Available: {list(VALID_SCANNERS.keys())}",
        )

    hook_bus = request.app.state.hook_bus
    if hook_bus is not None:
        from pwnproxy.shared.models import Flow as FlowModel
        f = FlowModel(
            id=str(flow.id),
            method=flow.method,
            url=flow.url,
            request_headers=flow.request_headers or {},
            request_body=flow.request_body,
            status_code=flow.status_code,
            response_headers=flow.response_headers or {},
            response_body=flow.response_body,
        )
        hook_bus.publish("done", f)

    return {"status": "triggered", "flow_id": body.flow_id}


@router.post("/scanners/second-order/start")
async def start_second_order(request: Request):
    """Start the second-order detection background task."""
    from pwnproxy.services.scan.payload_store import get_store

    store = get_store()
    store._running = True
    return {"status": "started", "stats": store.stats()}


@router.post("/scanners/second-order/stop")
async def stop_second_order(request: Request):
    """Stop the second-order detection background task."""
    from pwnproxy.services.scan.payload_store import get_store

    store = get_store()
    store._running = False
    return {"status": "stopped", "stats": store.stats()}


@router.get("/scanners/second-order/status")
async def second_order_status(request: Request):
    """Get second-order detection status."""
    from pwnproxy.services.scan.payload_store import get_store

    store = get_store()
    return {"running": store._running, "stats": store.stats()}
