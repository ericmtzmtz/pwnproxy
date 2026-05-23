import logging
from typing import Dict, List

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.core.db import FlowRecord

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


@router.post("/scanners/trigger")
async def trigger_scanners(request: Request, body: TriggerRequest):
    traffic_engine = request.app.state.traffic_engine
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
        from pwnproxy.core.models import Flow as FlowModel
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
