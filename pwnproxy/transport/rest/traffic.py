from urllib.parse import urlparse
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete as sa_delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.shared.db import FlowRecord

router = APIRouter(prefix="/api/v1", tags=["traffic"])


class FlowOut(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: Optional[int] = None
    method: Optional[str] = None
    url: Optional[str] = None
    request_headers: Optional[dict[str, Any]] = None
    request_body: Optional[str] = None
    request_body_truncated: Optional[bool] = None
    status_code: Optional[int] = None
    response_headers: Optional[dict[str, Any]] = None
    response_body: Optional[str] = None
    response_body_truncated: Optional[bool] = None
    timestamp: Optional[str] = None
    duration_ms: Optional[float] = None
    error: Optional[str] = None
    tls: Optional[bool] = None


class OutscopeResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: Optional[str] = None
    message: Optional[str] = None
    out_of_scope: list[str] = Field(default_factory=list)


def _flow_to_dict(f: FlowRecord) -> dict:
    """Convert FlowRecord to JSON-safe dict, encoding binary fields."""
    return {
        "id": f.id,
        "method": f.method,
        "url": f.url,
        "request_headers": f.request_headers,
        "request_body": f.request_body.decode("utf-8", errors="replace") if f.request_body else None,
        "request_body_truncated": f.request_body_truncated,
        "status_code": f.status_code,
        "response_headers": f.response_headers,
        "response_body": f.response_body.decode("utf-8", errors="replace") if f.response_body else None,
        "response_body_truncated": f.response_body_truncated,
        "timestamp": f.timestamp.isoformat() if f.timestamp else None,
        "duration_ms": f.duration_ms,
        "error": f.error,
        "tls": f.tls,
    }


@router.get("/flows", response_model=list[FlowOut])
async def list_flows(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    since_id: Optional[int] = Query(None, ge=0, description="Return only flows with id > since_id"),
):
    engine = request.app.state.session_manager.get_traffic_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        if since_id is not None:
            result = await session.execute(
                select(FlowRecord)
                .where(FlowRecord.id > since_id)
                .order_by(FlowRecord.id.asc())
            )
        else:
            result = await session.execute(
                select(FlowRecord).order_by(FlowRecord.id.desc()).limit(limit).offset(offset)
            )
        return [_flow_to_dict(f) for f in result.scalars().all()]


@router.get("/flows/{flow_id}", response_model=FlowOut)
async def get_flow(request: Request, flow_id: int):
    engine = request.app.state.session_manager.get_traffic_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        result = await session.execute(select(FlowRecord).where(FlowRecord.id == flow_id))
        flow = result.scalar_one_or_none()
        if not flow:
            raise HTTPException(status_code=404, detail="Flow not found")
        return _flow_to_dict(flow)


@router.delete("/flows/{flow_id}", status_code=204)
async def delete_flow(request: Request, flow_id: int):
    engine = request.app.state.session_manager.get_traffic_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        result = await session.execute(sa_delete(FlowRecord).where(FlowRecord.id == flow_id))
        await session.commit()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Flow not found")


@router.delete("/flows", status_code=204)
async def clear_flows(request: Request):
    engine = request.app.state.session_manager.get_traffic_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        await session.execute(sa_delete(FlowRecord))
        await session.commit()


@router.post("/flows/{flow_id}/outscope", status_code=200, response_model=OutscopeResponse)
async def outscope_flow(request: Request, flow_id: int):
    engine = request.app.state.session_manager.get_traffic_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        result = await session.execute(select(FlowRecord).where(FlowRecord.id == flow_id))
        flow = result.scalar_one_or_none()
        if not flow:
            raise HTTPException(status_code=404, detail="Flow not found")

    parsed = urlparse(flow.url)
    host = parsed.hostname or ""
    if not host:
        raise HTTPException(status_code=400, detail="Could not parse host from flow URL")

    manager = request.app.state.session_manager
    patterns = [host, f"*.{host}"]
    added = []
    for p in patterns:
        if p not in manager.scope.out_of_scope:
            manager.scope.out_of_scope.append(p)
            added.append(p)

    if added:
        manager.mark_unsaved()

    return {"status": "ok", "message": f"Added {', '.join(added)} to out-of-scope", "out_of_scope": manager.scope.out_of_scope}
