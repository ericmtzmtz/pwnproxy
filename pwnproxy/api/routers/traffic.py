from urllib.parse import urlparse
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import delete as sa_delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.core.db import FlowRecord

router = APIRouter(prefix="/api/v1", tags=["traffic"])


@router.get("/flows")
async def list_flows(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    since_id: Optional[int] = Query(None, ge=0, description="Return only flows with id > since_id"),
):
    engine = request.app.state.traffic_engine
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
        return result.scalars().all()


@router.get("/flows/{flow_id}")
async def get_flow(request: Request, flow_id: int):
    engine = request.app.state.traffic_engine
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        result = await session.execute(select(FlowRecord).where(FlowRecord.id == flow_id))
        flow = result.scalar_one_or_none()
        if not flow:
            raise HTTPException(status_code=404, detail="Flow not found")
        return flow


@router.delete("/flows/{flow_id}", status_code=204)
async def delete_flow(request: Request, flow_id: int):
    engine = request.app.state.traffic_engine
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        result = await session.execute(sa_delete(FlowRecord).where(FlowRecord.id == flow_id))
        await session.commit()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Flow not found")


@router.delete("/flows", status_code=204)
async def clear_flows(request: Request):
    engine = request.app.state.traffic_engine
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        await session.execute(sa_delete(FlowRecord))
        await session.commit()


@router.post("/flows/{flow_id}/outscope", status_code=200)
async def outscope_flow(request: Request, flow_id: int):
    engine = request.app.state.traffic_engine
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
