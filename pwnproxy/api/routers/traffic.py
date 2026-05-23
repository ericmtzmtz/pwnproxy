from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.core.db import FlowRecord

router = APIRouter(prefix="/api/v1", tags=["traffic"])


@router.get("/flows")
async def list_flows(request: Request, limit: int = 50, offset: int = 0):
    engine = request.app.state.traffic_engine
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
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
