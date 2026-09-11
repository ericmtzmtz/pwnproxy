from urllib.parse import urlparse
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete as sa_delete, select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.shared.db import FlowCommentORM, FlowRecord

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
    comment_count: Optional[int] = None


class OutscopeResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: Optional[str] = None
    message: Optional[str] = None
    out_of_scope: list[str] = Field(default_factory=list)


class CommentCreate(BaseModel):
    body: str = Field(..., min_length=1)
    kind: str = Field(default="note")
    resolved: bool = False
    author: Optional[str] = None


class CommentUpdate(BaseModel):
    body: Optional[str] = None
    kind: Optional[str] = None
    resolved: Optional[bool] = None


class CommentOut(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: int
    flow_id: int
    body: str
    kind: str
    resolved: bool
    author: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


def _flow_to_dict(f: FlowRecord, comment_count: int = 0) -> dict:
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
        "comment_count": comment_count,
    }


def _comment_to_dict(c: dict) -> dict:
    d = dict(c)
    if d.get("created_at") is not None and hasattr(d["created_at"], "isoformat"):
        d["created_at"] = d["created_at"].isoformat()
    if d.get("updated_at") is not None and hasattr(d["updated_at"], "isoformat"):
        d["updated_at"] = d["updated_at"].isoformat()
    return d


async def _ensure_comment_table(engine) -> None:
    """Ensure flow_comments table exists (create_all is idempotent)."""
    from pwnproxy.shared.db import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


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
        flows = result.scalars().all()
        if not flows:
            return []
        # Batch comment counts with one grouped query
        await _ensure_comment_table(engine)
        flow_ids = [f.id for f in flows]
        cnt_result = await session.execute(
            select(FlowCommentORM.flow_id, func.count(FlowCommentORM.id))
            .where(FlowCommentORM.flow_id.in_(flow_ids))
            .group_by(FlowCommentORM.flow_id)
        )
        counts = dict(cnt_result.all())
        return [_flow_to_dict(f, comment_count=counts.get(f.id, 0)) for f in flows]


@router.get("/flows/{flow_id}", response_model=FlowOut)
async def get_flow(request: Request, flow_id: int):
    engine = request.app.state.session_manager.get_traffic_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        result = await session.execute(select(FlowRecord).where(FlowRecord.id == flow_id))
        flow = result.scalar_one_or_none()
        if not flow:
            raise HTTPException(status_code=404, detail="Flow not found")
        # comment count
        await _ensure_comment_table(engine)
        cnt_result = await session.execute(
            select(func.count(FlowCommentORM.id)).where(FlowCommentORM.flow_id == flow_id)
        )
        cnt = cnt_result.scalar() or 0
        return _flow_to_dict(flow, comment_count=cnt)


@router.delete("/flows/{flow_id}", status_code=204)
async def delete_flow(request: Request, flow_id: int):
    engine = request.app.state.session_manager.get_traffic_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        # Cascade delete comments first
        await _ensure_comment_table(engine)
        await session.execute(sa_delete(FlowCommentORM).where(FlowCommentORM.flow_id == flow_id))
        result = await session.execute(sa_delete(FlowRecord).where(FlowRecord.id == flow_id))
        await session.commit()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Flow not found")


@router.delete("/flows", status_code=204)
async def clear_flows(request: Request):
    engine = request.app.state.session_manager.get_traffic_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        await _ensure_comment_table(engine)
        await session.execute(sa_delete(FlowCommentORM))
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


# ── Comment CRUD ──────────────────────────────────────────────────


@router.get("/flows/{flow_id}/comments", response_model=list[CommentOut])
async def list_flow_comments(flow_id: int, request: Request):
    engine = request.app.state.session_manager.get_traffic_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        flow_res = await session.execute(select(FlowRecord).where(FlowRecord.id == flow_id))
        if flow_res.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Flow not found")
    await _ensure_comment_table(engine)
    from pwnproxy.shared.comments.storage import FlowCommentStorage

    storage = FlowCommentStorage(engine)
    rows = await storage.list_by_flow(flow_id)
    return [_comment_to_dict(r) for r in rows]


@router.post("/flows/{flow_id}/comments", response_model=CommentOut, status_code=201)
async def create_flow_comment(flow_id: int, payload: CommentCreate, request: Request):
    if payload.kind.lower() not in ("note", "flag", "todo"):
        raise HTTPException(status_code=422, detail="Invalid kind: must be note, flag, or todo")
    engine = request.app.state.session_manager.get_traffic_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        flow_res = await session.execute(select(FlowRecord).where(FlowRecord.id == flow_id))
        if flow_res.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Flow not found")
    await _ensure_comment_table(engine)
    from pwnproxy.shared.comments.storage import FlowCommentStorage

    storage = FlowCommentStorage(engine)
    row = await storage.create(
        flow_id, body=payload.body, kind=payload.kind, resolved=payload.resolved, author=payload.author
    )
    hook_bus = getattr(request.app.state, "hook_bus", None)
    if hook_bus:
        try:
            sid = getattr(request.app.state.session_manager, "active_name", None) or ""
            evt = {"flow_id": flow_id, "comment_id": row["id"], **row}
            if sid:
                evt["session_id"] = sid
            hook_bus.publish("comment.created", evt)
        except Exception:
            pass
    return _comment_to_dict(row)


@router.patch("/flows/{flow_id}/comments/{comment_id}", response_model=CommentOut)
async def update_flow_comment(flow_id: int, comment_id: int, payload: CommentUpdate, request: Request):
    if payload.kind is not None and payload.kind.lower() not in ("note", "flag", "todo"):
        raise HTTPException(status_code=422, detail="Invalid kind: must be note, flag, or todo")
    engine = request.app.state.session_manager.get_traffic_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        flow_res = await session.execute(select(FlowRecord).where(FlowRecord.id == flow_id))
        if flow_res.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Flow not found")
    await _ensure_comment_table(engine)
    from pwnproxy.shared.comments.storage import FlowCommentStorage

    storage = FlowCommentStorage(engine)
    # verify comment belongs to flow
    existing = await storage.get(comment_id)
    if not existing or existing["flow_id"] != flow_id:
        raise HTTPException(status_code=404, detail="Comment not found")
    updated = await storage.update(comment_id, body=payload.body, kind=payload.kind, resolved=payload.resolved)
    if not updated:
        raise HTTPException(status_code=404, detail="Comment not found")
    hook_bus = getattr(request.app.state, "hook_bus", None)
    if hook_bus:
        try:
            sid = getattr(request.app.state.session_manager, "active_name", None) or ""
            evt = {"flow_id": flow_id, "comment_id": comment_id, **updated}
            if sid:
                evt["session_id"] = sid
            hook_bus.publish("comment.updated", evt)
        except Exception:
            pass
    return _comment_to_dict(updated)


@router.delete("/flows/{flow_id}/comments/{comment_id}", status_code=204)
async def delete_flow_comment(flow_id: int, comment_id: int, request: Request):
    engine = request.app.state.session_manager.get_traffic_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        flow_res = await session.execute(select(FlowRecord).where(FlowRecord.id == flow_id))
        if flow_res.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Flow not found")
    await _ensure_comment_table(engine)
    from pwnproxy.shared.comments.storage import FlowCommentStorage

    storage = FlowCommentStorage(engine)
    existing = await storage.get(comment_id)
    if not existing or existing["flow_id"] != flow_id:
        raise HTTPException(status_code=404, detail="Comment not found")
    await storage.delete(comment_id)
    hook_bus = getattr(request.app.state, "hook_bus", None)
    if hook_bus:
        try:
            sid = getattr(request.app.state.session_manager, "active_name", None) or ""
            evt = {"flow_id": flow_id, "comment_id": comment_id}
            if sid:
                evt["session_id"] = sid
            hook_bus.publish("comment.deleted", evt)
        except Exception:
            pass
