import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.shared.db import FlowRecord

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["scanners"])


def _available_scanners(request: Request) -> set[str]:
    """Names the plugin catalog knows about (lower-cased), never a literal list.

    The catalog is the single registry (built-ins plus installed packages by
    entry point), so ``command-injection`` and any active commercial plugin are
    accepted here without touching this module. The live loader is preferred
    because it already resolved discovery; a fresh catalog is only built when it
    has none yet (endpoint hit before the loader starts, or in tests).
    """
    loader = getattr(request.app.state, "plugin_loader", None)
    names = {record.name for record in loader.catalog()} if loader is not None else set()
    if not names:
        from pwnproxy.plugins.core.catalog import discover_plugins

        names = {record.name for record in discover_plugins()}
    return {name.lower() for name in names}


class TriggerRequest(BaseModel):
    budget_ms: int | None = None
    flow_id: int
    scanners: list[str]


class FlowTriggerRequest(BaseModel):
    budget_ms: int | None = None
    id: str
    method: str
    url: str
    request_headers: dict[str, str] = {}
    request_body: str | None = None
    status_code: int | None = None
    response_headers: dict[str, str] = {}
    response_body: str | None = None


class TriggerResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: str | None = None
    flow_id: Any = None


@router.post("/scanners/trigger-flow", response_model=TriggerResponse)
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
    hook_bus.publish("flow", f)
    bus = getattr(request.app.state, "bus", None)
    if bus is not None:
        await bus.publish("flow", f)
    return {"status": "scanning", "flow_id": body.id}


@router.post("/scanners/trigger", response_model=TriggerResponse)
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

    available = _available_scanners(request)
    unknown = [s for s in body.scanners if s.lower() not in available]
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scanner(s): {unknown}. Available: {sorted(available)}",
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
        hook_bus.publish("flow", f)
        bus = getattr(request.app.state, "bus", None)
        if bus is not None:
            await bus.publish("flow", f)
        # Publish on per-scanner topics if specific scanners are requested
        for scanner_name in body.scanners:
            topic = f"flow.{scanner_name.lower()}"
            hook_bus.publish(topic, f)
            if bus is not None:
                await bus.publish(topic, f)

    return {"status": "triggered", "flow_id": body.flow_id}
