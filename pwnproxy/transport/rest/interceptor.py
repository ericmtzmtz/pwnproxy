from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from pwnproxy.shared.models import Flow

router = APIRouter(prefix="/api/v1", tags=["interceptor"])


class InterceptorStatusResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = False
    pending_count: int = 0


class PendingFlow(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: Any = None
    method: Optional[str] = None
    url: Optional[str] = None
    status_code: Optional[int] = None
    timestamp: Any = None


class InterceptorActionResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: Optional[str] = None


class InterceptorActionCountResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: Optional[str] = None
    count: int = 0


def _get_controller(request: Request):
    controller = request.app.state.interceptor_controller
    if not controller:
        raise HTTPException(status_code=503, detail="Interceptor not available")
    return controller


@router.get("/interceptor/status", response_model=InterceptorStatusResponse)
async def interceptor_status(request: Request):
    controller = _get_controller(request)
    return {
        "enabled": controller.enabled,
        "pending_count": controller.pending_count,
    }


@router.put("/interceptor/toggle", response_model=InterceptorStatusResponse)
async def interceptor_toggle(request: Request):
    controller = _get_controller(request)
    controller.toggle()
    mgr = getattr(request.app.state, "session_manager", None)
    if mgr:
        mgr.mark_unsaved()
    return {"enabled": controller.enabled, "pending_count": controller.pending_count}


@router.get("/interceptor/pending", response_model=list[PendingFlow])
async def interceptor_pending(request: Request):
    controller = _get_controller(request)
    flows = []
    for flow in controller.pending.values():
        flows.append({
            "id": flow.id,
            "method": flow.method,
            "url": flow.url,
            "status_code": flow.status_code,
            "timestamp": flow.timestamp if hasattr(flow, "timestamp") else None,
        })
    return flows


@router.post("/interceptor/forward/{flow_id}", response_model=InterceptorActionResponse)
async def interceptor_forward(flow_id: str, request: Request):
    controller = _get_controller(request)
    if flow_id not in controller.pending:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id} not found")
    controller.forward(flow_id)
    return {"status": "forwarded"}


@router.post("/interceptor/drop/{flow_id}", response_model=InterceptorActionResponse)
async def interceptor_drop(flow_id: str, request: Request):
    controller = _get_controller(request)
    if flow_id not in controller.pending:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id} not found")
    controller.drop(flow_id)
    return {"status": "dropped"}


@router.post("/interceptor/forward-all", response_model=InterceptorActionCountResponse)
async def interceptor_forward_all(request: Request):
    controller = _get_controller(request)
    count = controller.pending_count
    controller.forward_all()
    return {"status": "forwarded", "count": count}


@router.post("/interceptor/drop-all", response_model=InterceptorActionCountResponse)
async def interceptor_drop_all(request: Request):
    controller = _get_controller(request)
    count = controller.pending_count
    controller.drop_all()
    return {"status": "dropped", "count": count}
