from fastapi import APIRouter, HTTPException, Request

from pwnproxy.core.models import Flow

router = APIRouter(prefix="/api/v1", tags=["interceptor"])


def _get_controller(request: Request):
    controller = request.app.state.interceptor_controller
    if not controller:
        raise HTTPException(status_code=503, detail="Interceptor not available")
    return controller


@router.get("/interceptor/status")
async def interceptor_status(request: Request):
    controller = _get_controller(request)
    return {
        "enabled": controller.enabled,
        "pending_count": controller.pending_count,
    }


@router.put("/interceptor/toggle")
async def interceptor_toggle(request: Request):
    controller = _get_controller(request)
    controller.toggle()
    return {"enabled": controller.enabled, "pending_count": controller.pending_count}


@router.get("/interceptor/pending")
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


@router.post("/interceptor/forward/{flow_id}")
async def interceptor_forward(flow_id: str, request: Request):
    controller = _get_controller(request)
    if flow_id not in controller.pending:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id} not found")
    controller.forward(flow_id)
    return {"status": "forwarded"}


@router.post("/interceptor/drop/{flow_id}")
async def interceptor_drop(flow_id: str, request: Request):
    controller = _get_controller(request)
    if flow_id not in controller.pending:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id} not found")
    controller.drop(flow_id)
    return {"status": "dropped"}


@router.post("/interceptor/forward-all")
async def interceptor_forward_all(request: Request):
    controller = _get_controller(request)
    count = controller.pending_count
    controller.forward_all()
    return {"status": "forwarded", "count": count}


@router.post("/interceptor/drop-all")
async def interceptor_drop_all(request: Request):
    controller = _get_controller(request)
    count = controller.pending_count
    controller.drop_all()
    return {"status": "dropped", "count": count}
