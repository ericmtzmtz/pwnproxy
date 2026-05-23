from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/api/v1", tags=["interceptor"])


@router.get("/interceptor/status")
async def interceptor_status(request: Request):
    controller = request.app.state.interceptor_controller
    if not controller:
        raise HTTPException(status_code=503, detail="Interceptor not available")
    return {
        "enabled": controller.enabled,
        "pending_count": controller.pending_count,
    }


@router.put("/interceptor/toggle")
async def interceptor_toggle(request: Request):
    controller = request.app.state.interceptor_controller
    if not controller:
        raise HTTPException(status_code=503, detail="Interceptor not available")
    controller.toggle()
    return {"enabled": controller.enabled, "pending_count": controller.pending_count}
