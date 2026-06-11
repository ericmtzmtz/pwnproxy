from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/api/v1", tags=["proxy"])


def _get_proxy(request: Request):
    proxy = getattr(request.app.state, "proxy_engine", None)
    if not proxy:
        raise HTTPException(status_code=503, detail="Proxy not available")
    return proxy


@router.get("/proxy/status")
async def proxy_status(request: Request):
    proxy = _get_proxy(request)
    return {"capture_enabled": proxy.capture_enabled}


@router.put("/proxy/toggle")
async def proxy_toggle(request: Request):
    proxy = _get_proxy(request)
    new = not proxy.capture_enabled
    proxy.set_capture_enabled(new)
    return {"capture_enabled": new}
