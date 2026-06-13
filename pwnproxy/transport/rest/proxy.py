from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/api/v1", tags=["proxy"])


def _get_session_manager(request: Request):
    sm = getattr(request.app.state, "session_manager", None)
    if not sm:
        raise HTTPException(status_code=503, detail="Session manager not available")
    return sm


def _get_proxy(request: Request):
    sm = _get_session_manager(request)
    proxy = sm.get_proxy_engine()
    if not proxy:
        raise HTTPException(status_code=503, detail="Proxy not available")
    return proxy


@router.get("/proxy/status")
async def proxy_status(request: Request):
    proxy = _get_proxy(request)
    sm = _get_session_manager(request)
    return {
        "capture_enabled": sm.proxy_config.capture_enabled,
        "running": proxy.running,
        "host": sm.proxy_config.host,
        "port": sm.proxy_config.port,
        "ssl_insecure": sm.proxy_config.ssl_insecure,
        "upstream": sm.proxy_config.upstream,
    }


@router.put("/proxy/toggle")
async def proxy_toggle(request: Request):
    sm = _get_session_manager(request)
    sm.proxy_config.capture_enabled = not sm.proxy_config.capture_enabled
    sm.mark_unsaved()
    return {"capture_enabled": sm.proxy_config.capture_enabled}


def _build_proxy_params(sm):
    db_path = None
    scope = None
    if sm.has_active_session:
        db_path = str(sm.active_path / "traffic.db")
        if sm.scope.enabled and sm.scope.in_scope:
            scope = list(sm.scope.in_scope)
    return db_path, scope


@router.post("/proxy/start")
async def proxy_start(request: Request):
    sm = _get_session_manager(request)
    proxy = _get_proxy(request)
    db_path, scope = _build_proxy_params(sm)
    await proxy.start(sm.proxy_config, db_path=db_path, scope=scope)
    return await proxy_status(request)


@router.post("/proxy/stop")
async def proxy_stop(request: Request):
    proxy = _get_proxy(request)
    await proxy.stop()
    return {"success": True, "running": False}


@router.post("/proxy/restart")
async def proxy_restart(request: Request):
    sm = _get_session_manager(request)
    proxy = _get_proxy(request)
    db_path, scope = _build_proxy_params(sm)
    await proxy.restart(sm.proxy_config, db_path=db_path, scope=scope)
    return await proxy_status(request)
