import json

from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/api/v1", tags=["sessions"])


@router.get("/sessions")
async def list_sessions(request: Request):
    """List all proxy sessions (not tokens — use /api/v1/tokens for tokens)."""
    manager = request.app.state.session_manager
    sessions = manager.list()
    return [
        {
            "name": s["name"],
            "created_at": s.get("created_at"),
            "last_modified": s.get("last_modified"),
            "active": s["name"] == manager.active_name,
        }
        for s in sessions
    ]


@router.get("/sessions/active")
async def get_active_session(request: Request):
    manager = request.app.state.session_manager
    return {
        "name": manager.active_name,
        "path": str(manager.active_path),
        "has_unsaved_changes": manager.has_unsaved_changes,
        "scope_enabled": manager.scope.enabled,
    }


@router.post("/sessions/manage")
async def manage_session(request: Request):
    """Create, load, save, or delete sessions."""
    body = await request.json()
    action = body.get("action")
    name = body.get("name", "")
    manager = request.app.state.session_manager

    try:
        if action == "create":
            await manager.create(name)
            return {"status": "ok", "message": f"Created session '{name}'"}
        elif action == "load":
            await manager.load(name)
            return {"status": "ok", "message": f"Loaded session '{name}'"}
        elif action == "save":
            await manager.save()
            return {"status": "ok", "message": f"Saved session '{manager.active_name}'"}
        elif action == "delete":
            await manager.delete(name)
            return {"status": "ok", "message": f"Deleted session '{name}'"}
        elif action == "rename":
            new_name = body.get("new_name", "")
            from pwnproxy.modules.session_manager.manager import SessionManager
            await SessionManager.rename(name, new_name)
            if manager._active_name == name:
                manager._active_name = new_name
                manager._active_path = manager._active_path.parent / new_name
            return {"status": "ok", "message": f"Renamed session '{name}' -> '{new_name}'"}
        else:
            raise HTTPException(status_code=400, detail=f"Unknown action: {action}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/sessions/scope")
async def get_scope(request: Request):
    manager = request.app.state.session_manager
    return manager.scope.to_dict()


@router.put("/sessions/scope")
async def update_scope(request: Request):
    body = await request.json()
    manager = request.app.state.session_manager
    from pwnproxy.modules.session_manager import ScopeConfig
    manager.scope = ScopeConfig(body)
    manager.mark_unsaved()
    return {"status": "ok", "message": "Scope updated"}
