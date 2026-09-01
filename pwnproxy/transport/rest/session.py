import json
import logging
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator

router = APIRouter(prefix="/api/v1", tags=["sessions"])

logger = logging.getLogger(__name__)


class ScopeUpdateRequest(BaseModel):
    """Scope patterns MUST be fnmatch strings (e.g. 'http://host:8080/*').

    Structured objects like {"host": ..., "port": ...} are rejected with 422:
    they used to be stored verbatim and later crash ScopeConfig.is_in_scope
    at runtime inside fnmatch().
    """

    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    enabled: Optional[bool] = None

    @model_validator(mode="before")
    @classmethod
    def _legacy_patterns_alias(cls, data):
        if isinstance(data, dict) and "patterns" in data:
            data = {**data, "in_scope": data.pop("patterns")}
        return data


class SessionInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str = ""
    created_at: Optional[str] = None
    last_modified: Optional[str] = None
    active: bool = False
    last_active: bool = False
    request_count: int = 0
    finding_count: int = 0


class ActiveSessionResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: Optional[str] = None
    path: Optional[str] = None
    has_unsaved_changes: bool = False
    scope_enabled: bool = False


class SessionManageRequest(BaseModel):
    action: str = ""
    name: str = ""
    new_name: Optional[str] = None


class SessionManageResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: Optional[str] = None
    message: Optional[str] = None


class ScopeResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    enabled: bool = False


async def _restart_crawler_for_scope(request: Request) -> None:
    """Restart the crawler worker so its scope filter reflects the current scope.

    The worker receives a snapshot of the scope at spawn time; after a scope
    change the snapshot is stale, so restart it (idempotent via CrawlerProcess).
    """
    manager = getattr(request.app.state, "session_manager", None)
    crawler = getattr(request.app.state, "crawler_process", None)
    if not manager or not crawler or not manager.has_active_session:
        return
    try:
        await crawler.restart(
            db_path=str(manager.active_path / "crawler.db"),
            scope_json=json.dumps(manager.scope.to_dict()),
        )
    except Exception as exc:
        logger.warning("Could not restart crawler after scope change: %s", exc)


def _db_size(session_path: Path, db_name: str) -> int:
    db = session_path / db_name
    try:
        return os.path.getsize(db)
    except OSError:
        return 0


@router.get("/sessions", response_model=list[SessionInfo])
async def list_sessions(request: Request):
    """List all proxy sessions."""
    import pwnproxy.services.session.manager as _mgr

    manager = request.app.state.session_manager
    sessions = manager.list()

    try:
        last_active = _mgr.LAST_SESSION_FILE.read_text().strip()
    except OSError:
        last_active = None

    return [
        {
            "name": s["name"],
            "created_at": s.get("created_at"),
            "last_modified": s.get("last_modified"),
            "active": s["name"] == manager.active_name,
            "last_active": s["name"] == last_active,
            "request_count": _db_size(_mgr.SESSIONS_ROOT / s["name"], "traffic.db"),
            "finding_count": _db_size(_mgr.SESSIONS_ROOT / s["name"], "scanner_results.db"),
        }
        for s in sessions
    ]


@router.get("/sessions/active", response_model=ActiveSessionResponse)
async def get_active_session(request: Request):
    manager = request.app.state.session_manager
    return {
        "name": manager.active_name,
        "path": str(manager.active_path),
        "has_unsaved_changes": manager.has_unsaved_changes,
        "scope_enabled": manager.scope.enabled,
    }


@router.post("/sessions/manage", response_model=SessionManageResponse)
async def manage_session(request: Request, body: SessionManageRequest):
    """Create, load, save, or delete sessions."""
    action = body.action
    name = body.name
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
            new_name = body.new_name or ""
            from pwnproxy.services.session.manager import SessionManager
            await SessionManager.rename(name, new_name)
            if manager._active_name == name:
                manager._active_name = new_name
                manager._active_path = manager._active_path.parent / new_name
            return {"status": "ok", "message": f"Renamed session '{name}' -> '{new_name}'"}
        else:
            raise HTTPException(status_code=400, detail=f"Unknown action: {action}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/sessions/scope", response_model=ScopeResponse)
async def get_scope(request: Request):
    manager = request.app.state.session_manager
    return manager.scope.to_dict()


@router.put("/sessions/scope", response_model=SessionManageResponse)
async def update_scope(payload: ScopeUpdateRequest, request: Request):
    manager = request.app.state.session_manager
    data = payload.model_dump(exclude_unset=True)
    if "in_scope" in data and "enabled" not in data:
        data["enabled"] = True
    # SessionManager owns the scope write (mutate + save + publish callback).
    scope_dict = await manager.update_scope(data)

    # ── Push scope filter to running components (transport fan-out) ──
    # HookBus: dynamic lambda, scope is already updated on SessionManager
    # Interceptor addon (embedded mode): re-wire if available
    intercept = getattr(request.app.state, "interceptor_controller", None)
    if intercept and hasattr(intercept, "_addon"):
        intercept._addon.set_scope_filter(lambda url: manager.scope.is_in_scope(url))

    # Proxy (subprocess mode): live reload if supported, else restart.
    # Embedded mode (ProxyEngine): hot-swap the shared FlowFilter.
    proxy = manager.get_proxy_engine()
    if proxy:
        flow_filter = getattr(proxy, "flow_filter", None)
        if flow_filter is not None and hasattr(flow_filter, "set_scope"):
            flow_filter.set_scope(manager.scope)
        if hasattr(proxy, "running") and proxy.running:
            if hasattr(proxy, "send_scope_update"):
                await proxy.send_scope_update(scope_json=json.dumps(scope_dict))
            else:
                await manager._apply_proxy_config()

    # Crawler (subprocess mode): publish scope.updated via feed bridge
    # (restart is the fallback if the worker can't handle live updates)
    crawler = getattr(request.app.state, "crawler_process", None)
    if crawler and crawler.running:
        crawler.send_to_worker("scope.updated", scope_dict)

    return {"status": "ok", "message": "Scope updated"}
