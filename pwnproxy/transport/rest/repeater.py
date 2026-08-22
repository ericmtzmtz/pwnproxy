import json
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from pwnproxy.services.repeater.engine import RepeaterEngine
from pwnproxy.services.repeater.parser import parse_raw_request

router = APIRouter(prefix="/api/v1", tags=["repeater"])


# --- Tab models ---

class RepeaterTabCreate(BaseModel):
    name: Optional[str] = None
    raw_request: str = ""


class RepeaterTabUpdate(BaseModel):
    name: Optional[str] = None
    raw_request: Optional[str] = None
    last_task_id: Optional[str] = None


class RepeaterTabOut(BaseModel):
    id: int
    name: str
    raw_request: str
    last_task_id: Optional[str] = None
    created_at: str
    updated_at: str


# --- In-memory tab store per session ---
# _tab_store[ session_name ] = { id: tab_dict, ... }
_tab_store: dict[str, dict[int, dict]] = {}
_next_ids: dict[str, int] = {}


def _tabs_path(session_name: str) -> Path:
    return Path.home() / ".pwnproxy" / "sessions" / session_name / "tabs.json"


def _load_tabs(session_name: str) -> dict[int, dict]:
    if session_name in _tab_store:
        return _tab_store[session_name]
    path = _tabs_path(session_name)
    tabs: dict[int, dict] = {}
    max_id = 0
    if path.exists():
        raw = json.loads(path.read_text())
        for t in raw:
            tid = t["id"]
            tabs[tid] = t
            if tid > max_id:
                max_id = tid
    _next_ids[session_name] = max_id + 1
    _tab_store[session_name] = tabs
    return tabs


def _save_tabs(session_name: str, tabs: dict[int, dict]) -> None:
    path = _tabs_path(session_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(list(tabs.values()), indent=2))
    _tab_store[session_name] = tabs


def _next_tab_id(session_name: str) -> int:
    nid = _next_ids.get(session_name, 1)
    _next_ids[session_name] = nid + 1
    return nid


def _get_session_name(request: Request) -> str:
    mgr = getattr(request.app.state, "session_manager", None)
    return mgr.active_name if mgr and mgr.active_name else "default"


# --- Tab CRUD endpoints ---

@router.get("/repeater/tabs", response_model=list[RepeaterTabOut])
async def list_tabs(request: Request):
    session = _get_session_name(request)
    tabs = _load_tabs(session)
    return [RepeaterTabOut(**t) for t in sorted(tabs.values(), key=lambda x: x["id"])]


@router.post("/repeater/tabs", response_model=RepeaterTabOut, status_code=201)
async def create_tab(request: Request, body: RepeaterTabCreate):
    session = _get_session_name(request)
    tabs = _load_tabs(session)
    tid = _next_tab_id(session)
    now = datetime.now().isoformat()
    tab = {
        "id": tid,
        "name": body.name or str(tid),
        "raw_request": body.raw_request,
        "created_at": now,
        "updated_at": now,
    }
    tabs[tid] = tab
    _save_tabs(session, tabs)
    return RepeaterTabOut(**tab)


@router.put("/repeater/tabs/{tab_id}", response_model=RepeaterTabOut)
async def update_tab(request: Request, tab_id: int, body: RepeaterTabUpdate):
    session = _get_session_name(request)
    tabs = _load_tabs(session)
    if tab_id not in tabs:
        raise HTTPException(status_code=404, detail=f"Tab {tab_id} not found")
    tab = tabs[tab_id]
    if body.name is not None:
        tab["name"] = body.name
    if body.raw_request is not None:
        tab["raw_request"] = body.raw_request
    tab["updated_at"] = datetime.now().isoformat()
    tabs[tab_id] = tab
    _save_tabs(session, tabs)
    return RepeaterTabOut(**tab)


@router.delete("/repeater/tabs/{tab_id}", status_code=204)
async def delete_tab(request: Request, tab_id: int):
    session = _get_session_name(request)
    tabs = _load_tabs(session)
    if tab_id not in tabs:
        raise HTTPException(status_code=404, detail=f"Tab {tab_id} not found")
    del tabs[tab_id]
    _save_tabs(session, tabs)


# --- Send endpoint (unchanged) ---

class RepeaterSendRequest(BaseModel):
    raw_request: str
    tab_id: Optional[int] = None


class RepeaterSendResponse(BaseModel):
    task_id: str
    status_code: int
    headers: dict
    body_preview: str
    timing_ms: float


@router.post("/repeater/send")
async def repeater_send(request: Request, body: RepeaterSendRequest):
    from pwnproxy.transport.rest.tasks import get_task_store
    store = get_task_store(request)

    session_mgr = getattr(request.app.state, "session_manager", None)
    session_name = session_mgr.active_name if session_mgr else ""

    config = {"raw_request": body.raw_request}
    task_id = await store.create("repeater", config, session_name=session_name)

    if body.tab_id is not None:
        session = _get_session_name(request)
        tabs = _load_tabs(session)
        if body.tab_id in tabs:
            tabs[body.tab_id]["last_task_id"] = task_id
            tabs[body.tab_id]["updated_at"] = datetime.now().isoformat()
            _save_tabs(session, tabs)

    await store.update(task_id, status="running", total=1)
    start = time.monotonic()
    engine = RepeaterEngine()
    try:
        parsed = parse_raw_request(body.raw_request)
        resp = await engine.send(parsed)
        elapsed = (time.monotonic() - start) * 1000
        result = {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text,
            "duration_ms": round(elapsed, 1),
        }
        await store.update(task_id, status="completed", progress=1, result=result)

        body_text = resp.text or ""
        body_preview = body_text[:500] + ("..." if len(body_text) > 500 else "")
        return RepeaterSendResponse(
            task_id=task_id,
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body_preview=body_preview,
            timing_ms=round(elapsed, 1),
        )
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        error_result = {"status_code": 0, "headers": {}, "body": "", "duration_ms": round(elapsed, 1), "error": str(e)}
        await store.update(task_id, status="completed", progress=1, result=error_result)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await engine.close()
