import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from pwnproxy.intruder.generator import read_wordlist

router = APIRouter(prefix="/api/v1", tags=["intruder"])

logger = logging.getLogger(__name__)


class IntruderRunRequest(BaseModel):
    raw_request: str
    mode: str = "sniper"
    wordlist_path: str
    concurrency: int = 10


class IntruderResultItem(BaseModel):
    request_id: int
    payload: str
    status_code: int
    response_length: int
    timing_ms: float
    error: Optional[str] = None


@router.post("/intruder/run")
async def intruder_run(request: Request, body: IntruderRunRequest):
    from pwnproxy.intruder.parser import parse_markers

    from pwnproxy.api.routers.tasks import get_task_store
    store = get_task_store(request)
    engine = request.app.state.intruder_engine
    if not engine:
        raise HTTPException(status_code=503, detail="Intruder engine not available")

    template, markers = parse_markers(body.raw_request)
    if not markers:
        raise HTTPException(status_code=400, detail="No §markers§ found in request")

    wordlist_path = Path(body.wordlist_path)
    if not wordlist_path.exists():
        raise HTTPException(status_code=400, detail=f"Wordlist not found: {body.wordlist_path}")

    wordlist = [w async for w in read_wordlist(str(wordlist_path))]
    if not wordlist:
        raise HTTPException(status_code=400, detail="Empty wordlist")

    session_mgr = getattr(request.app.state, "session_manager", None)
    session_name = session_mgr.active_name if session_mgr else ""

    config = {
        "raw_request": body.raw_request,
        "mode": body.mode,
        "wordlist_path": body.wordlist_path,
        "concurrency": body.concurrency,
    }
    task_id = await store.create("intruder", config, session_name=session_name)

    from pwnproxy.api.routers.tasks import _launch_task_runner
    coro = _launch_task_runner("intruder", config, task_id, store, request)
    store.track(task_id, coro)

    logger.info("Intruder attack %s started: %d words, mode=%s, wordlist=%s",
                task_id, len(wordlist), body.mode, body.wordlist_path)

    return {"attack_id": task_id, "task_id": task_id, "status": "running", "total": len(wordlist)}


@router.get("/intruder/attack/{attack_id}")
async def poll_attack(attack_id: str, request: Request):
    from pwnproxy.api.routers.tasks import get_task_store
    store = get_task_store(request)
    task = await store.get(attack_id)
    if task is None:
        raise HTTPException(status_code=404, detail=f"Attack '{attack_id}' not found")
    return {
        "status": task["status"],
        "total": task["total"],
        "completed": task["progress"],
        "results": task["result"].get("results", []) if task["result"] else [],
        "error": task["error"],
    }
