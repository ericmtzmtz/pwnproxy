import time
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from pwnproxy.intruder.engine import _parse_raw_from_template

router = APIRouter(prefix="/api/v1", tags=["repeater"])


class RepeaterSendRequest(BaseModel):
    raw_request: str


class RepeaterSendResponse(BaseModel):
    task_id: str
    status_code: int
    headers: dict
    body_preview: str
    timing_ms: float


@router.post("/repeater/send")
async def repeater_send(request: Request, body: RepeaterSendRequest):
    store = getattr(request.app.state, "task_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="Task store not available")

    session_mgr = getattr(request.app.state, "session_manager", None)
    session_name = session_mgr.active_name if session_mgr else ""

    config = {"raw_request": body.raw_request}
    task_id = await store.create("repeater", config, session_name=session_name)

    await store.update(task_id, status="running", total=1)
    start = time.monotonic()
    try:
        parsed = _parse_raw_from_template(body.raw_request)
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            resp = await client.request(
                method=parsed["method"],
                url=parsed["url"],
                headers=parsed["headers"],
                content=parsed["body"],
            )
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
