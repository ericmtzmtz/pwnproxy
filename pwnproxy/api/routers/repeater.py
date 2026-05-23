from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from pwnproxy.repeater.parser import parse_raw_request

router = APIRouter(prefix="/api/v1", tags=["repeater"])


class RepeaterSendRequest(BaseModel):
    raw_request: str


class RepeaterSendResponse(BaseModel):
    status_code: int
    headers: dict
    body_preview: str
    timing_ms: float


@router.post("/repeater/send")
async def repeater_send(request: Request, body: RepeaterSendRequest):
    engine = request.app.state.repeater_engine
    if not engine:
        raise HTTPException(status_code=503, detail="Repeater engine not available")

    import time
    try:
        parsed = parse_raw_request(body.raw_request)
        start = time.monotonic()
        response = await engine.send(parsed)
        elapsed = (time.monotonic() - start) * 1000

        raw_body = response.content
        body_preview = (raw_body.decode("utf-8", "replace")[:500]
                        + ("..." if len(raw_body) > 500 else "")) if raw_body else ""

        return RepeaterSendResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            body_preview=body_preview,
            timing_ms=round(elapsed, 1),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
