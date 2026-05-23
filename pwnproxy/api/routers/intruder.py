from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from pwnproxy.intruder.generator import ClusterBombGenerator, SniperGenerator, read_wordlist
from pwnproxy.intruder.parser import parse_markers

router = APIRouter(prefix="/api/v1", tags=["intruder"])


class IntruderRunRequest(BaseModel):
    raw_request: str
    mode: str = "sniper"
    wordlist_path: str
    concurrency: int = 10
    max_results: int = 100


class IntruderResultItem(BaseModel):
    request_id: int
    payload: str
    status_code: int
    response_length: int
    timing_ms: float
    error: Optional[str] = None


class IntruderRunResponse(BaseModel):
    total: int
    results: List[IntruderResultItem]


@router.post("/intruder/run")
async def intruder_run(request: Request, body: IntruderRunRequest):
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

    if body.mode == "cluster_bomb":
        wordlists = [wordlist] * len(markers)
        gen = ClusterBombGenerator(template, markers, wordlists)
    else:
        gen = SniperGenerator(template, markers, wordlist)

    total = gen.total_requests
    engine._concurrency = body.concurrency

    results: list[IntruderResultItem] = []
    async for result in engine.execute(gen, total):
        results.append(
            IntruderResultItem(
                request_id=result.request_id,
                payload=result.payload,
                status_code=result.status_code,
                response_length=result.response_length,
                timing_ms=result.timing_ms,
                error=result.error,
            )
        )
        if len(results) >= body.max_results:
            break

    return IntruderRunResponse(total=total, results=results)
