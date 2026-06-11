import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request

from pwnproxy.task.schemas import (
    TaskCreateRequest,
    TaskCreateResponse,
    TaskListResponse,
    TaskStatusResponse,
    TaskSummary,
)
from pwnproxy.task.store import TaskStore

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["tasks"])


def _get_store(request: Request) -> TaskStore:
    return get_task_store(request)


def get_task_store(request: Request) -> TaskStore:
    """Get the session-scoped task store, falling back to app.state."""
    mgr = getattr(request.app.state, "session_manager", None)
    if mgr and mgr.task_store:
        return mgr.task_store
    store: Optional[TaskStore] = getattr(request.app.state, "task_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="Task store not available")
    return store


@router.post("/tasks", response_model=TaskCreateResponse, status_code=201)
async def create_task(request: Request, body: TaskCreateRequest):
    store = _get_store(request)
    session_mgr = getattr(request.app.state, "session_manager", None)
    session_name = session_mgr.active_name if session_mgr else ""

    task_id = await store.create(body.type, body.config, session_name=session_name)

    coro = _launch_task_runner(body.type, body.config, task_id, store, request)
    store.track(task_id, coro)

    return TaskCreateResponse(task_id=task_id)


async def _launch_task_runner(
    task_type: str,
    config: dict,
    task_id: str,
    store: TaskStore,
    request: Request,
) -> None:
    try:
        if task_type == "scan":
            await _run_scan(config, task_id, store, request)
        elif task_type == "intruder":
            await _run_intruder(config, task_id, store, request)
        else:
            await store.update(task_id, status="failed", error=f"Unknown task type: {task_type}")
    except asyncio.CancelledError:
        await store.update(task_id, status="cancelled")
    except Exception as e:
        logger.exception("Task %s failed", task_id)
        await store.update(task_id, status="failed", error=str(e))


async def _run_scan(config: dict, task_id: str, store: TaskStore, request: Request) -> None:
    from pwnproxy.cli.scan import _build_scan_loader, _scan_target
    from pwnproxy.export.engine import ExportEngine

    main_loader = getattr(request.app.state, "plugin_loader", None)
    loader = await _build_scan_loader()
    if main_loader is not None:
        disabled = main_loader.watchdog_stats().get("disabled", [])
        for name in disabled:
            loader.deactivate(name)

    await store.update(task_id, status="running", total=1)
    url = config.get("url", "")
    detection_depth = config.get("detection_depth", "fast")
    evasion_level = config.get("evasion_level", "none")
    findings = await _scan_target(loader, url, 60, detection_depth=detection_depth, evasion_level=evasion_level)
    result_data = ExportEngine(findings).to_dicts() if findings else []
    await store.update(
        task_id,
        status="completed" if not any(f.get("severity") == "error" for f in result_data) else "failed",
        progress=1,
        result={"findings": result_data, "count": len(result_data)},
    )


async def _run_intruder(config: dict, task_id: str, store: TaskStore, request: Request) -> None:
    from pwnproxy.intruder.generator import ClusterBombGenerator, SniperGenerator, read_wordlist
    from pwnproxy.intruder.parser import parse_markers
    from pathlib import Path

    engine = getattr(request.app.state, "intruder_engine", None)
    if engine is None:
        await store.update(task_id, status="failed", error="Intruder engine not available")
        return

    raw_request = config.get("raw_request", "")
    mode = config.get("mode", "sniper")
    wordlist_path = config.get("wordlist_path", "")
    concurrency = config.get("concurrency", 10)

    template, markers = parse_markers(raw_request)
    wordlist = [w async for w in read_wordlist(str(Path(wordlist_path)))]
    if mode == "cluster_bomb":
        wordlists = [wordlist] * len(markers)
        gen = ClusterBombGenerator(template, markers, wordlists)
    else:
        gen = SniperGenerator(template, markers, wordlist)

    total = gen.total_requests
    engine._concurrency = concurrency
    await store.update(task_id, status="running", total=total)

    results: list[dict] = []
    async for result in engine.execute(gen, total):
        results.append({
            "request_id": result.request_id,
            "payload": result.payload,
            "status_code": result.status_code,
            "response_length": result.response_length,
            "timing_ms": result.timing_ms,
            "response_headers": result.response_headers,
            "response_body": result.response_body,
            "error": result.error,
        })
        await store.update(task_id, progress=len(results))

    await store.update(task_id, status="completed", progress=total, result={"results": results})


@router.get("/tasks", response_model=TaskListResponse)
async def list_tasks(
    request: Request,
    type: str = Query(None, alias="type"),
    limit: int = Query(50, ge=1, le=200),
):
    store = _get_store(request)
    session_mgr = getattr(request.app.state, "session_manager", None)
    session_name = session_mgr.active_name if session_mgr else ""

    tasks = await store.list(task_type=type, limit=limit, session_name=session_name)
    total = await store.count(task_type=type, session_name=session_name)
    summaries = [TaskSummary(**{k: t[k] for k in TaskSummary.model_fields.keys() if k in t}) for t in tasks]
    return TaskListResponse(tasks=summaries, total=total)


@router.get("/tasks/{task_id}", response_model=TaskStatusResponse)
async def get_task(task_id: str, request: Request):
    store = _get_store(request)
    task = await store.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return TaskStatusResponse(**task)


@router.post("/tasks/{task_id}/cancel", response_model=TaskStatusResponse)
async def cancel_task(task_id: str, request: Request):
    store = _get_store(request)
    ok = await store.cancel(task_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Task not found")
    task = await store.get(task_id)
    return TaskStatusResponse(**task)

@router.delete("/tasks/{task_id}", status_code=204)
async def delete_task(task_id: str, request: Request):
    store = _get_store(request)
    ok = await store.delete(task_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Task not found")
