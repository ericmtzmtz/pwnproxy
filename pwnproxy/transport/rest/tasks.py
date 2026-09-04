import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from datetime import datetime, timezone

from pwnproxy.shared.schemas import (
    TaskCreateRequest,
    TaskCreateResponse,
    TaskListResponse,
    TaskStatusResponse,
    TaskSummary,
)
from pwnproxy.services.session.store import TaskStore

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
    from apps.terminal.cli.scan import _build_scan_loader, _scan_target
    from pwnproxy.services.findings.engine import ExportEngine

    main_loader = getattr(request.app.state, "plugin_loader", None)
    scanners = config.get("scanners")
    if scanners is not None:
        # ensure it's a set of strings
        if isinstance(scanners, str):
            scanners = set([s.strip() for s in scanners.split(",") if s.strip()])
        elif isinstance(scanners, list):
            scanners = set(scanners)
        else:
            scanners = None
    disabled = []
    if main_loader is not None:
        disabled = main_loader.watchdog_stats().get("disabled", [])
    loader = await _build_scan_loader(scanners, disabled_plugins=disabled)

    await store.update(task_id, status="running", total=1)
    url = config.get("url", "")
    detection_depth = config.get("detection_depth", "fast")
    evasion_level = config.get("evasion_level", "none")
    method = config.get("method", "GET")
    body = config.get("body") or None
    extra_headers: dict[str, str] = {}
    cookies = config.get("cookies")
    if cookies:
        extra_headers["cookie"] = cookies
    raw_headers = config.get("headers")
    if raw_headers and isinstance(raw_headers, dict):
        extra_headers.update(raw_headers)
    content_type = config.get("content_type")
    if content_type:
        extra_headers["Content-Type"] = content_type
    if body and method.upper() in ("GET", "HEAD"):
        # Paridad con el CLI: un cuerpo no tiene sentido en GET/HEAD.
        logger.warning("Scan %s: body ignored for method %s", task_id, method.upper())
        body = None
    findings = await _scan_target(
        loader, url, 60,
        detection_depth=detection_depth,
        evasion_level=evasion_level,
        extra_headers=extra_headers or None,
        method=method,
        body=body,
    )

    # Persist findings to the active session so they show up in /findings
    # and the web UI (not just in the task result).
    try:
        from pwnproxy.shared.findings.storage import FindingStorage
        sm = getattr(request.app.state, "session_manager", None)
        if sm is not None:
            storage = FindingStorage(sm.get_scanner_engine())
            for f in findings:
                # Tag the originating scan so the triage LLM budget is per-scan.
                extra = dict(f.extra or {})
                extra["scan_id"] = task_id
                f.extra = extra
                await storage.save(f)
            logger.info("Persisted %d finding(s) from scan %s", len(findings), task_id)
    except Exception as e:
        logger.warning("Could not persist findings to session: %s", e)

    result_data = ExportEngine(findings).to_dicts() if findings else []
    await store.update(
        task_id,
        status="completed" if not any(f.get("severity") == "error" for f in result_data) else "failed",
        progress=1,
        result={"findings": result_data, "count": len(result_data)},
    )
    hook_bus = request.app.state.hook_bus
    if hook_bus:
        # Calculate duration
        task = await store.get(task_id)
        duration_ms = 0
        if task and task.get("completed_at") and task.get("created_at"):
            try:
                completed_at = datetime.fromisoformat(task["completed_at"])
                created_at = datetime.fromisoformat(task["created_at"])
                duration_ms = int((completed_at - created_at).total_seconds() * 1000)
            except (ValueError, TypeError):
                logger.warning(f"Could not calculate duration for task {task_id}")

        hook_bus.publish("scan.completed", {
            "task_id": task_id,
            "findings_count": len(result_data) if result_data else 0,
            "duration_ms": duration_ms,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })


async def _run_intruder(config: dict, task_id: str, store: TaskStore, request: Request) -> None:
    from pwnproxy.services.intruder.generator import ClusterBombGenerator, SniperGenerator, read_wordlist
    from pwnproxy.services.intruder.parser import parse_markers
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
