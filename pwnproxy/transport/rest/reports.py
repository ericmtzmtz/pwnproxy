import asyncio
import logging
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict

from pwnproxy.services.session.manager import SESSIONS_ROOT
from pwnproxy.transport.rest.tasks import get_task_store

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["reports"])

_MEDIA_TYPES = {
    "md": "text/markdown",
    "html": "text/html",
    "pdf": "application/pdf",
}


class ReportGenerateRequest(BaseModel):
    audience: Literal["executive", "technical", "remediation"] = "technical"
    formats: list[Literal["md", "html", "pdf"]] = ["md"]


class ReportGenerateResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    task_id: str = ""


@router.post("/reports/generate", status_code=202, response_model=ReportGenerateResponse)
async def generate_report(request: Request, body: ReportGenerateRequest):
    from sqlalchemy import func, select
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm import sessionmaker

    from pwnproxy.shared.findings.storage import FindingORM

    mgr = getattr(request.app.state, "session_manager", None)
    if mgr is None or not mgr.has_active_session:
        raise HTTPException(status_code=409, detail="No active session")

    engine = mgr.get_scanner_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        total = (await session.execute(select(func.count(FindingORM.id)))).scalar() or 0
    if total == 0:
        raise HTTPException(
            status_code=409,
            detail="Session has no findings: run a scan first before generating a report",
        )

    llm = getattr(request.app.state, "llm_client", None)
    if llm is None:
        raise HTTPException(status_code=503, detail="LLM client not available")

    store = get_task_store(request)
    session_name = mgr.active_name or "default"
    config = {
        "audience": body.audience,
        "formats": list(body.formats),
        "session": session_name,
    }
    task_id = await store.create("report", config, session_name=session_name)
    store.track(task_id, _run_report(task_id, config, store, request))
    return {"task_id": task_id}


async def _run_report(task_id: str, config: dict, store, request: Request) -> None:
    try:
        await _generate_report_artifacts(task_id, config, store, request)
    except asyncio.CancelledError:
        await store.update(task_id, status="cancelled")
    except Exception as e:
        logger.exception("Report task %s failed", task_id)
        await store.update(task_id, status="failed", error=str(e))


async def _generate_report_artifacts(task_id: str, config: dict, store, request: Request) -> None:
    from pwnproxy.ai.reports.generator import ReportGenerator
    from pwnproxy.shared.findings.storage import FindingStorage

    mgr = request.app.state.session_manager
    findings = await FindingStorage(mgr.get_scanner_engine()).list(limit=100_000)

    async def progress(phase: str, pct: int) -> None:
        await store.update(task_id, status="running", progress=pct, total=100, result={"phase": phase})

    out_dir = SESSIONS_ROOT / config.get("session", "default") / "reports" / task_id
    generator = ReportGenerator(request.app.state.llm_client, session_name=config.get("session", ""))
    result = await generator.generate(
        findings,
        out_dir,
        audience=config.get("audience", "technical"),
        formats=tuple(config.get("formats", ["md"])),
        progress=progress,
    )
    result["report_dir"] = f"{config.get('session', 'default')}/reports/{task_id}"
    await store.update(task_id, status="completed", progress=100, total=100, result=result)


@router.get("/reports/{task_id}/download")
async def download_report(task_id: str, request: Request, format: str = Query("md")):
    if format not in _MEDIA_TYPES:
        raise HTTPException(status_code=400, detail=f"Unsupported format '{format}'. Valid: md, html, pdf")

    store = get_task_store(request)
    task = await store.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.get("type") != "report":
        raise HTTPException(status_code=400, detail=f"Task {task_id} is not a report")

    result = task.get("result") or {}
    files = result.get("files") or {}
    filename = files.get(format)
    if not filename:
        available = ", ".join(sorted(files)) or "none"
        raise HTTPException(status_code=404, detail=f"No '{format}' artifact. Available: {available}")

    report_dir = SESSIONS_ROOT / str(result.get("report_dir") or "")
    path = report_dir / filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Report file no longer exists on disk")

    return FileResponse(
        path,
        media_type=_MEDIA_TYPES[format],
        filename=f"pwnproxy-report-{task_id}.{format}",
    )
