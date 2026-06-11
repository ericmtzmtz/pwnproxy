import json
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from pwnproxy.plugin.loader import PluginLoader

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["plugins"])


class BurpImportRequest(BaseModel):
    config: str


@router.get("/plugins")
async def list_plugins(request: Request):
    loader: Optional[PluginLoader] = getattr(request.app.state, "plugin_loader", None)
    if loader is None:
        return {"error": "plugin_loader not available", "plugins": []}
    return {"plugins": loader.list_active()}


@router.post("/plugins/{name}/toggle")
async def toggle_plugin(name: str, request: Request):
    loader: Optional[PluginLoader] = getattr(request.app.state, "plugin_loader", None)
    if loader is None:
        raise HTTPException(status_code=503, detail="plugin_loader not available")
    plugin = loader.get_plugin(name)
    if plugin is None:
        raise HTTPException(status_code=404, detail=f"Plugin '{name}' not found")

    stats = loader.watchdog_stats()
    if name in stats.get("disabled", []):
        await loader.activate(name)
        status = "enabled"
    else:
        loader.deactivate(name)
        status = "disabled"

    mgr = getattr(request.app.state, "session_manager", None)
    if mgr:
        mgr.mark_unsaved()

    return {"status": status, "name": name}


@router.post("/scan")
async def launch_scan(
    url: str,
    request: Request,
    scanners: str = "",
    detection_depth: str = "fast",
    evasion_level: str = "none",
):
    mgr = getattr(request.app.state, "session_manager", None)
    store = mgr.task_store if mgr and mgr.task_store else getattr(request.app.state, "task_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="Task store not available")
    session_name = mgr.active_name if mgr else ""

    config = {
        "url": url,
        "scanners": scanners,
        "detection_depth": detection_depth,
        "evasion_level": evasion_level,
    }
    task_id = await store.create("scan", config, session_name=session_name)

    from pwnproxy.api.routers.tasks import _launch_task_runner
    coro = _launch_task_runner("scan", config, task_id, store, request)
    store.track(task_id, coro)

    return {"scan_id": task_id, "task_id": task_id, "status": "running"}


@router.get("/scan/{scan_id}")
async def poll_scan(scan_id: str, request: Request):
    from pwnproxy.api.routers.tasks import get_task_store
    store = get_task_store(request)
    task = await store.get(scan_id)
    if task is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return {
        "status": task["status"],
        "url": task["config"].get("url", ""),
        "findings_count": len(task["result"].get("findings", [])) if task["result"] else 0,
        "findings": task["result"].get("findings", []) if task["result"] else [],
        "error": task["error"],
    }


@router.get("/export/{scan_id}")
async def export_scan(scan_id: str, format: str = "json"):
    from pwnproxy.export.engine import ExportEngine
    from pwnproxy.plugin.base import Finding

    task = _scan_tasks.get(scan_id)
    if task is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    if task["status"] != "completed":
        raise HTTPException(status_code=400, detail=f"Scan is {task['status']}, not completed")

    findings = []
    for d in task["findings"]:
        f = Finding(
            scanner=d["scanner"], url=d["url"], method=d["method"],
            param_name=d.get("param_name", ""), param_location=d.get("param_location", ""),
            technique=d.get("technique", ""), severity=d.get("severity", "medium"),
            confidence=d.get("confidence", "tentative"), payload=d.get("payload", ""),
            evidence=d.get("evidence"),
        )
        findings.append(f)

    engine = ExportEngine(findings, target_url=task["url"])

    content_type_map = {"json": "application/json", "sarif": "application/json", "html": "text/html", "pdf": "application/pdf"}
    from fastapi.responses import Response

    if format == "pdf":
        pdf = engine.to_pdf()
        if pdf is None or not pdf.endswith(".pdf"):
            return Response(content=engine.to_html(), media_type="text/html")
        return Response(content=Path(pdf).read_bytes(), media_type="application/pdf")

    body = engine.write(format)
    return Response(content=body, media_type=content_type_map.get(format, "text/plain"))


@router.post("/import/burp")
async def import_burp(request: Request, body: BurpImportRequest):
    try:
        data = json.loads(body.config)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")

    from pwnproxy.cli.import_cmd import _parse_burp_scope

    raw = _parse_burp_scope(data)
    if raw is None:
        return {"status": "ok", "imported": 0, "detail": "No scope found"}

    in_scope = [r for r in raw.get("include", []) if r]
    out_scope = [r for r in raw.get("exclude", []) if r]

    manager = getattr(request.app.state, "session_manager", None)
    if manager:
        manager.scope.in_scope = in_scope
        manager.scope.out_of_scope = out_scope
        manager.scope.enabled = True
        manager.mark_unsaved()

    return {
        "status": "ok",
        "imported": len(in_scope) + len(out_scope),
        "include_count": len(in_scope),
        "exclude_count": len(out_scope),
    }
