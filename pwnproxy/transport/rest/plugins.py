import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from pwnproxy.plugins.core.catalog import PluginRecord
from pwnproxy.plugins.core.config import ActivationConfigError
from pwnproxy.plugins.core.loader import (
    PluginLoader,
    PluginNotFoundError,
    PluginUnavailableError,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["plugins"])


class BurpImportRequest(BaseModel):
    config: str


class PluginsListResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    plugins: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None


class PluginToggleResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: str | None = None
    name: str | None = None


class ScanLaunchResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    scan_id: str | None = None
    task_id: str | None = None
    status: str | None = None


class ScanPollResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: str | None = None
    url: str | None = None
    findings_count: int = 0
    findings: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None


class BurpImportResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: str | None = None
    imported: int = 0
    include_count: int | None = None
    exclude_count: int | None = None
    detail: str | None = None


def _plugin_payload(loader: PluginLoader, record: PluginRecord) -> dict[str, Any]:
    """Render one catalog record as a ``GET /plugins`` entry.

    Obligatory fields (always present): ``name``, ``source``, ``package``,
    ``version``, ``enabled``, ``error``. Optional ones (``category``,
    ``description``, ``author``, ``consumes``, ``produces``) come from the
    metadata the *catalog* captured at discovery, so they are also available for
    a plugin that is disabled (and therefore never instantiated); ``loaded`` says
    whether the process has it loaded right now.

    The record's metadata is preferred over the live plugin's on purpose: it is
    the normalized copy (``category`` filled in from the class default), while
    the instance shares the raw class attribute and would report an empty
    category.

    ``enabled`` is the *effective* state: an installed package is off until the
    user turns it on, and a plugin whose discovery/``on_load`` failed reports
    ``false`` even when the configuration says otherwise — reporting it as
    enabled would promise scanning that is not happening.
    """
    metadata = record.metadata
    plugin = loader.get_plugin(record.name)
    payload: dict[str, Any] = {
        "name": record.name,
        "source": record.source,
        "package": record.package,
        "version": record.version,
        "enabled": loader.plugin_enabled(record.name),
        "error": record.error,
        "loaded": plugin is not None,
    }
    if metadata is not None:
        payload.update({
            "category": metadata.category,
            "description": metadata.description,
            "author": metadata.author,
            "consumes": list(metadata.consumes),
            "produces": list(metadata.produces),
        })
    return payload


@router.get(
    "/plugins",
    response_model=PluginsListResponse,
    summary="List every plugin in the catalog (built-in and installed)",
)
async def list_plugins(request: Request):
    """List every plugin in the catalog, disabled and broken ones included.

    Never fails because of a plugin: a broken package shows up with its
    ``error``. Order is stable (built-ins first, then ``name`` ascending) so
    clients do not sort. Without a loader the answer is an empty list plus the
    reason, still ``200``.
    """
    loader: PluginLoader | None = getattr(request.app.state, "plugin_loader", None)
    if loader is None:
        return {"plugins": [], "error": "plugin_loader not available"}
    return {"plugins": [_plugin_payload(loader, record) for record in loader.catalog()], "error": None}


@router.post(
    "/plugins/{name}/toggle",
    response_model=PluginToggleResponse,
    summary="Enable or disable a plugin (machine-wide, persisted)",
    responses={
        404: {"description": "The name is not in the plugin catalog"},
        409: {"description": "The plugin exists but cannot run (broken or failing on_load)"},
        500: {"description": "The config file cannot be written; in-memory state unchanged"},
        503: {"description": "No plugin loader in this process"},
    },
)
async def toggle_plugin(name: str, request: Request):
    """Enable or disable a plugin and persist the decision.

    ``404`` when the name is not in the catalog, ``409`` when it exists but
    cannot run (broken package or failing ``on_load``), ``500`` when the config
    cannot be written (the in-memory state is left untouched). The session is
    never marked as modified: activation is a machine-level setting.
    """
    loader: PluginLoader | None = getattr(request.app.state, "plugin_loader", None)
    if loader is None:
        raise HTTPException(status_code=503, detail="plugin_loader not available")
    try:
        status = await loader.toggle(name)
    except PluginNotFoundError:
        raise HTTPException(status_code=404, detail=f"plugin '{name}' not found") from None
    except PluginUnavailableError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    except ActivationConfigError as exc:
        raise HTTPException(status_code=500, detail=f"could not persist plugin state: {exc}") from None
    return {"status": status, "name": name}


@router.post("/scan", response_model=ScanLaunchResponse)
async def launch_scan(
    url: str,
    request: Request,
    scanners: str = "",
    detection_depth: str = "fast",
    evasion_level: str = "none",
    cookies: str = "",
    headers: str = "",
    method: str = "GET",
    body: str = "",
    content_type: str = "",
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
        "method": method,
    }
    if body:
        config["body"] = body
    if content_type:
        config["content_type"] = content_type
    if session_name:
        config["session_name"] = session_name
    if cookies:
        config["cookies"] = cookies
    if headers:
        import json
        try:
            config["headers"] = json.loads(headers)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="headers must be a valid JSON object") from None
    task_id = await store.create("scan", config, session_name=session_name)

    from pwnproxy.transport.rest.tasks import _launch_task_runner
    coro = _launch_task_runner("scan", config, task_id, store, request)
    store.track(task_id, coro)

    hook_bus = request.app.state.hook_bus
    if hook_bus:
        hook_bus.publish("scan.started", {
            "task_id": task_id,
            "scanners": scanners,
            "target": url,
            "session_id": session_name,
            "timestamp": datetime.now(UTC).isoformat(),
        })
    return {"scan_id": task_id, "task_id": task_id, "status": "running"}


@router.get("/scan/{scan_id}", response_model=ScanPollResponse)
async def poll_scan(scan_id: str, request: Request):
    from pwnproxy.transport.rest.tasks import get_task_store
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
async def export_scan(scan_id: str, request: Request, format: str = "json"):
    from pwnproxy.plugins.core.base import Finding
    from pwnproxy.services.findings.engine import ExportEngine
    from pwnproxy.transport.rest.tasks import get_task_store

    store = get_task_store(request)
    task = await store.get(scan_id)
    if task is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    if task.get("status") != "completed":
        raise HTTPException(status_code=400, detail=f"Scan is {task.get('status')}, not completed")

    findings = []
    for d in (task.get("result") or {}).get("findings", []):
        f = Finding(
            scanner=d["scanner"], url=d["url"], method=d["method"],
            param_name=d.get("param_name", ""), param_location=d.get("param_location", ""),
            technique=d.get("technique", ""), severity=d.get("severity", "medium"),
            confidence=d.get("confidence", "tentative"), payload=d.get("payload", ""),
            evidence=d.get("evidence"),
        )
        findings.append(f)

    engine = ExportEngine(findings, target_url=(task.get("config") or {}).get("url", ""))

    content_type_map = {"json": "application/json", "sarif": "application/json", "html": "text/html", "pdf": "application/pdf"}
    from fastapi.responses import Response

    if format == "pdf":
        pdf = engine.to_pdf()
        if pdf is None or not pdf.endswith(".pdf"):
            return Response(content=engine.to_html(), media_type="text/html")
        return Response(content=Path(pdf).read_bytes(), media_type="application/pdf")

    body = engine.write(format)
    return Response(content=body, media_type=content_type_map.get(format, "text/plain"))


@router.post("/import/burp", response_model=BurpImportResponse)
async def import_burp(request: Request, body: BurpImportRequest):
    try:
        data = json.loads(body.config)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}") from e

    from apps.terminal.cli.import_cmd import _parse_burp_scope

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
        from pwnproxy.transport.rest.session import _restart_crawler_for_scope
        await _restart_crawler_for_scope(request)

    return {
        "status": "ok",
        "imported": len(in_scope) + len(out_scope),
        "include_count": len(in_scope),
        "exclude_count": len(out_scope),
    }
