"""Worker status aggregation: what is actively working right now.

Answers "which workers (scanners, crawler, proxy, auto-scan) are running and
what have they done recently" — a single endpoint for the UI status strip.
"""

import logging
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["workers"])


class ActiveTask(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str = ""
    type: str = ""
    status: str = ""
    progress: int = 0
    total: int = 0
    created_at: str | None = None


class CrawlerJob(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: Any = None
    type: str = ""
    status: str = ""
    created_at: str | None = None


class AutoScanBatchOut(BaseModel):
    model_config = ConfigDict(extra="allow")

    batch_id: str | None = None
    flows: int = 0
    findings: int = 0
    duration_ms: float = 0.0


class AutoScanStatus(BaseModel):
    model_config = ConfigDict(extra="allow")

    running: bool = False
    active: AutoScanBatchOut | None = None
    last: AutoScanBatchOut | None = None


class ProxyStatus(BaseModel):
    model_config = ConfigDict(extra="allow")

    running: bool = False
    port: int | None = None
    capture_enabled: bool = False


class WorkersResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    tasks: list[ActiveTask] = Field(default_factory=list)
    crawler_jobs: list[CrawlerJob] = Field(default_factory=list)
    autoscan: AutoScanStatus = Field(default_factory=AutoScanStatus)
    proxy: ProxyStatus = Field(default_factory=ProxyStatus)
    #: Same verdict (and same sentence) as ``GET /sessions/scope``: the strip
    #: shows the auto-scan as paused with this reason instead of "idle".
    active_scan_allowed: bool = Field(
        default=True,
        description=(
            "Whether automatically captured traffic is delivered to the active "
            "scanners. Same verdict as GET /sessions/scope."
        ),
    )
    active_scan_blocked_reason: str | None = Field(
        default=None,
        description="Why the auto-scan is paused, ready to display; null when allowed.",
    )


def _active_scan_status(session_manager) -> tuple[bool, str | None]:
    """Return ``(allowed, reason)`` for the auto-scan from the session scope.

    Defensive on purpose (API edge): an app with no session manager or one
    wired to a stand-in must not turn into a 500 on a status endpoint. When the
    scope cannot be read, nothing is claimed to be blocked.
    """
    scope = getattr(session_manager, "scope", None)
    if scope is None:
        return True, None
    try:
        return bool(scope.active_scan_allowed()), scope.active_scan_blocked_reason()
    except (AttributeError, TypeError) as exc:
        logger.warning("workers: could not read the scope: %s", exc)
        return True, None


@router.get("/workers", response_model=WorkersResponse)
async def workers_status(request: Request):
    tasks: list[ActiveTask] = []
    store = getattr(request.app.state, "task_store", None)
    sm = getattr(request.app.state, "session_manager", None)
    if store is not None:
        try:
            session_name = sm.active_name if sm else ""
            rows = await store.list(task_type=None, limit=50, session_name=session_name)
            for t in rows:
                if t.get("status") in ("running", "queued"):
                    tasks.append(ActiveTask(**{k: t.get(k) for k in ActiveTask.model_fields if k in t}))
        except Exception as exc:
            logger.warning("workers: task listing failed: %s", exc)

    crawler_jobs: list[CrawlerJob] = []
    crawler = getattr(request.app.state, "crawler_process", None)
    if crawler is not None:
        try:
            if sm is not None:
                engine = sm.get_crawler_engine() if hasattr(sm, "get_crawler_engine") else None
                if engine is not None:
                    from pwnproxy.services.crawler.storage import JobStorage

                    storage = JobStorage(engine)
                    active = await storage.list_active()
                    for j in active:
                        crawler_jobs.append(CrawlerJob(**{k: j.get(k) for k in CrawlerJob.model_fields if k in j}))
        except Exception as exc:
            logger.warning("workers: crawler job listing failed: %s", exc)

    autoscan = AutoScanStatus()
    tracker = getattr(request.app.state, "autoscan_tracker", None)
    if tracker is not None:
        try:
            st = tracker.status()
            autoscan = AutoScanStatus(
                running=bool(st.get("running")),
                active=AutoScanBatchOut(**st["active"]) if st.get("active") else None,
                last=AutoScanBatchOut(**st["last"]) if st.get("last") else None,
            )
        except Exception as exc:
            logger.warning("workers: autoscan status failed: %s", exc)

    proxy = ProxyStatus()
    if sm is not None:
        pe = sm.get_proxy_engine()
        if pe is not None:
            proxy = ProxyStatus(
                running=bool(getattr(pe, "running", False)),
                port=getattr(sm.proxy_config, "port", None),
                capture_enabled=bool(getattr(sm.proxy_config, "capture_enabled", False)),
            )

    active_scan_allowed, active_scan_blocked_reason = _active_scan_status(sm)

    return WorkersResponse(
        tasks=tasks,
        crawler_jobs=crawler_jobs,
        autoscan=autoscan,
        proxy=proxy,
        active_scan_allowed=active_scan_allowed,
        active_scan_blocked_reason=active_scan_blocked_reason,
    )
