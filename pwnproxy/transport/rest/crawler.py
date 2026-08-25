import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.services.crawler.storage import DiscoveredURLORM, JobStorage

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["crawler"])


# ── Helpers ──────────────────────────────────────────────────────────────


async def _get_job_storage(request: Request) -> Optional[JobStorage]:
    sm = getattr(request.app.state, "session_manager", None)
    engine = sm.get_crawler_engine() if sm and hasattr(sm, "get_crawler_engine") else None
    if engine is None:
        return None
    return JobStorage(engine)


async def _get_discovered_storage(request: Request):
    sm = getattr(request.app.state, "session_manager", None)
    engine = sm.get_crawler_engine() if sm and hasattr(sm, "get_crawler_engine") else None
    if engine is None:
        return None
    from pwnproxy.services.crawler.storage import DiscoveredURLStorage
    return DiscoveredURLStorage(engine)


# ── Discovered URLs ──────────────────────────────────────────────────────


@router.get("/crawler/urls")
async def list_crawler_urls(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=500),
    source: Optional[str] = Query(None, description="Filter by source (a, form, script, js, img, location)"),
):
    storage = await _get_discovered_storage(request)
    if storage is None:
        return {"items": [], "total": 0, "page": page, "per_page": per_page}
    try:
        total = await storage.count(source=source)
        items = await storage.list(source=source, limit=per_page, offset=(page - 1) * per_page)
        return {"items": items, "total": total, "page": page, "per_page": per_page}
    except Exception as exc:
        logger.warning("Could not query crawler URLs: %s", exc)
        return {"items": [], "total": 0, "page": page, "per_page": per_page}


# ── Active crawl control ─────────────────────────────────────────────────


class CrawlStartRequest(BaseModel):
    seeds: list[str] = Field(..., min_length=1)
    depth: int = Field(3, ge=1, le=10)
    rate_limit: float = Field(10.0, gt=0, le=100)
    concurrency: int = Field(5, ge=1, le=50)
    max_urls: int = Field(1000, ge=1, le=50000)
    respect_robots: bool = False
    include_discovered: bool = False
    scan_while_crawl: bool = False


@router.post("/crawler/start")
async def start_crawl(request: Request, body: CrawlStartRequest):
    """Create a crawl job and start the worker."""
    job_storage = await _get_job_storage(request)
    if job_storage is None:
        raise HTTPException(status_code=503, detail="Crawler storage unavailable")

    # Only one active job at a time.
    active = await job_storage.list_active()
    if active:
        raise HTTPException(status_code=409, detail="A crawl job is already running")

    config = {
        "seeds": body.seeds,
        "depth": body.depth,
        "rate_limit": body.rate_limit,
        "concurrency": body.concurrency,
        "max_urls": body.max_urls,
        "respect_robots": body.respect_robots,
        "include_discovered": body.include_discovered,
        "scan_while_crawl": body.scan_while_crawl,
    }
    job_id = await job_storage.create(job_type="active", config=config)
    await job_storage.update_status(job_id, "running")

    crawler = getattr(request.app.state, "crawler_process", None)
    if crawler is None or not getattr(crawler, "running", False):
        await job_storage.update_status(job_id, "failed", error="Crawler process not running")
        raise HTTPException(status_code=503, detail="Crawler process not running")

    sent = crawler.send_to_worker("crawl.start", {"job_id": job_id, "config": config})
    if not sent:
        await job_storage.update_status(job_id, "failed", error="Could not reach crawler worker")
        raise HTTPException(status_code=503, detail="Could not reach crawler worker")

    return {"job_id": job_id, "status": "running"}


@router.post("/crawler/stop")
async def stop_crawl(request: Request):
    """Stop the active crawl job."""
    job_storage = await _get_job_storage(request)
    if job_storage is None:
        raise HTTPException(status_code=503, detail="Crawler storage unavailable")

    active = await job_storage.list_active()
    if not active:
        return {"stopped": False, "detail": "No active crawl job"}

    job = active[0]
    crawler = getattr(request.app.state, "crawler_process", None)
    if crawler and getattr(crawler, "running", False):
        crawler.send_to_worker("crawl.stop", {"job_id": job["id"]})

    await job_storage.update_status(job["id"], "stopped")
    return {"stopped": True, "job_id": job["id"]}


# ── Status ───────────────────────────────────────────────────────────────


@router.get("/crawler/status")
async def crawler_status(request: Request):
    crawler = getattr(request.app.state, "crawler_process", None)
    process_status = crawler.status() if crawler else {"running": False}

    job_storage = await _get_job_storage(request)
    jobs = []
    if job_storage:
        try:
            active = await job_storage.list_active()
            jobs = active
        except Exception:
            pass

    return {
        **process_status,
        "active_jobs": jobs,
    }
