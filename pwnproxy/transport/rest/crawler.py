import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.services.crawler.storage import DiscoveredURLORM, JobStorage
from pwnproxy.services.crawler.wordlist import resolve_wordlist, builtin_sizes

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
    job = next((j for j in active if j.get("type") == "active"), None)
    if job is None:
        return {"stopped": False, "detail": "No active crawl job"}

    crawler = getattr(request.app.state, "crawler_process", None)
    if crawler and getattr(crawler, "running", False):
        crawler.send_to_worker("crawl.stop", {"job_id": job["id"]})

    await job_storage.update_status(job["id"], "stopped")
    return {"stopped": True, "job_id": job["id"]}


# ── Bruteforce control ───────────────────────────────────────────────────


class BruteforceStartRequest(BaseModel):
    base_urls: list[str] = Field(..., min_length=1)
    wordlist: str | list[str] = Field("medium")
    extensions: list[str] = Field(default_factory=list)
    status_filter: list[int] = Field(default=[200, 204, 301, 302, 307, 401, 403])
    rate_limit: float = Field(20.0, gt=0, le=200)
    concurrency: int = Field(10, ge=1, le=100)
    max_requests: int = Field(100_000, ge=1, le=2_000_000)
    detect_soft404: bool = Field(True)


@router.post("/bruteforce/start")
async def start_bruteforce(request: Request, body: BruteforceStartRequest):
    job_storage = await _get_job_storage(request)
    if job_storage is None:
        raise HTTPException(status_code=503, detail="Crawler storage unavailable")

    # Only one active job at a time (shared slot with crawl)
    active = await job_storage.list_active()
    if active:
        raise HTTPException(status_code=409, detail="A crawler job is already running")

    # Resolve wordlist
    try:
        resolved_words = resolve_wordlist(body.wordlist)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    if len(resolved_words) < 1:
        raise HTTPException(status_code=422, detail="Wordlist resolved to 0 entries")

    # Validate base_urls are in scope
    sm = getattr(request.app.state, "session_manager", None)
    scope = sm.scope if sm and hasattr(sm, "scope") else None
    if scope and scope.enabled:
        for url in body.base_urls:
            if not scope.is_in_scope(url):
                raise HTTPException(status_code=422, detail=f"Base URL out of scope: {url}")

    config = {
        "base_urls": body.base_urls,
        "wordlist": resolved_words,
        "extensions": body.extensions,
        "status_filter": body.status_filter,
        "rate_limit": body.rate_limit,
        "concurrency": body.concurrency,
        "max_requests": body.max_requests,
        "detect_soft404": body.detect_soft404,
    }
    job_id = await job_storage.create(job_type="bruteforce", config=config)
    await job_storage.update_status(job_id, "running")

    crawler = getattr(request.app.state, "crawler_process", None)
    if crawler is None or not getattr(crawler, "running", False):
        await job_storage.update_status(job_id, "failed", error="Crawler process not running")
        raise HTTPException(status_code=503, detail="Crawler process not running")

    sent = crawler.send_to_worker("bruteforce.start", {"job_id": job_id, "config": config})
    if not sent:
        await job_storage.update_status(job_id, "failed", error="Could not reach crawler worker")
        raise HTTPException(status_code=503, detail="Could not reach crawler worker")

    total_est = len(resolved_words) * (1 + len(body.extensions)) * len(body.base_urls)
    return {"job_id": job_id, "status": "running", "total_estimated": total_est}


@router.post("/bruteforce/stop")
async def stop_bruteforce(request: Request):
    job_storage = await _get_job_storage(request)
    if job_storage is None:
        raise HTTPException(status_code=503, detail="Crawler storage unavailable")

    active = await job_storage.list_active()
    job = next((j for j in active if j.get("type") == "bruteforce"), None)
    if job is None:
        return {"stopped": False, "detail": "No active bruteforce job"}

    crawler = getattr(request.app.state, "crawler_process", None)
    if crawler and getattr(crawler, "running", False):
        crawler.send_to_worker("bruteforce.stop", {"job_id": job["id"]})

    await job_storage.update_status(job["id"], "stopped")
    return {"stopped": True, "job_id": job["id"]}


@router.get("/bruteforce/wordlists")
async def list_wordlists():
    return {"wordlists": [{"name": k, "entries": v} for k, v in builtin_sizes().items()]}


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