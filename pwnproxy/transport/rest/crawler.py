import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.services.crawler.storage import DiscoveredURLORM

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["crawler"])


async def _get_storage(request: Request):
    """Return DiscoveredURLStorage for the current session (or None)."""
    sm = getattr(request.app.state, "session_manager", None)
    engine = sm.get_crawler_engine() if sm and hasattr(sm, "get_crawler_engine") else None
    if engine is None:
        return None
    from pwnproxy.services.crawler.storage import DiscoveredURLStorage
    return DiscoveredURLStorage(engine)


@router.get("/crawler/urls")
async def list_crawler_urls(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=500),
    source: Optional[str] = Query(None, description="Filter by source (a, form, script, js, img, location)"),
):
    storage = await _get_storage(request)
    if storage is None:
        return {"items": [], "total": 0, "page": page, "per_page": per_page}
    try:
        total = await storage.count(source=source)
        items = await storage.list(source=source, limit=per_page, offset=(page - 1) * per_page)
        return {"items": items, "total": total, "page": page, "per_page": per_page}
    except Exception as exc:
        logger.warning("Could not query crawler URLs: %s", exc)
        return {"items": [], "total": 0, "page": page, "per_page": per_page}


@router.get("/crawler/status")
async def crawler_status(request: Request):
    crawler = getattr(request.app.state, "crawler_process", None)
    if crawler is None:
        return {"running": False}
    return crawler.status()
