import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.shared.findings.storage import FindingORM

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["findings"])


def _severity_clause(severity: Optional[str]) -> list:
    if not severity:
        return []
    return [s.strip() for s in severity.split(",") if s.strip()]


def _apply_filters(query, scanner: Optional[str] = None, severity: Optional[str] = None):
    if scanner:
        query = query.where(FindingORM.scanner == scanner)
    levels = _severity_clause(severity)
    if levels:
        query = query.where(FindingORM.severity.in_(levels))
    return query


@router.get("/findings/{scanner_name}")
async def get_findings(
    scanner_name: str,
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=500),
    severity: Optional[str] = Query(None, description="Comma-separated severity levels"),
):
    offset = (page - 1) * per_page
    engine = request.app.state.session_manager.get_scanner_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        try:
            count_q = _apply_filters(select(func.count(FindingORM.id)), scanner_name, severity)
            total = (await session.execute(count_q)).scalar() or 0

            sel_q = _apply_filters(select(FindingORM), scanner_name, severity)
            sel_q = sel_q.order_by(FindingORM.id.desc()).limit(per_page).offset(offset)
            result = await session.execute(sel_q)
            rows = result.scalars().all()
            items = [{c.name: getattr(r, c.name) for c in FindingORM.__table__.columns} for r in rows]
            return {"items": items, "total": total, "page": page, "per_page": per_page}
        except Exception as exc:
            logger.warning(f"Could not query findings: {exc}")
            return {"items": [], "total": 0, "page": page, "per_page": per_page}


@router.get("/findings")
async def list_all_findings(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=500),
    severity: Optional[str] = Query(None, description="Comma-separated severity levels"),
):
    offset = (page - 1) * per_page
    engine = request.app.state.session_manager.get_scanner_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        try:
            count_q = _apply_filters(select(func.count(FindingORM.id)), severity=severity)
            total = (await session.execute(count_q)).scalar() or 0

            sel_q = _apply_filters(select(FindingORM), severity=severity)
            sel_q = sel_q.order_by(FindingORM.id.desc()).limit(per_page).offset(offset)
            result = await session.execute(sel_q)
            rows = result.scalars().all()
            items = [{c.name: getattr(r, c.name) for c in FindingORM.__table__.columns} for r in rows]
            return {"items": items, "total": total, "page": page, "per_page": per_page}
        except Exception as exc:
            logger.warning(f"Could not query findings: {exc}")
            return {"items": [], "total": 0, "page": page, "per_page": per_page}


@router.delete("/findings/{finding_id}", status_code=204)
async def delete_finding(finding_id: int, request: Request):
    engine = request.app.state.session_manager.get_scanner_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        try:
            result = await session.execute(select(FindingORM).where(FindingORM.id == finding_id))
            record = result.scalar_one_or_none()
            if not record:
                raise HTTPException(status_code=404, detail="Finding not found")
            await session.delete(record)
            await session.commit()
        except HTTPException:
            raise
        except Exception as exc:
            logger.warning(f"Could not delete finding: {exc}")
            raise HTTPException(status_code=500, detail=str(exc))
