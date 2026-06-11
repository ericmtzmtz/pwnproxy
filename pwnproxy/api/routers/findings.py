import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["findings"])

SCANNER_TABLES: Dict[str, str] = {
    "sqli": "scan_findings",
    "xss": "xss_findings",
    "lfi": "lfi_findings",
    "xxe": "xxe_findings",
    "ssrf": "ssrf_findings",
}


def _severity_clause(severity: Optional[str]) -> str:
    if not severity:
        return ""
    levels = [s.strip() for s in severity.split(",") if s.strip()]
    if not levels:
        return ""
    quoted = ", ".join(f"'{s}'" for s in levels)
    return f"AND severity IN ({quoted})"


def _count_sql(table: str, severity_clause: str) -> str:
    return f"SELECT COUNT(*) as cnt FROM {table} WHERE 1=1 {severity_clause}"


def _select_sql(table: str, severity_clause: str, limit: int, offset: int) -> str:
    return f"SELECT * FROM {table} WHERE 1=1 {severity_clause} ORDER BY id DESC LIMIT {limit} OFFSET {offset}"


@router.get("/findings/{scanner_name}")
async def get_findings(
    scanner_name: str,
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=500),
    severity: Optional[str] = Query(None, description="Comma-separated severity levels"),
):
    table = SCANNER_TABLES.get(scanner_name.lower())
    if not table:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown scanner: {scanner_name}. Available: {list(SCANNER_TABLES.keys())}",
        )
    sev_clause = _severity_clause(severity)
    offset = (page - 1) * per_page
    engine = request.app.state.scanner_engine
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        try:
            count_result = await session.execute(
                text(_count_sql(table, sev_clause))
            )
            total = count_result.scalar() or 0

            result = await session.execute(
                text(_select_sql(table, sev_clause, per_page, offset))
            )
            rows = result.mappings().all()
            items = [dict(row) for row in rows]
            for item in items:
                item["scanner"] = scanner_name
            return {"items": items, "total": total, "page": page, "per_page": per_page}
        except Exception as exc:
            logger.warning(f"Could not query {table}: {exc}")
            return {"items": [], "total": 0, "page": page, "per_page": per_page}


@router.get("/findings")
async def list_all_findings(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=500),
    severity: Optional[str] = Query(None, description="Comma-separated severity levels"),
):
    sev_clause = _severity_clause(severity)
    offset = (page - 1) * per_page
    engine = request.app.state.scanner_engine
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    all_findings: List[Dict[str, Any]] = []
    total = 0
    async with factory() as session:
        for scanner_name, table in SCANNER_TABLES.items():
            try:
                count_result = await session.execute(
                    text(_count_sql(table, sev_clause))
                )
                total += count_result.scalar() or 0

                result = await session.execute(
                    text(_select_sql(table, sev_clause, per_page + offset, 0))
                )
                rows = result.mappings().all()
                for row in rows:
                    item = dict(row)
                    item["scanner"] = scanner_name
                    all_findings.append(item)
            except Exception as exc:
                logger.debug(f"Could not query {table}: {exc}")

    all_findings.sort(key=lambda x: x.get("id", 0), reverse=True)
    paginated = all_findings[offset:offset + per_page]
    return {"items": paginated, "total": total, "page": page, "per_page": per_page}


@router.delete("/findings/{scanner_name}/{finding_id}", status_code=204)
async def delete_finding(scanner_name: str, finding_id: int, request: Request):
    table = SCANNER_TABLES.get(scanner_name.lower())
    if not table:
        raise HTTPException(status_code=404, detail=f"Unknown scanner: {scanner_name}")
    engine = request.app.state.scanner_engine
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        try:
            await session.execute(text(f"DELETE FROM {table} WHERE id = :id"), {"id": finding_id})
            await session.commit()
        except Exception as exc:
            logger.warning(f"Could not delete from {table}: {exc}")
            raise HTTPException(status_code=500, detail=str(exc))
