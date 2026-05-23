import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Request
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


@router.get("/findings/{scanner_name}")
async def get_findings(scanner_name: str, request: Request, limit: int = 100, offset: int = 0):
    table = SCANNER_TABLES.get(scanner_name.lower())
    if not table:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown scanner: {scanner_name}. Available: {list(SCANNER_TABLES.keys())}",
        )
    engine = request.app.state.scanner_engine
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        try:
            result = await session.execute(
                text(f"SELECT * FROM {table} ORDER BY id DESC LIMIT :limit OFFSET :offset"),
                {"limit": limit, "offset": offset},
            )
            rows = result.mappings().all()
            return [dict(row) for row in rows]
        except Exception as exc:
            logger.warning(f"Could not query {table}: {exc}")
            return []


@router.get("/findings")
async def list_all_findings(request: Request, limit: int = 20):
    engine = request.app.state.scanner_engine
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    all_findings: List[Dict[str, Any]] = []
    async with factory() as session:
        for scanner_name, table in SCANNER_TABLES.items():
            try:
                result = await session.execute(
                    text(f"SELECT * FROM {table} ORDER BY id DESC LIMIT :limit"),
                    {"limit": limit},
                )
                rows = result.mappings().all()
                for row in rows:
                    item = dict(row)
                    item["scanner"] = scanner_name
                    all_findings.append(item)
            except Exception as exc:
                logger.debug(f"Could not query {table}: {exc}")
    all_findings.sort(key=lambda x: x.get("id", 0), reverse=True)
    return all_findings[:limit]
