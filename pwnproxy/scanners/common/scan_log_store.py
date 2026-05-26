import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from pwnproxy.scanners.common.models import Base, ScanLog

logger = logging.getLogger(__name__)

_DEFAULT_DB = str(Path.home() / ".pwnproxy" / "scanner_results.db")


class ScanLogStore:
    def __init__(self, db_path: Optional[str] = None):
        path = Path(db_path or _DEFAULT_DB)
        path.parent.mkdir(parents=True, exist_ok=True)
        db_url = f"sqlite+aiosqlite:///{path.absolute()}"
        self.engine = create_async_engine(db_url, echo=False)
        self.session_factory = sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

    async def create_table(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def insert_scan_log(
        self,
        flow_id: str,
        url: str,
        method: str,
        scanner_name: str,
        status: str,
        duration_ms: Optional[float] = None,
        finding_count: int = 0,
    ) -> None:
        now = datetime.utcnow()
        entry = ScanLog(
            flow_id=flow_id,
            url=url,
            method=method,
            scanner_name=scanner_name,
            status=status,
            duration_ms=duration_ms,
            finding_count=finding_count,
            started_at=now,
            completed_at=now,
        )
        async with self.session_factory() as session:
            session.add(entry)
            await session.commit()

    async def query_logs_grouped_by_url(
        self, limit: int = 5000
    ) -> list[dict]:
        sql = text("""
            SELECT
                url,
                method,
                GROUP_CONCAT(DISTINCT scanner_name) AS scanners,
                SUM(finding_count) AS total_findings,
                MAX(completed_at) AS last_scanned,
                AVG(duration_ms) AS avg_duration_ms
            FROM scan_log
            GROUP BY url
            ORDER BY last_scanned DESC
            LIMIT :limit
        """)
        async with self.session_factory() as session:
            result = await session.execute(sql, {"limit": limit})
            rows = []
            for row in result:
                rows.append({
                    "url": row.url,
                    "method": row.method,
                    "scanners": row.scanners,
                    "total_findings": row.total_findings or 0,
                    "last_scanned": str(row.last_scanned) if row.last_scanned else "",
                    "avg_duration_ms": round(row.avg_duration_ms, 1) if row.avg_duration_ms else 0,
                })
            return rows

    async def query_findings_for_url(
        self, url: str, limit: int = 100
    ) -> list[dict]:
        sql = text("""
            SELECT flow_id, scanner_name, status, finding_count, duration_ms, completed_at
            FROM scan_log
            WHERE url = :url
            ORDER BY completed_at DESC
            LIMIT :limit
        """)
        async with self.session_factory() as session:
            result = await session.execute(sql, {"url": url, "limit": limit})
            rows = []
            for row in result:
                rows.append({
                    "flow_id": row.flow_id,
                    "scanner_name": row.scanner_name,
                    "status": row.status,
                    "finding_count": row.finding_count,
                    "duration_ms": round(row.duration_ms, 1) if row.duration_ms else 0,
                    "completed_at": str(row.completed_at) if row.completed_at else "",
                })
            return rows

    async def dispose(self) -> None:
        await self.engine.dispose()
