import json
import logging
from pathlib import Path
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from pwnproxy.plugins.scanners.xss.models import Base, XssCanary, XssFinding

logger = logging.getLogger(__name__)


class XssFindingStorage:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path_obj = Path.home() / ".pwnproxy" / "scanner_results.db"
        else:
            db_path_obj = Path(db_path)
        db_path_obj.parent.mkdir(parents=True, exist_ok=True)
        db_url = f"sqlite+aiosqlite:///{db_path_obj.absolute()}"
        self.engine: AsyncEngine = create_async_engine(db_url, echo=False)
        self.session_factory = sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

    async def create_tables(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def save_finding(self, finding: XssFinding) -> None:
        async with self.session_factory() as session:
            session.add(finding)
            await session.commit()

    async def get_findings(self) -> list[XssFinding]:
        from sqlalchemy import select
        async with self.session_factory() as session:
            result = await session.execute(
                select(XssFinding).order_by(XssFinding.timestamp.desc())
            )
            return list(result.scalars().all())

    async def export_json(self, filepath: Optional[str] = None) -> str:
        if filepath is None:
            filepath = str(Path.home() / ".pwnproxy" / "xss_findings.json")
        findings = await self.get_findings()
        data = [
            {
                "id": f.id,
                "method": f.method,
                "url": f.url,
                "param_name": f.param_name,
                "param_location": f.param_location,
                "xss_type": f.xss_type,
                "context": f.context,
                "severity": f.severity,
                "confidence": f.confidence,
                "payload": f.payload,
                "evidence": f.evidence,
                "reflection_url": f.reflection_url,
                "source_flow_id": f.source_flow_id,
                "timestamp": f.timestamp.isoformat(),
            }
            for f in findings
        ]
        Path(filepath).write_text(json.dumps(data, indent=2), encoding="utf-8")
        return filepath

    async def save_canary(self, canary: XssCanary) -> None:
        async with self.session_factory() as session:
            session.add(canary)
            await session.commit()

    async def get_active_canaries(self) -> list[XssCanary]:
        from sqlalchemy import select
        async with self.session_factory() as session:
            result = await session.execute(
                select(XssCanary).where(XssCanary.found == False)
            )
            return list(result.scalars().all())

    async def mark_canary_found(self, canary_id: int, found_url: str) -> None:
        from datetime import datetime
        async with self.session_factory() as session:
            result = await session.execute(
                select(XssCanary).where(XssCanary.id == canary_id)
            )
            canary = result.scalar_one_or_none()
            if canary:
                canary.found = True
                canary.found_url = found_url
                canary.found_at = datetime.now()
                await session.commit()

    async def cleanup_old_canaries(self, max_age_hours: int = 24) -> int:
        from datetime import datetime, timedelta
        from sqlalchemy import delete
        cutoff = datetime.now() - timedelta(hours=max_age_hours)
        async with self.session_factory() as session:
            result = await session.execute(
                delete(XssCanary).where(
                    XssCanary.found == False,
                    XssCanary.injected_at < cutoff,
                )
            )
            await session.commit()
            return result.rowcount
