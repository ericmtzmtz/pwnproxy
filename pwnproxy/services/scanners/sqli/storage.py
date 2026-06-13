import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from pwnproxy.services.scanners.sqli.models import Base, ScanFinding

logger = logging.getLogger(__name__)


class FindingStorage:
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

    async def save_finding(self, finding: ScanFinding) -> None:
        async with self.session_factory() as session:
            session.add(finding)
            await session.commit()

    async def get_findings(self) -> list[ScanFinding]:
        from sqlalchemy import select
        async with self.session_factory() as session:
            result = await session.execute(
                select(ScanFinding).order_by(ScanFinding.timestamp.desc())
            )
            return list(result.scalars().all())

    async def export_json(self, filepath: Optional[str] = None) -> str:
        if filepath is None:
            filepath = str(Path.home() / ".pwnproxy" / "sqli_findings.json")
        findings = await self.get_findings()
        data = [
            {
                "id": f.id,
                "method": f.method,
                "url": f.url,
                "param_name": f.param_name,
                "param_location": f.param_location,
                "technique": f.technique,
                "dbms": f.dbms,
                "severity": f.severity,
                "confidence": f.confidence,
                "payload": f.payload,
                "evidence": f.evidence,
                "baseline_ms": f.baseline_ms,
                "response_ms": f.response_ms,
                "source_flow_id": f.source_flow_id,
                "timestamp": f.timestamp.isoformat(),
            }
            for f in findings
        ]
        Path(filepath).write_text(json.dumps(data, indent=2), encoding="utf-8")
        return filepath
