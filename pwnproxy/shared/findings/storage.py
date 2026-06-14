import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.shared.db import Base

logger = logging.getLogger(__name__)


class FindingORM(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scanner = Column(String(50), nullable=False, index=True)
    url = Column(Text, nullable=False)
    method = Column(String(10), default="GET")
    param_name = Column(String(255), default="")
    param_location = Column(String(50), default="query")
    technique = Column(String(100), default="")
    severity = Column(String(20), default="medium")
    confidence = Column(String(20), default="tentative")
    payload = Column(Text, default="")
    evidence = Column(Text, default="")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    extra = Column(JSON, default=dict)


class FindingStorage:
    def __init__(self, engine):
        self._engine = engine
        self._factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def create_table(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def save(self, finding) -> None:
        from pwnproxy.plugins.core.base import Finding as BaseFinding
        record = FindingORM(
            scanner=finding.scanner,
            url=finding.url,
            method=finding.method,
            param_name=finding.param_name,
            param_location=finding.param_location,
            technique=finding.technique,
            severity=finding.severity,
            confidence=finding.confidence,
            payload=finding.payload,
            evidence=finding.evidence,
            timestamp=finding.timestamp,
            extra=finding.extra if hasattr(finding, "extra") else {},
        )
        async with self._factory() as session:
            await session.merge(record)
            await session.commit()

    async def list(self, scanner: Optional[str] = None, limit: int = 100, offset: int = 0) -> list[dict]:
        from sqlalchemy import select
        async with self._factory() as session:
            query = select(FindingORM)
            if scanner:
                query = query.where(FindingORM.scanner == scanner)
            query = query.order_by(FindingORM.id.desc()).limit(limit).offset(offset)
            result = await session.execute(query)
            rows = result.scalars().all()
            return [{c.name: getattr(r, c.name) for c in FindingORM.__table__.columns} for r in rows]

    async def count(self, scanner: Optional[str] = None) -> int:
        from sqlalchemy import select, func
        async with self._factory() as session:
            query = select(func.count(FindingORM.id))
            if scanner:
                query = query.where(FindingORM.scanner == scanner)
            result = await session.execute(query)
            return result.scalar() or 0

    async def delete(self, finding_id: int) -> bool:
        from sqlalchemy import select
        async with self._factory() as session:
            result = await session.execute(select(FindingORM).where(FindingORM.id == finding_id))
            record = result.scalar_one_or_none()
            if record:
                await session.delete(record)
                await session.commit()
                return True
            return False
