import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Integer, Float, String, Text, DateTime, JSON
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
    request_data = Column(JSON, default=None)
    triage_score = Column(Float, default=None)
    triage_verdict = Column(String(20), default=None)
    triage_method = Column(String(10), default=None)
    triage_reason = Column(String(255), default=None)


class TriageHistoryORM(Base):
    __tablename__ = "triage_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, nullable=False, index=True)
    verdict = Column(String(20), nullable=False)
    method = Column(String(10), nullable=False)
    score = Column(Float, default=None)
    reason = Column(String(255), default=None)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class FindingStorage:
    #: Optional async callback fired after each successful save with the persisted row dict.
    #: Wired at startup to the FP-triage pipeline; storage stays usable when unset.
    on_saved = None

    def __init__(self, engine):
        self._engine = engine
        self._factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def create_table(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        # Additive migration: ensure columns exist on pre-existing tables.
        from sqlalchemy import text
        async with self._engine.begin() as conn:
            cols = await conn.execute(text("SELECT name FROM pragma_table_info('findings')"))
            names = {row[0] for row in cols}
            for column, ddl in (
                ("request_data", "JSON"),
                ("triage_score", "FLOAT"),
                ("triage_verdict", "VARCHAR(20)"),
                ("triage_method", "VARCHAR(10)"),
                ("triage_reason", "VARCHAR(255)"),
            ):
                if column not in names:
                    await conn.execute(text(f"ALTER TABLE findings ADD COLUMN {column} {ddl}"))
                    logger.info("Migrated findings table: added %s column", column)

    async def save(self, finding) -> int:
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
            request_data=finding.request_data if hasattr(finding, "request_data") else None,
        )
        async with self._factory() as session:
            persisted = await session.merge(record)
            await session.flush()
            record_id = persisted.id
            await session.commit()
        row = self._row_dict(persisted)
        if self.on_saved is not None:
            asyncio.get_running_loop().create_task(self._notify(row))
        return record_id

    @staticmethod
    def _row_dict(record: FindingORM) -> dict:
        return {c.name: getattr(record, c.name) for c in FindingORM.__table__.columns}

    async def _notify(self, row: dict) -> None:
        try:
            await self.on_saved(row)
        except Exception:
            logger.exception("post-save triage callback failed for finding %s", row.get("id"))

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

    async def get(self, finding_id: int) -> Optional[dict]:
        from sqlalchemy import select
        async with self._factory() as session:
            result = await session.execute(select(FindingORM).where(FindingORM.id == finding_id))
            record = result.scalar_one_or_none()
            return self._row_dict(record) if record else None

    async def set_triage(
        self,
        finding_id: int,
        verdict: str,
        method: str,
        score: Optional[float] = None,
        reason: Optional[str] = None,
        features: Optional[dict] = None,
    ) -> Optional[dict]:
        """Update triage columns and append an immutable history row. Returns updated row."""
        from sqlalchemy import select
        if reason and len(reason) > 255:
            reason = reason[:252] + "..."
        async with self._factory() as session:
            result = await session.execute(select(FindingORM).where(FindingORM.id == finding_id))
            record = result.scalar_one_or_none()
            if record is None:
                return None
            record.triage_verdict = verdict
            record.triage_method = method
            record.triage_score = score
            record.triage_reason = reason
            if features:
                extra = dict(record.extra or {})
                extra["triage_features"] = features
                record.extra = extra
            session.add(TriageHistoryORM(
                finding_id=finding_id, verdict=verdict, method=method, score=score, reason=reason,
            ))
            await session.commit()
            return self._row_dict(record)

    async def iter_all(self):
        """Yield every finding row dict ordered by id (for JSONL export)."""
        from sqlalchemy import select
        async with self._factory() as session:
            result = await session.execute(select(FindingORM).order_by(FindingORM.id.asc()))
            for record in result.scalars():
                yield self._row_dict(record)

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
