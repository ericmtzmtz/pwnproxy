import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, sessionmaker

logger = logging.getLogger(__name__)


class CrawlerBase(DeclarativeBase):
    """Dedicated metadata so discovered_urls is never created inside
    traffic.db / scanner_results.db by shared Base.metadata.create_all()."""


class DiscoveredURLORM(CrawlerBase):
    __tablename__ = "discovered_urls"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(Text, nullable=False, unique=True, index=True)
    base_url = Column(Text, default="")
    method = Column(String(10), default="GET")
    source = Column(String(20), default="")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class JobORM(CrawlerBase):
    __tablename__ = "jobs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String(20), nullable=False, default="active")
    status = Column(String(20), nullable=False, default="queued")
    config = Column(Text, nullable=False, default="{}")
    stats = Column(Text, nullable=False, default="{}")
    error = Column(Text, nullable=True)
    tenant_id = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)


class DiscoveredURLStorage:
    def __init__(self, engine):
        self._engine = engine
        self._factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def create_table(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(
                lambda sync_conn: DiscoveredURLORM.__table__.create(sync_conn, checkfirst=True)
            )
            await conn.run_sync(
                lambda sync_conn: JobORM.__table__.create(sync_conn, checkfirst=True)
            )
        # Enable WAL: the crawler worker writes while the API process reads.
        from sqlalchemy import text
        try:
            async with self._engine.begin() as conn:
                await conn.execute(text("PRAGMA journal_mode=WAL"))
        except Exception:
            logger.debug("could not enable WAL on crawler db", exc_info=True)
        # Additive migration for pre-existing tables (FindingStorage pattern).
        async with self._engine.begin() as conn:
            cols = await conn.execute(text("SELECT name FROM pragma_table_info('discovered_urls')"))
            names = {row[0] for row in cols}
            if not names:
                return
            for column, ddl in (
                ("base_url", "TEXT DEFAULT ''"),
                ("method", "VARCHAR(10) DEFAULT 'GET'"),
                ("source", "VARCHAR(20) DEFAULT ''"),
            ):
                if column not in names:
                    await conn.execute(text(f"ALTER TABLE discovered_urls ADD COLUMN {column} {ddl}"))
                    logger.info("Migrated discovered_urls table: added %s column", column)

    async def save(self, url: str, source: str = "", method: str = "GET", base_url: str = "") -> Optional[int]:
        """Insert a discovered URL. Returns the new row id, or None if duplicate."""
        record = DiscoveredURLORM(url=url, source=source or "", method=method or "GET", base_url=base_url or "")
        async with self._factory() as session:
            existing = await session.execute(
                DiscoveredURLORM.__table__.select().where(DiscoveredURLORM.url == url)
            )
            if existing.first() is not None:
                return None
            session.add(record)
            try:
                await session.commit()
            except Exception:
                # Lost a race (unique index) — treat as duplicate.
                await session.rollback()
                return None
            return record.id

    @staticmethod
    def _row_dict(record: DiscoveredURLORM) -> dict:
        return {c.name: getattr(record, c.name) for c in DiscoveredURLORM.__table__.columns}

    async def list(self, source: Optional[str] = None, limit: int = 100, offset: int = 0) -> list[dict]:
        from sqlalchemy import select
        async with self._factory() as session:
            query = select(DiscoveredURLORM)
            if source:
                query = query.where(DiscoveredURLORM.source == source)
            query = query.order_by(DiscoveredURLORM.id.desc()).limit(limit).offset(offset)
            result = await session.execute(query)
            rows = result.scalars().all()
            return [self._row_dict(r) for r in rows]

    async def count(self, source: Optional[str] = None) -> int:
        from sqlalchemy import select, func
        async with self._factory() as session:
            query = select(func.count(DiscoveredURLORM.id))
            if source:
                query = query.where(DiscoveredURLORM.source == source)
            result = await session.execute(query)
            return result.scalar() or 0


class JobStorage:
    def __init__(self, engine):
        self._engine = engine
        self._factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def create(self, job_type: str = "active", config: Optional[dict] = None) -> int:
        """Create a new job and return its id."""
        now = datetime.now(timezone.utc)
        record = JobORM(
            type=job_type,
            status="queued",
            config=json.dumps(config or {}),
            stats="{}",
            created_at=now,
        )
        async with self._factory() as session:
            session.add(record)
            await session.commit()
            return record.id  # type: ignore[return-value]

    async def get(self, job_id: int) -> Optional[dict]:
        """Fetch a job by id, or None."""
        from sqlalchemy import select
        async with self._factory() as session:
            result = await session.execute(
                select(JobORM).where(JobORM.id == job_id)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return None
            return self._row_dict(row)

    async def list_active(self) -> list[dict]:
        """Return all queued or running jobs."""
        from sqlalchemy import select
        async with self._factory() as session:
            result = await session.execute(
                select(JobORM)
                .where(JobORM.status.in_(["queued", "running"]))
                .order_by(JobORM.id)
            )
            return [self._row_dict(r) for r in result.scalars().all()]

    async def list_all(self, limit: int = 50) -> list[dict]:
        """Return jobs ordered by most recent."""
        from sqlalchemy import select
        async with self._factory() as session:
            result = await session.execute(
                select(JobORM).order_by(JobORM.id.desc()).limit(limit)
            )
            return [self._row_dict(r) for r in result.scalars().all()]

    async def update_status(self, job_id: int, status: str, error: Optional[str] = None) -> None:
        """Transition job status; sets started_at/finished_at timestamps."""
        from sqlalchemy import update
        now = datetime.now(timezone.utc)
        values: dict[str, Any] = {"status": status, "error": error}
        if status == "running":
            values["started_at"] = now
        elif status in ("completed", "failed", "stopped"):
            values["finished_at"] = now
        async with self._factory() as session:
            await session.execute(
                update(JobORM).where(JobORM.id == job_id).values(**values)
            )
            await session.commit()

    async def update_stats(self, job_id: int, stats: dict) -> None:
        """Replace the JSON stats blob."""
        from sqlalchemy import update
        async with self._factory() as session:
            await session.execute(
                update(JobORM).where(JobORM.id == job_id).values(stats=json.dumps(stats))
            )
            await session.commit()

    async def mark_stale_running_failed(self) -> int:
        """Mark any jobs stuck in 'running' as 'failed' (crash recovery).
        Returns the number of affected rows."""
        from sqlalchemy import update
        now = datetime.now(timezone.utc)
        async with self._factory() as session:
            result = await session.execute(
                update(JobORM)
                .where(JobORM.status == "running")
                .values(status="failed", error="worker restarted", finished_at=now)
            )
            await session.commit()
            return result.rowcount

    @staticmethod
    def _row_dict(record: JobORM) -> dict:
        return {c.name: getattr(record, c.name) for c in JobORM.__table__.columns}
