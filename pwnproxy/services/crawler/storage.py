import logging
from datetime import datetime, timezone
from typing import Optional

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


class DiscoveredURLStorage:
    def __init__(self, engine):
        self._engine = engine
        self._factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def create_table(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(
                lambda sync_conn: DiscoveredURLORM.__table__.create(sync_conn, checkfirst=True)
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
