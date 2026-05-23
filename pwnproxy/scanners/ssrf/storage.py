import json
import logging
from pathlib import Path
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from pwnproxy.scanners.ssrf.models import Base, SsrfFinding

logger = logging.getLogger(__name__)


class SsrfFindingStorage:
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

    async def save_finding(self, finding: SsrfFinding) -> None:
        async with self.session_factory() as session:
            session.add(finding)
            await session.commit()

    async def get_findings(self) -> list[SsrfFinding]:
        from sqlalchemy import select
        async with self.session_factory() as session:
            result = await session.execute(
                select(SsrfFinding).order_by(SsrfFinding.timestamp.desc())
            )
            return list(result.scalars().all())
