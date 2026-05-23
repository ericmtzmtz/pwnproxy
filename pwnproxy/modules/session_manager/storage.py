import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from pwnproxy.modules.session_manager.models import Base, SessionToken, TokenCandidate

logger = logging.getLogger(__name__)


class TokenStorage:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path_obj = Path.home() / ".pwnproxy" / "sessions.db"
        else:
            db_path_obj = Path(db_path)
        db_path_obj.parent.mkdir(parents=True, exist_ok=True)
        db_url = f"sqlite+aiosqlite:///{db_path_obj.absolute()}"
        self.engine: AsyncEngine = create_async_engine(db_url, echo=False)
        self.session_factory = sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

    async def init(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await conn.exec_driver_sql("PRAGMA journal_mode=WAL")

    async def save(self, candidates: list[TokenCandidate]) -> None:
        async with self.session_factory() as session:
            for c in candidates:
                existing = await session.execute(
                    select(SessionToken).where(
                        SessionToken.token_hash == c.token_hash
                    )
                )
                row = existing.scalar_one_or_none()
                if row is None:
                    row = SessionToken(
                        token_type=c.token_type,
                        token_value=c.token_value,
                        token_hash=c.token_hash,
                        label=c.label,
                        decoded_payload=c.decoded_payload,
                        decoded_header=c.decoded_header,
                        status=c.status,
                        source_url=c.source_url,
                        source_flow_id=c.source_flow_id,
                        ref_count=1,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        expires_at=c.expires_at,
                    )
                    session.add(row)
                else:
                    row.ref_count = (row.ref_count or 0) + 1
                    row.last_seen = datetime.now()
                    if c.status != "unknown":
                        row.status = c.status
                    if c.decoded_payload:
                        row.decoded_payload = c.decoded_payload
                    if c.decoded_header:
                        row.decoded_header = c.decoded_header
            await session.commit()

    async def query(
        self,
        token_type: Optional[str] = None,
        search: Optional[str] = None,
    ) -> list[SessionToken]:
        async with self.session_factory() as session:
            stmt = select(SessionToken).order_by(SessionToken.last_seen.desc())
            if token_type:
                stmt = stmt.where(SessionToken.token_type == token_type)
            if search:
                like = f"%{search}%"
                stmt = stmt.where(
                    SessionToken.token_value.like(like)
                    | SessionToken.label.like(like)
                )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def get_by_id(self, token_id: int) -> Optional[SessionToken]:
        async with self.session_factory() as session:
            result = await session.execute(
                select(SessionToken).where(SessionToken.id == token_id)
            )
            return result.scalar_one_or_none()

    async def delete_old(self, before: datetime) -> int:
        async with self.session_factory() as session:
            stmt = select(SessionToken).where(SessionToken.last_seen < before)
            result = await session.execute(stmt)
            rows = list(result.scalars().all())
            for row in rows:
                await session.delete(row)
            await session.commit()
            return len(rows)

    async def delete_by_id(self, token_id: int) -> bool:
        async with self.session_factory() as session:
            result = await session.execute(
                select(SessionToken).where(SessionToken.id == token_id)
            )
            token = result.scalar_one_or_none()
            if not token:
                return False
            await session.delete(token)
            await session.commit()
            return True

    async def close(self) -> None:
        await self.engine.dispose()
