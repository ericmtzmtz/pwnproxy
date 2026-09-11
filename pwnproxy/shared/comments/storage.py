import logging
from datetime import datetime, timezone
from typing import Optional, List

from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.shared.db import Base, FlowCommentORM

logger = logging.getLogger(__name__)


class FlowCommentStorage:
    """CRUD storage for flow comments, mirroring FindingStorage pattern."""

    def __init__(self, engine):
        self._engine = engine
        self._factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def create_table(self) -> None:
        """Run Base.metadata.create_all and apply additive migrations for future columns."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        # Additive migration guard – future columns can be added here.
        from sqlalchemy import text as sql_text
        async with self._engine.begin() as conn:
            cols = await conn.execute(sql_text("SELECT name FROM pragma_table_info('flow_comments')"))
            names = {row[0] for row in cols}
            # Example future columns (currently none). Keep placeholder for future expansions.
            # for column, ddl in (("new_col", "TEXT"),):
            #     if column not in names:
            #         await conn.execute(sql_text(f"ALTER TABLE flow_comments ADD COLUMN {column} {ddl}"))
            #         logger.info("Migrated flow_comments table: added %s column", column)

    def _row_dict(self, record: FlowCommentORM) -> dict:
        return {c.name: getattr(record, c.name) for c in FlowCommentORM.__table__.columns}

    async def create(self, flow_id: int, body: str, kind: str = "note", resolved: bool = False, author: Optional[str] = None) -> dict:
        kind = kind.lower()
        if kind not in ("note", "flag", "todo"):
            raise ValueError(f"Invalid comment kind: {kind}")
        if not body:
            raise ValueError("Comment body cannot be empty")
        now = datetime.now(timezone.utc)
        record = FlowCommentORM(
            flow_id=flow_id,
            body=body,
            kind=kind,
            resolved=resolved,
            author=author,
            created_at=now,
            updated_at=now,
        )
        async with self._factory() as session:
            persisted = await session.merge(record)
            await session.flush()
            row_id = persisted.id
            await session.commit()
        return self._row_dict(persisted)

    async def list_by_flow(self, flow_id: int) -> List[dict]:
        async with self._factory() as session:
            query = select(FlowCommentORM).where(FlowCommentORM.flow_id == flow_id).order_by(FlowCommentORM.id.asc())
            result = await session.execute(query)
            rows = result.scalars().all()
            return [self._row_dict(r) for r in rows]

    async def get(self, comment_id: int) -> Optional[dict]:
        async with self._factory() as session:
            result = await session.execute(select(FlowCommentORM).where(FlowCommentORM.id == comment_id))
            record = result.scalar_one_or_none()
            return self._row_dict(record) if record else None

    async def update(self, comment_id: int, body: Optional[str] = None, kind: Optional[str] = None, resolved: Optional[bool] = None) -> Optional[dict]:
        async with self._factory() as session:
            result = await session.execute(select(FlowCommentORM).where(FlowCommentORM.id == comment_id))
            record = result.scalar_one_or_none()
            if not record:
                return None
            if body is not None:
                record.body = body
            if kind is not None:
                kind = kind.lower()
                if kind not in ("note", "flag", "todo"):
                    raise ValueError(f"Invalid comment kind: {kind}")
                record.kind = kind
            if resolved is not None:
                record.resolved = resolved
            record.updated_at = datetime.now(timezone.utc)
            await session.commit()
            return self._row_dict(record)

    async def delete(self, comment_id: int) -> bool:
        async with self._factory() as session:
            result = await session.execute(select(FlowCommentORM).where(FlowCommentORM.id == comment_id))
            record = result.scalar_one_or_none()
            if not record:
                return False
            await session.delete(record)
            await session.commit()
            return True

    async def count_by_flow(self, flow_id: int) -> int:
        async with self._factory() as session:
            query = select(func.count(FlowCommentORM.id)).where(FlowCommentORM.flow_id == flow_id)
            result = await session.execute(query)
            return result.scalar() or 0

    async def delete_by_flow(self, flow_id: int) -> int:
        """Delete all comments for a flow, returning number of rows removed."""
        async with self._factory() as session:
            stmt = delete(FlowCommentORM).where(FlowCommentORM.flow_id == flow_id)
            result = await session.execute(stmt)
            await session.commit()
            return result.rowcount or 0
