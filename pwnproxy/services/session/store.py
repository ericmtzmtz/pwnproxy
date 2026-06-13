import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select, delete as sa_delete, func
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from pwnproxy.shared.task_model import TaskRecord, init_task_db

logger = logging.getLogger(__name__)

STALE_TIMEOUT = timedelta(minutes=5)


class TaskStore:
    def __init__(self, engine: AsyncEngine):
        self._engine = engine
        self._session_factory: async_sessionmaker[AsyncSession] | None = None
        self._running_tasks: dict[str, asyncio.Task] = {}

    async def init(self) -> None:
        await init_task_db(self._engine)
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def _session(self):
        if self._session_factory is None:
            await self.init()
        async with self._session_factory() as s:
            yield s

    async def create(
        self,
        task_type: str,
        config: dict[str, Any],
        session_name: str = "",
    ) -> str:
        task_id = uuid.uuid4().hex[:8]
        record = TaskRecord(
            id=task_id,
            session=session_name,
            type=task_type,
            config=json.dumps(config),
            status="running",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        async with self._session_factory() as s:
            s.add(record)
            await s.commit()
        return task_id

    async def update(
        self,
        task_id: str,
        status: str | None = None,
        progress: int | None = None,
        total: int | None = None,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        async with self._session_factory() as s:
            record = await s.get(TaskRecord, task_id)
            if record is None:
                return
            if status is not None:
                record.status = status
            if progress is not None:
                record.progress = progress
            if total is not None:
                record.total = total
            if result is not None:
                record.result = json.dumps(result)
            if error is not None:
                record.error = error
            if status in ("completed", "failed", "cancelled"):
                record.completed_at = datetime.now(timezone.utc).isoformat()
            await s.commit()

    async def get(self, task_id: str) -> Optional[dict[str, Any]]:
        async with self._session_factory() as s:
            record = await s.get(TaskRecord, task_id)
            if record is None:
                return None
            if record.status == "running":
                created = datetime.fromisoformat(record.created_at) if record.created_at else datetime.now(timezone.utc)
                if datetime.now(timezone.utc) - created > STALE_TIMEOUT and record.id not in self._running_tasks:
                    record.status = "failed"
                    record.completed_at = datetime.now(timezone.utc).isoformat()
                    record.error = "Stale — task timed out"
                    await s.commit()
            return self._record_to_dict(record)

    async def list(
        self,
        task_type: str | None = None,
        limit: int = 50,
        session_name: str = "",
    ) -> list[dict[str, Any]]:
        stmt = select(TaskRecord).where(
            TaskRecord.session == session_name
        ).order_by(TaskRecord.created_at.desc()).limit(limit)
        if task_type:
            stmt = stmt.where(TaskRecord.type == task_type)
        async with self._session_factory() as s:
            result = await s.execute(stmt)
            rows = result.scalars().all()
            now = datetime.now(timezone.utc)
            stale_tasks = []
            for r in rows:
                if r.status == "running":
                    created = datetime.fromisoformat(r.created_at) if r.created_at else now
                    if now - created > STALE_TIMEOUT and r.id not in self._running_tasks:
                        r.status = "failed"
                        r.completed_at = now.isoformat()
                        r.error = "Stale — task timed out"
                        stale_tasks.append(r)
            if stale_tasks:
                await s.commit()
            return [self._record_to_dict(r) for r in rows]

    async def count(self, task_type: str | None = None, session_name: str = "") -> int:
        stmt = select(func.count()).select_from(TaskRecord).where(
            TaskRecord.session == session_name
        )
        if task_type:
            stmt = stmt.where(TaskRecord.type == task_type)
        async with self._session_factory() as s:
            result = await s.execute(stmt)
            return result.scalar() or 0

    async def cancel(self, task_id: str) -> bool:
        async with self._session_factory() as s:
            record = await s.get(TaskRecord, task_id)
            if record is None:
                return False
            record.status = "cancelled"
            record.completed_at = datetime.now(timezone.utc).isoformat()
            await s.commit()
        runner = self._running_tasks.pop(task_id, None)
        if runner and not runner.done():
            runner.cancel()
        return True

    async def delete(self, task_id: str) -> bool:
        if self._session_factory is None:
            await self.init()
        logger.info("DELETE task %s from %s", task_id, self._engine.url)
        async with self._session_factory() as s:
            stmt = sa_delete(TaskRecord).where(TaskRecord.id == task_id)
            result = await s.execute(stmt)
            await s.commit()
            deleted = result.rowcount > 0
            logger.info("DELETE task %s deleted=%s rowcount=%d", task_id, deleted, result.rowcount)
        runner = self._running_tasks.pop(task_id, None)
        if runner and not runner.done():
            runner.cancel()
        return deleted

    def track(self, task_id: str, coro) -> None:
        self._running_tasks[task_id] = asyncio.create_task(coro)

    @staticmethod
    def _record_to_dict(r: TaskRecord) -> dict[str, Any]:
        return {
            "id": r.id,
            "type": r.type,
            "status": r.status,
            "progress": r.progress,
            "total": r.total,
            "config": json.loads(r.config) if isinstance(r.config, str) else (r.config or {}),
            "result": json.loads(r.result) if r.result and isinstance(r.result, str) else r.result,
            "error": r.error,
            "created_at": r.created_at,
            "completed_at": r.completed_at,
        }
