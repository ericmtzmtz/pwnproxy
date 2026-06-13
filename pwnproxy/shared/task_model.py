from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class TaskBase(DeclarativeBase):
    pass


@event.listens_for(Engine, "connect")
def _set_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


class TaskRecord(TaskBase):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(primary_key=True)
    session: Mapped[str] = mapped_column(default="")
    type: Mapped[str]
    status: Mapped[str] = mapped_column(default="pending")
    progress: Mapped[int] = mapped_column(default=0)
    total: Mapped[int] = mapped_column(default=0)
    config: Mapped[str] = mapped_column(default="{}")
    result: Mapped[str | None] = mapped_column(default=None)
    error: Mapped[str | None] = mapped_column(default=None)
    created_at: Mapped[str] = mapped_column(
        default=lambda: datetime.now(timezone.utc).isoformat()
    )
    completed_at: Mapped[str | None] = mapped_column(default=None)


def create_task_engine(session_path: str) -> AsyncEngine:
    db_path = Path(session_path) / "tasks.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    url = f"sqlite+aiosqlite:///{db_path.absolute().as_posix()}"
    return create_async_engine(url, echo=False)


async def init_task_db(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(TaskBase.metadata.create_all)
