import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import JSON, LargeBinary, Text, event
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


class FlowCommentORM(Base):
    __tablename__ = "flow_comments"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    flow_id: Mapped[int] = mapped_column(index=True)
    body: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(default="note")
    resolved: Mapped[bool] = mapped_column(default=False)
    author: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class FlowRecord(Base):
    __tablename__ = "flows"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    # Request
    method: Mapped[str]
    url: Mapped[str]
    request_headers: Mapped[Dict[str, Any]] = mapped_column(JSON)
    request_body: Mapped[Optional[bytes]] = mapped_column(LargeBinary)
    request_body_truncated: Mapped[bool] = mapped_column(default=False)
    
    # Response
    status_code: Mapped[Optional[int]]
    response_headers: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    response_body: Mapped[Optional[bytes]] = mapped_column(LargeBinary)
    response_body_truncated: Mapped[bool] = mapped_column(default=False)
    
    # Metadata
    timestamp: Mapped[datetime] = mapped_column(default=func.now())
    duration_ms: Mapped[Optional[float]]
    error: Mapped[Optional[str]]
    tls: Mapped[bool] = mapped_column(default=False)


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


def ensure_db_dir(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)


def create_engine(db_path: Optional[str] = None, session_path: Optional[str] = None) -> AsyncEngine:
    if session_path is not None:
        db_path_obj = Path(session_path) / "traffic.db"
    elif db_path is None:
        db_path_obj = Path.home() / ".pwnproxy" / "traffic.db"
    else:
        db_path_obj = Path(db_path)
    
    ensure_db_dir(db_path_obj)
    
    # Use aiosqlite for async sqlalchemy
    db_url = f"sqlite+aiosqlite:///{db_path_obj.absolute()}"
    return create_async_engine(db_url, echo=False)


async def init_db(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def truncate_body(body: bytes | None, max_size: int = 1_048_576) -> Tuple[bytes | None, bool]:
    """Truncate body to max_size. Returns (truncated_body, is_truncated)."""
    if body is None:
        return None, False
    if len(body) > max_size:
        return body[:max_size], True
    return body, False
