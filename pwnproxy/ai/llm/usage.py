"""Append-only usage ledger (ai_usage table) for cost/latency observability."""
import asyncio
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from pwnproxy.ai.llm.models import LLMResponse


class UsageBase(DeclarativeBase):
    pass


class UsageRecordORM(UsageBase):
    __tablename__ = "ai_usage"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(String(40), default=lambda: datetime.now(timezone.utc).isoformat())
    provider = Column(String(30), nullable=False)
    model = Column(String(100), default="")
    status = Column(String(10), nullable=False)  # ok | error
    input_tokens = Column(Integer, default=0)
    output_tokens = Column(Integer, default=0)
    latency_ms = Column(Integer, default=0)
    error = Column(Text, nullable=True)
    request_summary = Column(Text, nullable=True)


def default_ledger_engine() -> AsyncEngine:
    db_path = Path.home() / ".pwnproxy" / "ai_usage.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return create_async_engine(f"sqlite+aiosqlite:///{db_path.absolute().as_posix()}", echo=False)


class UsageLedger:
    """Records one row per LLM call attempt (ok or error), append-only."""

    def __init__(self, engine: AsyncEngine):
        self._engine = engine
        self._ready = False
        self._lock = asyncio.Lock()

    async def _ensure_table(self) -> None:
        if self._ready:
            return
        async with self._lock:
            if not self._ready:
                async with self._engine.begin() as conn:
                    await conn.run_sync(UsageBase.metadata.create_all)
                self._ready = True

    async def record_ok(self, resp: LLMResponse, request_summary: str = "") -> None:
        await self._ensure_table()
        from sqlalchemy.ext.asyncio import AsyncSession
        from sqlalchemy.orm import sessionmaker
        factory = sessionmaker(self._engine, class_=AsyncSession, expire_on_commit=False)
        row = UsageRecordORM(
            provider=resp.provider,
            model=resp.model,
            status="ok",
            input_tokens=resp.input_tokens,
            output_tokens=resp.output_tokens,
            latency_ms=resp.latency_ms,
            request_summary=request_summary[:200],
        )
        async with factory() as session:
            session.add(row)
            await session.commit()

    async def record_error(self, provider: str, status: str, message: str, request_summary: str = "") -> None:
        await self._ensure_table()
        from sqlalchemy.ext.asyncio import AsyncSession
        from sqlalchemy.orm import sessionmaker
        factory = sessionmaker(self._engine, class_=AsyncSession, expire_on_commit=False)
        row = UsageRecordORM(provider=provider, model="", status=status, error=message[:500], request_summary=request_summary[:200])
        async with factory() as session:
            session.add(row)
            await session.commit()
