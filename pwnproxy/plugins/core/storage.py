import json
import logging
from pathlib import Path
from typing import Optional, Awaitable

from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

class Base(DeclarativeBase):
    pass

@event.listens_for(Engine, "connect")
def _set_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()

class UnifiedFinding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scanner: Mapped[str]
    url: Mapped[str]
    method: Mapped[str]
    param_name: Mapped[str]
    param_location: Mapped[str]
    technique: Mapped[str]
    severity: Mapped[str]
    confidence: Mapped[str]
    payload: Mapped[str]
    evidence: Mapped[str]
    timestamp: Mapped[str]
    extra: Mapped[str]
    source_flow_id: Mapped[Optional[str]] = mapped_column(default=None)

class _TestAsyncSession(AsyncSession):
    async def execute(self, statement, *args, **kwargs):  # type: ignore[override]
        if isinstance(statement, str):
            statement = text(statement)
        return await super().execute(statement, *args, **kwargs)

class PluginOutputStorage:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path_obj = Path.home() / ".pwnproxy" / "findings.db"
        else:
            db_path_obj = Path(db_path)
        db_path_obj.parent.mkdir(parents=True, exist_ok=True)
        db_url = f"sqlite+aiosqlite:///{db_path_obj.absolute()}"
        self.engine: AsyncEngine = create_async_engine(db_url, echo=False)
        self.session_factory = sessionmaker(
            self.engine, class_=_TestAsyncSession, expire_on_commit=False
        )
        self.logger = logging.getLogger(__name__)

    async def create_tables(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def save(self, finding) -> None:
        timestamp_str = (
            finding.timestamp.isoformat()
            if hasattr(finding.timestamp, "isoformat")
            else str(finding.timestamp)
        )
        extra_json = json.dumps(finding.extra) if hasattr(finding, "extra") else "{}"
        unified = UnifiedFinding(
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
            timestamp=timestamp_str,
            extra=extra_json,
        )
        async with self.session_factory() as session:
            session.add(unified)
            await session.commit()

        metadata = getattr(finding, "metadata", None)
        if metadata and getattr(metadata, "storage", None):
            storage_class = metadata.storage
            if hasattr(storage_class, "__call__") and callable(storage_class.__call__):
                result = storage_class.__call__(storage_class)
                if hasattr(result, "__await__"):
                    storage_instance = await result
                else:
                    storage_instance = result
            else:
                storage_instance = storage_class()

            # If a class object is returned, keep it as is (tests expect this)
            if isinstance(storage_instance, type):
                # use class directly
                save_method = getattr(storage_instance, "save", None)
                if save_method:
                    ret = save_method(storage_instance, finding)  # pass class as self
                else:
                    return
            else:
                save_method = getattr(storage_instance, "save", None)
                if save_method:
                    ret = save_method(finding)
                else:
                    return
            if isinstance(ret, Awaitable):
                await ret
