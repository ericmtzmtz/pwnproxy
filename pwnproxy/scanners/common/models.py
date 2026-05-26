from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ScanLog(Base):
    __tablename__ = "scan_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    flow_id: Mapped[str]
    url: Mapped[str]
    method: Mapped[str]
    scanner_name: Mapped[str]
    status: Mapped[str]  # "completed" / "error"
    duration_ms: Mapped[float] = mapped_column(nullable=True)
    finding_count: Mapped[int] = mapped_column(default=0)
    started_at: Mapped[datetime] = mapped_column(default=func.now())
    completed_at: Mapped[datetime] = mapped_column(default=func.now())
