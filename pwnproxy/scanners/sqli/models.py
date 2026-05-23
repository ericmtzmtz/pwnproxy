from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, LargeBinary, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    method: Mapped[str]
    url: Mapped[str]
    param_name: Mapped[str]
    param_location: Mapped[str]
    technique: Mapped[str]
    dbms: Mapped[Optional[str]]
    severity: Mapped[str]
    confidence: Mapped[str]
    payload: Mapped[str]
    evidence: Mapped[Optional[str]]
    baseline_ms: Mapped[Optional[float]]
    response_ms: Mapped[Optional[float]]
    source_flow_id: Mapped[Optional[int]]
    timestamp: Mapped[datetime] = mapped_column(default=func.now())


class ScanTarget(Base):
    __tablename__ = "scan_targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    method: Mapped[str]
    url_path: Mapped[str]
    param_name: Mapped[str]
    param_location: Mapped[str]
    status: Mapped[str]
    findings_count: Mapped[int] = mapped_column(default=0)
    scanned_at: Mapped[Optional[datetime]]
