from datetime import datetime
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class XssFinding(Base):
    __tablename__ = "xss_findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    method: Mapped[str]
    url: Mapped[str]
    param_name: Mapped[str]
    param_location: Mapped[str]
    xss_type: Mapped[str]
    context: Mapped[str]
    severity: Mapped[str]
    confidence: Mapped[str]
    payload: Mapped[str]
    evidence: Mapped[Optional[str]]
    reflection_url: Mapped[Optional[str]]
    source_flow_id: Mapped[Optional[int]]
    timestamp: Mapped[datetime] = mapped_column(default=func.now())


class XssCanary(Base):
    __tablename__ = "xss_canaries"

    id: Mapped[int] = mapped_column(primary_key=True)
    canary_value: Mapped[str] = mapped_column(unique=True)
    source_url: Mapped[str]
    param_name: Mapped[str]
    param_location: Mapped[str]
    injected_at: Mapped[datetime]
    found: Mapped[bool] = mapped_column(default=False)
    found_url: Mapped[Optional[str]]
    found_at: Mapped[Optional[datetime]]
