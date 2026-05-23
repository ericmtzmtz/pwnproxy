from datetime import datetime
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class SsrfFinding(Base):
    __tablename__ = "ssrf_findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str]
    param_name: Mapped[str]
    param_location: Mapped[str]
    canary: Mapped[str]
    payload: Mapped[str]
    callback_ip: Mapped[Optional[str]]
    callback_headers: Mapped[Optional[str]]
    severity: Mapped[str]
    timestamp: Mapped[datetime] = mapped_column(default=func.now())


class CallbackHit(Base):
    __tablename__ = "ssrf_callback_hits"

    id: Mapped[int] = mapped_column(primary_key=True)
    canary: Mapped[str]
    remote_ip: Mapped[str]
    remote_port: Mapped[int]
    request_path: Mapped[str]
    request_headers: Mapped[Optional[str]]
    timestamp: Mapped[datetime] = mapped_column(default=func.now())
