from datetime import datetime
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class XxeFinding(Base):
    __tablename__ = "xxe_findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str]
    param_name: Mapped[str]
    param_location: Mapped[str]
    technique: Mapped[str]
    payload: Mapped[str]
    evidence: Mapped[Optional[str]]
    mutation: Mapped[str]
    oob_domain: Mapped[Optional[str]]
    severity: Mapped[str]
    confidence: Mapped[str]
    timestamp: Mapped[datetime] = mapped_column(default=func.now())
