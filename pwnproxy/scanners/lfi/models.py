from datetime import datetime
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class LfiFinding(Base):
    __tablename__ = "lfi_findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    original_method: Mapped[str]
    successful_method: Mapped[str]
    url: Mapped[str]
    param_name: Mapped[str]
    param_location: Mapped[str]
    payload: Mapped[str]
    evidence: Mapped[Optional[str]]
    os: Mapped[str]
    severity: Mapped[str]
    timestamp: Mapped[datetime] = mapped_column(default=func.now())
