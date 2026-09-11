import hashlib
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import JSON, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class SessionToken(Base):
    __tablename__ = "session_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_type: Mapped[str] = mapped_column(String(16))
    token_value: Mapped[str] = mapped_column(String(4096))
    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, index=True
    )
    label: Mapped[str | None] = mapped_column(String(128))
    decoded_payload: Mapped[dict | None] = mapped_column(JSON)
    decoded_header: Mapped[dict | None] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(32), default="unknown")
    source_url: Mapped[str] = mapped_column(String(2048))
    source_flow_id: Mapped[str | None] = mapped_column(String(64))
    ref_count: Mapped[int] = mapped_column(default=1)
    first_seen: Mapped[datetime] = mapped_column(default=func.now())
    last_seen: Mapped[datetime] = mapped_column(default=func.now())
    expires_at: Mapped[datetime | None]


@dataclass
class TokenCandidate:
    token_type: str
    token_value: str
    label: str | None = None
    decoded_payload: dict | None = None
    decoded_header: dict | None = None
    status: str = "unknown"
    source_url: str = ""
    source_flow_id: str | None = None
    expires_at: datetime | None = None

    @property
    def token_hash(self) -> str:
        return hashlib.sha256(
            self.token_value.encode("utf-8")
        ).hexdigest()
