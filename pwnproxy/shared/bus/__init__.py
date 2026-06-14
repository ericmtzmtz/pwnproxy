from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncIterator as AIter
from uuid import uuid4


@dataclass
class Envelope:
    topic: str
    data: Any
    source: str = ""
    id: str = field(default_factory=lambda: uuid4().hex)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_json(self) -> str:
        return json.dumps({"topic": self.topic, "data": self.data, "source": self.source, "id": self.id, "timestamp": self.timestamp.isoformat()})

    @classmethod
    def from_json(cls, raw: str) -> "Envelope":
        d = json.loads(raw)
        return cls(
            topic=d["topic"],
            data=d["data"],
            source=d.get("source", ""),
            id=d.get("id", ""),
            timestamp=datetime.fromisoformat(d["timestamp"]) if "timestamp" in d else datetime.now(timezone.utc),
        )


class MessageBus(ABC):
    @abstractmethod
    async def publish(self, topic: str, data: Any, *, source: str = "") -> None: ...

    @abstractmethod
    def subscribe(self, topic: str) -> AsyncIterator[Envelope]: ...
