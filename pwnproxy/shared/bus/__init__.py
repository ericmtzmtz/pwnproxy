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

from pwnproxy.shared.bus.topics import QoSClass, TOPIC_QOS, DEFAULT_QOS


@dataclass
class Envelope:
    topic: str
    data: Any
    source: str = ""
    id: str = field(default_factory=lambda: uuid4().hex)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    qos_class: QoSClass = field(default=DEFAULT_QOS)

    def __post_init__(self) -> None:
        # Auto-classify QoS from topic if not explicitly set
        if self.qos_class == DEFAULT_QOS:
            self.qos_class = TOPIC_QOS.get(self.topic, DEFAULT_QOS)

    def to_json(self) -> str:
        return json.dumps({
            "topic": self.topic, "data": self.data, "source": self.source,
            "id": self.id, "timestamp": self.timestamp.isoformat(),
            "qos_class": self.qos_class.value,
        }, default=str)

    @classmethod
    def from_json(cls, raw: str) -> "Envelope":
        d = json.loads(raw)
        qos_raw = d.get("qos_class", DEFAULT_QOS.value)
        try:
            qos = QoSClass(qos_raw)
        except ValueError:
            qos = DEFAULT_QOS
        return cls(
            topic=d["topic"],
            data=d["data"],
            source=d.get("source", ""),
            id=d.get("id", ""),
            timestamp=datetime.fromisoformat(d["timestamp"]) if "timestamp" in d else datetime.now(timezone.utc),
            qos_class=qos,
        )


class MessageBus(ABC):
    @abstractmethod
    async def publish(self, topic: str, data: Any, *, source: str = "") -> None: ...

    @abstractmethod
    def subscribe(self, topic: str) -> AsyncIterator[Envelope]: ...
