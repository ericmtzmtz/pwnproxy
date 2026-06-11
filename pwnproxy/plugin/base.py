import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from pwnproxy.core.models import Flow

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    scanner: str
    url: str
    method: str
    param_name: str
    param_location: str
    technique: str
    severity: str
    confidence: str
    payload: str
    evidence: Optional[str] = None
    timestamp: float = field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    extra: dict[str, Any] = field(default_factory=dict)


class PwnPlugin:
    name: str = ""
    version: str = ""
    author: str = ""
    category: str = ""

    async def on_load(self) -> None:
        pass

    async def on_unload(self) -> None:
        pass


class ScannerPlugin(PwnPlugin):
    category: str = "scanner"

    async def scan(self, flow: Flow) -> Optional[Finding]:
        raise NotImplementedError


class HookPlugin(PwnPlugin):
    category: str = "hook"

    async def on_request(self, flow: Flow) -> Optional[Flow]:
        return flow

    async def on_response(self, flow: Flow) -> Optional[Flow]:
        return flow
