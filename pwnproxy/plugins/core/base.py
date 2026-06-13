import logging
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from pwnproxy.shared.models import Flow

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

    async def scan(
        self,
        flow: Flow,
        depth: str = "fast",
        evasion_level: str = "none",
    ) -> AsyncGenerator[Finding, None]:
        """Scan a flow for vulnerabilities and yield findings as they are confirmed.
        
        Args:
            flow: The HTTP flow to scan
            depth: Detection depth ("fast", "standard", "deep")
            evasion_level: WAF evasion level ("none", "light", "aggressive")
        
        New-style plugins use async generators to stream findings.
        Old-style plugins returning Optional[Finding] are wrapped by PluginLoader.
        """
        raise NotImplementedError
        yield  # Make this a generator (never reached but required for type)


class HookPlugin(PwnPlugin):
    category: str = "hook"

    async def on_request(self, flow: Flow) -> Optional[Flow]:
        return flow

    async def on_response(self, flow: Flow) -> Optional[Flow]:
        return flow
