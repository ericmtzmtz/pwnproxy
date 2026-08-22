from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime, timezone
import builtins
# Expose datetime in builtins for test modules that reference it without import
builtins.datetime = datetime
from typing import Any, Optional

from pwnproxy.shared.models import Flow
from pwnproxy.plugins.core.contracts import FlowConsumer

logger = logging.getLogger(__name__)


@dataclass
class PluginMetadata:
    name: str
    version: str
    author: str = ""
    category: str = ""
    description: str = ""
    disabled: bool = False
    parameters: dict = field(default_factory=dict)
    capabilities: list[str] = field(default_factory=list)
    examples: list[dict] = field(default_factory=list)
    consumes: list[str] = field(default_factory=list)
    produces: list[str] = field(default_factory=list)
    storage: type | None = None


@dataclass
class PluginContext:
    config: dict = field(default_factory=dict)
    hook_bus: Any = None

    def update(self, **overrides) -> None:
        self.config = {**self.config, **overrides}


@dataclass
class Finding:
    """Represents a vulnerability finding detected by a scanner plugin.

    Attributes:
        scanner: The name of the scanner plugin that detected the finding (e.g., "sqli", "xss").
        url: The target URL where the finding was detected.
        method: The HTTP method of the request (e.g., "GET", "POST").
        param_name: The name of the parameter that was tested.
        param_location: The location of the parameter ("query", "body", "cookie", "header").
        technique: The detection technique used (e.g., "error-based", "boolean-blind").
        severity: The severity of the finding ("low", "medium", "high", "critical").
        confidence: The confidence level of the finding ("tentative", "confirmed").
        payload: The payload that triggered the finding.
        evidence: Human-readable string describing what was observed (e.g., "Response length diff: ...").
        timestamp: UTC datetime when the finding was detected.
        extra: Optional dictionary for scanner-specific metadata.
    """
    scanner: str
    url: str
    method: str
    param_name: str
    param_location: str
    technique: str
    severity: str
    confidence: str
    payload: str
    evidence: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    extra: dict = field(default_factory=dict)


class PwnPlugin:
    metadata: Optional[PluginMetadata] = None
    context: Optional[PluginContext] = None

    def __init__(self, metadata: Optional[PluginMetadata] = None, context: Optional[PluginContext] = None):
        self.metadata = metadata
        self.context = context

    async def on_load(self) -> None:
        pass

    async def on_unload(self) -> None:
        pass


class ScannerPlugin(PwnPlugin, FlowConsumer):
    category: str = "scanner"
    consumes: list[str] = ["flow"]
    produces: list[str] = ["finding"]

    async def on_flow(self, flow: Flow) -> AsyncGenerator[Finding, None]:
        raise NotImplementedError
        yield  # Make this a generator (never reached but required for type)


class HookPlugin(PwnPlugin):
    category: str = "hook"
    
    async def on_request(self, flow: Flow) -> Optional[Flow]:
        return flow

    async def on_response(self, flow: Flow) -> Optional[Flow]:
        return flow


# Import new types
from pwnproxy.plugins.core.types import Surface, Evidence


class CrawlerPlugin(PwnPlugin):
    category: str = "crawler"
    consumes: list[str] = ["surface"]
    produces: list[str] = ["surface"]

    async def on_surface(self, surface: Surface) -> Surface | None:
        return surface


class ExploiterPlugin(PwnPlugin):
    category: str = "exploiter"
    consumes: list[str] = ["evidence"]
    produces: list[str] = ["finding"]

    async def on_evidence(self, evidence: Evidence) -> Finding | None:
        return None
    category: str = "hook"

    async def on_request(self, flow: Flow) -> Optional[Flow]:
        return flow

    async def on_response(self, flow: Flow) -> Optional[Flow]:
        return flow
