from __future__ import annotations

import builtins
import logging
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pwnproxy.plugins.core.contracts import FlowConsumer
from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.finding import Finding  # noqa: F401  (re-exported for plugins)

# Expose datetime in builtins for test modules that reference it without import
builtins.datetime = datetime

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


class PwnPlugin:
    metadata: PluginMetadata | None = None
    context: PluginContext | None = None

    def __init__(self, metadata: PluginMetadata | None = None, context: PluginContext | None = None):
        import copy
        if metadata is not None:
            self.metadata = metadata
        elif getattr(self.__class__, "metadata", None) is not None and isinstance(self.__class__.metadata, PluginMetadata):
            # Preserve class-level PluginMetadata instead of shadowing with None.
            # Copy so per-instance mutation (disabled) does not affect the class.
            self.metadata = copy.copy(self.__class__.metadata)
        else:
            self.metadata = metadata
        if context is not None:
            self.context = context
        elif getattr(self.__class__, "context", None) is not None:
            self.context = copy.copy(self.__class__.context)
        else:
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
    
    async def on_request(self, flow: Flow) -> Flow | None:
        return flow

    async def on_response(self, flow: Flow) -> Flow | None:
        return flow


# Import new types (after the class defs to avoid an import cycle)
from pwnproxy.plugins.core.types import Evidence, Surface  # noqa: E402


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

    async def on_request(self, flow: Flow) -> Flow | None:
        return flow

    async def on_response(self, flow: Flow) -> Flow | None:
        return flow
