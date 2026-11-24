"""The plugin contract: metadata, context, optional hooks and the configuration API.

Everything here is *duck-typed* on purpose: a plugin implements the methods it
needs and the core asks for them with ``getattr``. There is no ABC to inherit
(adding one would break the eleven plugins in the tree and every installed one),
so this docstring is the contract.

Hooks the core calls when it has loaded the plugin
--------------------------------------------------

``on_load()`` / ``on_unload()`` (inherited no-ops) and the channel hooks that the
metadata declares (``on_flow``, ``on_finding``, ``on_surface``, ``on_evidence``).

Configuration and actions (all optional, sync or ``async``)
-----------------------------------------------------------

A plugin publishes its configuration by implementing the first of these; the core
turns the schema into the ``/api/v1/plugins/{name}/…`` routes and never stores a
value. A plugin that implements none of them behaves exactly as before.

================================================  ==========================================
Method                                            Called by
================================================  ==========================================
``config_schema() -> PluginConfigSchema``          ``GET …/schema``
``config_read() -> dict[str, Any]``                ``GET …/settings``
``config_write(values: dict[str, Any]) -> None``   ``PATCH …/settings``
``collection_list(name: str) -> list[dict]``       ``GET …/collections/{c}``
``collection_create(name, values) -> dict``        ``POST …/collections/{c}``
``collection_update(name, item_id, values)``       ``PATCH …/collections/{c}/{id}``
``collection_delete(name, item_id) -> None``       ``DELETE …/collections/{c}/{id}``
``run_action(name, parameters) -> Any``            ``POST …/actions/{a}``
================================================  ==========================================

Rules for an author:

* A result is a **flat mapping** of *field key → value*; a collection item also
  carries its ``id`` (the identifier used to edit and delete it). Everything the
  schema does not declare is ignored by the server.
* ``config_read`` reports a secret as ``{"<key>__set": True}`` — the value itself
  is discarded by the server, so returning it publishes nothing but tells the
  server that the plugin is not keeping its half of the contract.
* ``config_write`` and ``collection_*`` are the **only seam**: persist and apply
  the change to the live state there. The core does **not** reload the plugin
  after a write (a reload would replay buffered events and restart consumer
  tasks), so there is no ``on_config_changed`` hook either.
* Reject a business rule with :class:`PluginValidationError` (``422`` with your
  message) and a vanished item with :class:`PluginItemNotFound` (``404``). Any
  other exception becomes the fixed ``500`` body and the trace goes to the log.
* Build the object in ``__init__`` without side effects (no network, no store, no
  tasks): the core may instantiate a plugin that is **not** loaded to read or
  write its configuration, and ``on_load()`` is never called on that instance.
  Open the store in ``on_load()``.
* **An action never returns a secret** in ``result``: the core has no schema of a
  result, so it cannot redact it. A parameter can never be declared ``secret``
  either (a long action persists its parameters in the task store).
"""

from __future__ import annotations

import builtins
import logging
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pwnproxy.plugins.core.config_schema import (  # noqa: F401  (configuration contract, re-exported for plugins)
    SCHEMA_VERSION,
    ActionSpec,
    CollectionSpec,
    FieldSpec,
    InvalidPluginSchema,
    PluginConfigSchema,
    PluginItemNotFound,
    PluginValidationError,
    SchemaViolation,
)
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
