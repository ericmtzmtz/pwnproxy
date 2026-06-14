"""Simple duck-typing contract mixins.

These classes provide the `consumes` attribute used by the plugin loader to
wire plugins to channels.  They purposefully contain no ABC machinery – the
tests expect plain classes that can be used with `isinstance` checks without
requiring an abstract base class.
"""

from typing import Any


class FlowConsumer:
    """Mixin for plugins that consume Flow objects."""
    consumes: list[str] = ["flow"]

    async def on_flow(self, flow: Any) -> Any:  # pragma: no cover
        """Handle incoming flow objects (optional implementation)."""
        raise NotImplementedError


class FindingConsumer:
    """Mixin for plugins that consume Finding objects."""
    consumes: list[str] = ["finding"]

    async def on_finding(self, finding: Any) -> Any:  # pragma: no cover
        raise NotImplementedError


class SurfaceConsumer:
    """Mixin for plugins that consume surface information."""
    consumes: list[str] = ["surface"]

    async def on_surface(self, surface: Any) -> Any:  # pragma: no cover
        raise NotImplementedError


class EvidenceConsumer:
    """Mixin for plugins that consume evidence objects."""
    consumes: list[str] = ["evidence"]

    async def on_evidence(self, evidence: Any) -> Any:  # pragma: no cover
        raise NotImplementedError