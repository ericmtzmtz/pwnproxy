"""XXE plugin entry point."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from pwnproxy.plugins.core.base import PluginMetadata, Finding, ScannerPlugin
from pwnproxy.shared.scan.replayers.xxe import XxeReplayer
from pwnproxy.shared.scan.params import extract as extract_params
from pwnproxy.shared.models import Flow
from pwnproxy.plugins.scanners.xxe.scanner import XXEScanner


class XXEScannerPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="xxe",
        version="0.2.0",
        author="pwnproxy",
        consumes=["flow"],
        produces=["finding"],
    )
    techniques = ["xxe-error-based", "xxe-json-mutation", "xxe-oob"]
    capabilities = ["xml-external-entity", "xxe"]

    async def on_load(self) -> None:
        depth = self.context.config.get("depth", "fast")
        evasion_level = self.context.config.get("evasion_level", "none")
        self._replayer = XxeReplayer()
        self._scanner = XXEScanner(self._replayer, depth=depth, evasion=evasion_level)

    async def on_flow(self, flow: Flow) -> AsyncGenerator[Finding, None]:
        self._replayer.flow = flow
        points = extract_params(flow)
        seen = set()
        valid_points = []
        for point in points:
            key = (point.host + point.path, point.name, point.location)
            if key in seen:
                continue
            seen.add(key)
            valid_points.append(point)

        if not valid_points:
            return

        findings = await self._scanner.scan(flow, valid_points)
        for finding in findings:
            yield finding

    async def on_unload(self) -> None:
        await self._replayer.close()
