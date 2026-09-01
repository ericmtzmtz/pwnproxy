"""XSS plugin entry point."""

from collections.abc import AsyncGenerator

from pwnproxy.plugins.core.base import PluginMetadata, Finding, ScannerPlugin
from pwnproxy.shared.scan.replayer import RequestReplayer
from pwnproxy.shared.scan.params import extract as extract_params
from pwnproxy.shared.models import Flow
from pwnproxy.plugins.scanners.xss.scanner import XSSScanner


class XSSScannerPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="xss",
        version="0.3.0",
        author="pwnproxy",
        consumes=["flow"],
        produces=["finding"],
    )
    techniques = ["reflected-xss", "stored-xss", "unescaped-reflection"]
    capabilities = ["cross-site-scripting", "reflected-xss", "stored-xss", "unescaped-reflection"]

    async def on_load(self) -> None:
        depth = self.context.config.get("depth", "fast")
        evasion_level = self.context.config.get("evasion_level", "none")
        self._replayer = RequestReplayer()
        self._scanner = XSSScanner(self._replayer, depth=depth, evasion=evasion_level)

    async def on_flow(self, flow: Flow) -> AsyncGenerator[Finding, None]:
        points = extract_params(flow)
        seen = set()
        for point in points:
            key = (point.host + point.path, point.name, point.location)
            if key in seen:
                continue
            seen.add(key)
            async for finding in self._scanner._scan_point(point):
                yield finding

    async def on_unload(self) -> None:
        await self._replayer.close()
