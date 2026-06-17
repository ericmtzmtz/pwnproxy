from collections.abc import AsyncGenerator

from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.replayer import RequestReplayer
from pwnproxy.shared.scan.params import extract as extract_params
from pwnproxy.plugins.core.base import PluginMetadata, ScannerPlugin, Finding
from pwnproxy.plugins.scanners.command_injection.scanner import CommandInjectionScanner


class CommandInjectionScannerPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="command-injection",
        version="0.1.0",
        author="pwnproxy",
        consumes=["flow"],
        produces=["finding"],
    )
    techniques = ["command-injection", "time-based"]
    capabilities = ["command-injection", "rce-detection"]
    
    async def on_load(self) -> None:
        depth = self.context.config.get("depth", "fast")
        evasion = self.context.config.get("evasion_level", "none")
        self._replayer = RequestReplayer()
        self._scanner = CommandInjectionScanner(self._replayer, depth, evasion)
    
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
