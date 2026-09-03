from collections.abc import AsyncGenerator

from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.replayer import RequestReplayer
from pwnproxy.shared.scan.params import extract as extract_params
from pwnproxy.plugins.core.base import PluginMetadata, Finding, ScannerPlugin
from pwnproxy.plugins.core.chain import DetectionChain, DetectionDepth, chain_from_depth
from pwnproxy.shared.scan.stages.sqli_stages import (
    ErrorBasedStage,
    BooleanBlindStage,
    TimeBlindStage,
    OOBStage,
)
from pwnproxy.plugins.scanners.sqli.signatures import ERROR_SIGNATURES
from pwnproxy.plugins.scanners.sqli.payloads import get_error_payloads, TIME_PAYLOADS
from pwnproxy.plugins.scanners.sqli.scanner import SQLiScanner


class SQLiScannerPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="sqli",
        version="0.3.0",
        author="pwnproxy",
        consumes=["flow"],
        produces=["finding"],
    )
    techniques = ["error-based", "boolean-blind", "time-based", "oob"]
    capabilities = ["sql-injection", "blind-sqli"]

    async def on_load(self) -> None:
        depth = self.context.config.get("depth", "fast")
        evasion_level = self.context.config.get("evasion_level", "none")
        aggressive_status = bool(self.context.config.get("aggressive_status", False))
        self._replayer = RequestReplayer()
        chain = chain_from_depth([
            ErrorBasedStage(
                self._replayer, ERROR_SIGNATURES, get_error_payloads(), evasion_level,
                aggressive_status=aggressive_status,
            ),
            BooleanBlindStage(self._replayer, evasion_level),
            TimeBlindStage(self._replayer, TIME_PAYLOADS, evasion_level),
            OOBStage(self._replayer, evasion_level),
        ], depth=depth)
        self._scanner = SQLiScanner(chain)

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
