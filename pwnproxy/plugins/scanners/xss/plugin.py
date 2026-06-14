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
    techniques = ["reflected-xss", "stored-xss", "context-aware-xss"]
    capabilities = ["cross-site-scripting", "reflected-xss", "stored-xss"]

    def __init__(self, scanner=None):
        self._scanner = scanner

    async def on_flow(self, flow: Flow) -> AsyncGenerator[Finding, None]:
        depth = self.context.config.get("depth", "fast")
        evasion_level = self.context.config.get("evasion_level", "none")
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

        replayer = RequestReplayer(flow)
        scanner = XSSScanner(replayer, depth=depth, evasion=evasion_level)
        findings = await scanner.scan(flow, valid_points)
        for finding in findings:
            yield finding
