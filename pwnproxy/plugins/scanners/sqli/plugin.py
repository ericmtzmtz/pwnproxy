from collections.abc import AsyncGenerator

from pwnproxy.shared.models import Flow
from pwnproxy.plugins.core.base import Finding, ScannerPlugin
from pwnproxy.shared.scan.params import extract as extract_params


class SQLiScannerPlugin(ScannerPlugin):
    name = "sqli"
    version = "0.2.0"
    author = "pwnproxy"

    def __init__(self, scanner):
        self._scanner = scanner

    async def scan(
        self,
        flow: Flow,
        depth: str = "fast",
        evasion_level: str = "none",
    ) -> AsyncGenerator[Finding, None]:
        points = extract_params(flow)
        seen = set()
        for point in points:
            key = (point.host + point.path, point.name, point.location)
            if key in seen:
                continue
            seen.add(key)
            async for finding in self._scanner._scan_point(point, depth=depth, evasion_level=evasion_level):
                yield finding
