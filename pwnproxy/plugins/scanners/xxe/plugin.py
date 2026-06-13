from collections.abc import AsyncGenerator

from pwnproxy.shared.models import Flow
from pwnproxy.plugins.core.base import Finding, ScannerPlugin
from pwnproxy.shared.scan.params import extract as extract_params


class XXEScannerPlugin(ScannerPlugin):
    name = "xxe"
    version = "0.1.0"
    author = "pwnproxy"

    def __init__(self, scanner):
        self._scanner = scanner

    async def scan(
        self,
        flow: Flow,
        depth: str = "fast",
        evasion_level: str = "none",
    ) -> AsyncGenerator[Finding, None]:
        old_count = self._scanner.finding_count
        points = extract_params(flow)
        seen = set()
        for point in points:
            key = (point.host + point.path, point.name, point.location)
            if key in seen:
                continue
            seen.add(key)
            await self._scanner._scan_point(point, flow)
        if self._scanner.finding_count > old_count:
            yield Finding(
                scanner="xxe",
                url=flow.url,
                method=flow.method,
                param_name="",
                param_location="",
                technique="scanner",
                severity="high",
                confidence="confirmed",
                payload="",
            )
