from collections.abc import AsyncGenerator

from pwnproxy.shared.models import Flow
from pwnproxy.services.plugins.base import Finding, ScannerPlugin
from pwnproxy.services.scan.params import extract as extract_params


class LFIScannerPlugin(ScannerPlugin):
    name = "lfi"
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
        old_count = self._scanner.finding_count
        points = extract_params(flow)
        seen = set()
        for point in points:
            key = (point.host + point.path, point.name, point.location)
            if key in seen:
                continue
            seen.add(key)
            await self._scanner._scan_point(point)
        if self._scanner.finding_count > old_count:
            yield Finding(
                scanner="lfi",
                url=flow.url,
                method=flow.method,
                param_name="",
                param_location="",
                technique="scanner",
                severity="high",
                confidence="confirmed",
                payload="",
            )
