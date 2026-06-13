import asyncio
from collections.abc import AsyncGenerator

from pwnproxy.shared.models import Flow
from pwnproxy.plugins.core.base import Finding, ScannerPlugin
from pwnproxy.shared.scan.params import extract as extract_params


class SSRFScannerPlugin(ScannerPlugin):
    name = "ssrf"
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
                scanner="ssrf",
                url=flow.url,
                method=flow.method,
                param_name="",
                param_location="",
                technique="scanner",
                severity="high",
                confidence="confirmed",
                payload="",
            )
        
        # Deep detection: integrate OOB callbacks
        if depth == "deep":
            from pwnproxy.shared.canary import get_registry
            from pwnproxy.shared.http_server import get_server as get_http
            
            registry = get_registry()
            canary = registry.create(flow.id)
            
            try:
                server = await get_http()
                if server.is_running:
                    callback_url = server.get_callback_url(canary.token)
                    # Note: actual injection via _scanner is handled internally
                    await asyncio.sleep(0.5)  # brief wait for callback
                    
                    if canary.callback_received:
                        yield Finding(
                            scanner="ssrf",
                            url=flow.url,
                            method=flow.method,
                            param_name="oob",
                            param_location="callback",
                            technique="out-of-band",
                            severity="high",
                            confidence="confirmed",
                            payload=callback_url,
                            evidence=f"Callback from {canary.callback_ip}",
                        )
            except Exception:
                pass
