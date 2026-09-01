"""SSRF plugin entry point."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from pwnproxy.plugins.core.base import PluginMetadata, Finding, ScannerPlugin
from pwnproxy.shared.scan.replayer import RequestReplayer
from pwnproxy.shared.scan.params import extract as extract_params, is_url_like_param
from pwnproxy.shared.models import Flow
from pwnproxy.plugins.scanners.ssrf.scanner import SSRFScanner


class SSRFScannerPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="ssrf",
        version="0.4.0",
        author="pwnproxy",
        consumes=["flow"],
        produces=["finding"],
    )
    techniques = ["ssrf-oob", "ssrf-redirect"]
    capabilities = ["server-side-request-forgery", "ssrf"]

    async def on_load(self) -> None:
        depth = self.context.config.get("depth", "fast")
        evasion_level = self.context.config.get("evasion_level", "none")
        callback_host = self.context.config.get("callback_host", "127.0.0.1")
        callback_port = int(self.context.config.get("callback_port", 18080))
        self._replayer = RequestReplayer()
        self._scanner = SSRFScanner(
            self._replayer,
            depth=depth,
            evasion=evasion_level,
            callback_host=callback_host,
            callback_port=callback_port,
        )

    async def on_flow(self, flow: Flow) -> AsyncGenerator[Finding, None]:
        points = extract_params(flow)
        seen = set()
        for point in points:
            if point.location != "query" and point.location != "body":
                continue
            if not is_url_like_param(point.name):
                continue
            key = (point.host + point.path, point.name, point.location)
            if key in seen:
                continue
            seen.add(key)
            async for finding in self._scanner._scan_point(point):
                yield finding

    async def on_unload(self) -> None:
        await self._replayer.close()
