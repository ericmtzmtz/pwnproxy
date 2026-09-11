"""LFI plugin entry point."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from pwnproxy.plugins.core.base import Finding, PluginMetadata, ScannerPlugin
from pwnproxy.plugins.scanners.lfi.payloads import (
    PHP_WRAPPER_PAYLOADS,
    get_payloads,
)
from pwnproxy.plugins.scanners.lfi.scanner import LFIScanner
from pwnproxy.plugins.scanners.lfi.signatures import OsSignatureMatcher
from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import extract as extract_params
from pwnproxy.shared.scan.replayer import RequestReplayer


class LFIScannerPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="lfi",
        version="0.3.0",
        author="pwnproxy",
        consumes=["flow"],
        produces=["finding"],
    )
    techniques = ["lfi-simple", "lfi-php-wrapper", "lfi-oob"]
    capabilities = ["local-file-inclusion", "lfi"]

    async def on_load(self) -> None:
        depth = self.context.config.get("depth", "fast")
        evasion_level = self.context.config.get("evasion_level", "none")
        if depth not in ("fast", "standard", "deep"):
            raise ValueError(f"invalid depth '{depth}' — expected fast|standard|deep")
        if evasion_level not in ("none", "light", "aggressive"):
            raise ValueError(f"invalid evasion_level '{evasion_level}'")
        self._replayer = RequestReplayer()
        self._scanner = LFIScanner(
            self._replayer,
            payloads=get_payloads(),
            php_payloads=PHP_WRAPPER_PAYLOADS,
            matcher=OsSignatureMatcher(),
            depth=depth,
            evasion=evasion_level,
        )

    async def on_flow(self, flow: Flow) -> AsyncGenerator[Finding, None]:
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
