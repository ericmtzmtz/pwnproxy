import logging
from typing import Optional

from pwnproxy.shared.models import Flow
from pwnproxy.plugins.core.base import Finding, ScannerPlugin
from pwnproxy.plugins.core.loader import PluginLoader
from pwnproxy.services.scan.scan_log_store import ScanLogStore
from pwnproxy.plugins.scanners.lfi.scanner import LFIScanner
from pwnproxy.plugins.scanners.sqli.scanner import SQLiScanner
from pwnproxy.plugins.scanners.ssrf.scanner import SSRFScanner
from pwnproxy.plugins.scanners.xxe.scanner import XXEScanner
from pwnproxy.plugins.scanners.xss.scanner import XSSScanner

logger = logging.getLogger(__name__)

SCANNER_NAMES = ["sqli", "xss", "lfi", "xxe", "ssrf"]


class ScanManager:
    def __init__(
        self,
        sqli: SQLiScanner,
        xss: XSSScanner,
        lfi: LFIScanner,
        xxe: XXEScanner,
        ssrf: SSRFScanner,
        loader: Optional[PluginLoader] = None,
        scan_log_store: Optional[ScanLogStore] = None,
    ):
        self._scanners = {
            "sqli": sqli,
            "xss": xss,
            "lfi": lfi,
            "xxe": xxe,
            "ssrf": ssrf,
        }
        self._loader = loader or PluginLoader()
        self._scan_log_store = scan_log_store or ScanLogStore()

        for name, scanner in self._scanners.items():
            scanner._on_flow_complete = self._make_flow_complete_handler(name)

    @property
    def loader(self) -> PluginLoader:
        return self._loader

    def get_plugin_scanner(self, name: str) -> Optional[ScannerPlugin]:
        return self._loader.get_scanner(name)

    async def scan_flow_via_plugins(self, flow: Flow) -> list[Finding]:
        return await self._loader.run_scan(flow)

    def _make_flow_complete_handler(self, scanner_name: str):
        async def handler(flow_id: str, url: str, method: str, _name: str, duration_ms: float, finding_count: int):
            try:
                await self._scan_log_store.insert_scan_log(
                    flow_id=flow_id,
                    url=url,
                    method=method,
                    scanner_name=scanner_name,
                    status="completed",
                    duration_ms=duration_ms,
                    finding_count=finding_count,
                )
            except Exception as e:
                logger.error(f"Failed to insert scan_log for {scanner_name}: {e}")
        return handler

    def _scanner(self, name: str):
        s = self._scanners.get(name)
        if not s:
            raise ValueError(f"Unknown scanner: {name}. Available: {list(self._scanners.keys())}")
        return s

    async def start(self, name: str) -> None:
        await self._scanner(name).start()

    async def stop(self, name: str) -> None:
        await self._scanner(name).stop()

    def pause(self, name: str) -> None:
        self._scanner(name).pause()

    def resume(self, name: str) -> None:
        self._scanner(name).resume()

    async def start_all(self) -> None:
        for s in self._scanners.values():
            await s.start()

    async def stop_all(self) -> None:
        for s in self._scanners.values():
            await s.stop()

    def pause_all(self) -> None:
        for s in self._scanners.values():
            s.pause()

    def resume_all(self) -> None:
        for s in self._scanners.values():
            s.resume()

    def status(self) -> dict:
        return {name: s.status() for name, s in self._scanners.items()}

    async def rescan_flow(self, flow: Flow) -> list[str]:
        active = [name for name, s in self._scanners.items() if s.is_running]
        if not active:
            return []
        for name in active:
            s = self._scanners[name]
            s._queue.put_nowait(flow)
        return active

    async def ensure_tables(self) -> None:
        await self._scan_log_store.create_table()

    async def dispose(self) -> None:
        await self.stop_all()
        await self._scan_log_store.dispose()
