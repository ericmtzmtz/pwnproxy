import asyncio
import inspect
import logging
from collections.abc import AsyncGenerator
from typing import Optional

from pwnproxy.shared.models import Flow
from pwnproxy.services.plugins.base import Finding, HookPlugin, PwnPlugin, ScannerPlugin
from pwnproxy.services.plugins.config import load_config
from pwnproxy.services.plugins.discovery import discover_installed
from pwnproxy.services.plugins.watchdog import PluginWatchdog

logger = logging.getLogger(__name__)


class PluginLoader:
    def __init__(self):
        self._plugins: dict[str, PwnPlugin] = {}
        self._scanner_plugins: dict[str, ScannerPlugin] = {}
        self._hook_plugins: dict[str, HookPlugin] = {}
        self._watchdog = PluginWatchdog()
        cfg = load_config()
        self._timeout = cfg.get("plugin_timeout", 30)

    async def load_builtin(self, plugin: PwnPlugin) -> None:
        name = plugin.name or plugin.__class__.__name__
        if name in self._plugins:
            logger.warning("Plugin %s already loaded, skipping", name)
            return
        await plugin.on_load()
        self._plugins[name] = plugin
        if isinstance(plugin, ScannerPlugin):
            self._scanner_plugins[name] = plugin
        elif isinstance(plugin, HookPlugin):
            self._hook_plugins[name] = plugin
        logger.info("Loaded builtin plugin: %s (%s)", name, plugin.category)

    async def load_from_package(self, package_name: str) -> Optional[str]:
        from pwnproxy.services.plugins.discovery import install_package
        if not install_package(package_name):
            return None
        return package_name

    async def activate(self, name: str) -> bool:
        plugin = self._plugins.get(name)
        if plugin is None:
            logger.error("Plugin %s not found", name)
            return False
        self._watchdog.enable(name)
        await plugin.on_load()
        logger.info("Activated plugin: %s", name)
        return True

    def deactivate(self, name: str) -> bool:
        plugin = self._plugins.get(name)
        if plugin is None:
            return False
        self._watchdog.disable(name)
        logger.info("Deactivated plugin: %s", name)
        return True

    async def run_scan(
        self,
        flow: Flow,
        depth: str = "fast",
        evasion_level: str = "none",
    ) -> list[Finding]:
        results: list[Finding] = []
        for name, plugin in list(self._scanner_plugins.items()):
            if self._watchdog.is_disabled(name):
                continue
            try:
                # Call scan() with depth and evasion_level params
                scan_result = plugin.scan(flow, depth=depth, evasion_level=evasion_level)
                
                # Check if it's an async generator (new-style)
                if inspect.isasyncgen(scan_result):
                    # Iterate async generator with timeout
                    async def _collect_findings():
                        findings = []
                        async for finding in scan_result:
                            findings.append(finding)
                        return findings
                    
                    findings = await asyncio.wait_for(
                        _collect_findings(),
                        timeout=self._timeout,
                    )
                    results.extend(findings)
                else:
                    # Old-style coroutine returning Optional[Finding]
                    result = await asyncio.wait_for(
                        scan_result,
                        timeout=self._timeout,
                    )
                    if isinstance(result, Finding):
                        results.append(result)
                
                self._watchdog.report_success(name)
            except asyncio.TimeoutError:
                self._watchdog.report_failure(name, "timeout")
            except Exception as e:
                self._watchdog.report_failure(name, str(e))
        return results

    async def run_hooks_request(self, flow: Flow) -> Flow:
        for name, plugin in list(self._hook_plugins.items()):
            if self._watchdog.is_disabled(name):
                continue
            try:
                result = await asyncio.wait_for(
                    plugin.on_request(flow),
                    timeout=self._timeout,
                )
                if result is not None:
                    flow = result
                self._watchdog.report_success(name)
            except asyncio.TimeoutError:
                self._watchdog.report_failure(name, "timeout")
            except Exception as e:
                self._watchdog.report_failure(name, str(e))
        return flow

    async def run_hooks_response(self, flow: Flow) -> Flow:
        for name, plugin in list(self._hook_plugins.items()):
            if self._watchdog.is_disabled(name):
                continue
            try:
                result = await asyncio.wait_for(
                    plugin.on_response(flow),
                    timeout=self._timeout,
                )
                if result is not None:
                    flow = result
                self._watchdog.report_success(name)
            except asyncio.TimeoutError:
                self._watchdog.report_failure(name, "timeout")
            except Exception as e:
                self._watchdog.report_failure(name, str(e))
        return flow

    def list_active(self) -> list[dict]:
        return [
            {
                "name": name,
                "category": p.category,
                "version": getattr(p, "version", ""),
                "author": getattr(p, "author", ""),
                "disabled": self._watchdog.is_disabled(name),
            }
            for name, p in self._plugins.items()
        ]

    def list_available(self) -> list[dict]:
        return discover_installed()

    def watchdog_stats(self) -> dict:
        return self._watchdog.stats()

    def get_scanner(self, name: str) -> Optional[ScannerPlugin]:
        return self._scanner_plugins.get(name)

    def get_all_scanners(self) -> dict[str, ScannerPlugin]:
        return dict(self._scanner_plugins)

    def get_plugin(self, name: str) -> Optional[PwnPlugin]:
        return self._plugins.get(name)
