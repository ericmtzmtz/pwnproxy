import asyncio
import importlib
import importlib.util
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Union
from collections.abc import AsyncGenerator

from pwnproxy.shared.models import Flow
from pwnproxy.plugins.core.base import Finding, PwnPlugin, PluginMetadata, PluginContext, ScannerPlugin
from pwnproxy.plugins.core.contracts import FlowConsumer, FindingConsumer
from pwnproxy.shared.hooks import HookBus

logger = logging.getLogger(__name__)


class PluginLoadError(Exception):
    """Exception raised when a plugin fails to load."""
    pass


def _implicit_consumes(plugin: PwnPlugin) -> List[str]:
    """Channels a plugin consumes implicitly via duck-typed handlers.

    Shared by ``load``, ``start`` and ``activate`` (3 real consumers) — the
    same computation was duplicated verbatim in all three before extraction.
    """
    implicit: List[str] = []
    if hasattr(plugin, "on_finding") and "finding" not in plugin.metadata.consumes:
        implicit.append("finding")
    if hasattr(plugin, "on_surface") and "surface" not in plugin.metadata.consumes:
        implicit.append("surface")
    if hasattr(plugin, "on_evidence") and "evidence" not in plugin.metadata.consumes:
        implicit.append("evidence")
    return implicit


class UniversalPluginLoader:
    """Universal plugin loader that connects plugins based on contracts."""
    
    def __init__(self, hook_bus: HookBus, bus=None, scanners_path: str | None = None):
        self.hook_bus = hook_bus
        self.bus = bus  # Optional MessageBus
        self._scanners_path = scanners_path
        self._plugins: Dict[str, PwnPlugin] = {}
        self._plugin_tasks: Dict[str, asyncio.Task] = {}
        self._timeout = 0.1  # Short timeout for consumer loop responsiveness

    async def load(
        self, 
        plugin: PwnPlugin, 
        channel_mapping: Optional[Dict[str, str]] = None
    ) -> None:
        """Load a plugin and connect it to appropriate channels based on contracts.
        
        Args:
            plugin: The plugin instance to load
            channel_mapping: Optional mapping of plugin consumes/produces to actual channel names
        """
        # Ensure plugin has metadata; construct default if missing
        if not hasattr(plugin, "metadata") or plugin.metadata is None:
            # Build metadata from class attributes if available
            meta = PluginMetadata(
                name=getattr(plugin, "name", plugin.__class__.__name__),
                version=getattr(plugin, "version", "0.0.0"),
                author=getattr(plugin, "author", ""),
                category=getattr(plugin, "category", ""),
                description=getattr(plugin, "description", ""),
                consumes=getattr(plugin, "consumes", []),
                produces=getattr(plugin, "produces", []),
            )
            plugin.metadata = meta
        name = plugin.metadata.name or plugin.__class__.__name__
        
        if name in self._plugins:
            logger.warning("Plugin %s already loaded, skipping", name)
            return

        # Register plugin channels based on consumes/produces
        if channel_mapping is None:
            channel_mapping = {}
        
        # Register channels that the plugin consumes from, including implicit handlers
        implicit_consumes = _implicit_consumes(plugin)
        # Combine explicit and implicit consumes
        all_consumes = list(plugin.metadata.consumes) + implicit_consumes
        # Register consume channels (tasks will be started in start())
        
        # Register channels that the plugin produces to
        for produce_type in plugin.metadata.produces:
            channel_name = channel_mapping.get(produce_type, produce_type)
            self.hook_bus.register_channel(channel_name)
        
        logger.info("Loaded plugin: %s with channels: %s", name, list(plugin.metadata.consumes))
        self._plugins[name] = plugin

    async def _run_consumer(
        self, 
        plugin: PwnPlugin, 
        consume_type: str, 
        channel_name: str
    ) -> None:
        """Run a consumer task for a plugin on a specific channel."""
        # New branch: use InProcessBus if available
        if self.bus is not None:
            async for envelope in self.bus.subscribe(channel_name):
                data = envelope.data
                if consume_type == "flow" and (hasattr(plugin, "on_flow") or hasattr(plugin, "scan")):
                    async for result in self._handle_flow(plugin, data):
                        if result is not None:
                            await self._publish_results(plugin, result)
                elif consume_type == "finding" and hasattr(plugin, "on_finding"):
                    result = await plugin.on_finding(data)
                    if result is not None:
                        await self._publish_results(plugin, result)
                elif consume_type == "surface" and hasattr(plugin, "on_surface"):
                    result = await plugin.on_surface(data)
                    if result is not None:
                        await _publish_results(plugin, result)
                elif consume_type == "evidence" and hasattr(plugin, "on_evidence"):
                    result = await plugin.on_evidence(data)
                    if result is not None:
                        await self._publish_results(plugin, result)
                else:
                    logger.warning("Plugin %s has no handler for %s", plugin.metadata.name, consume_type)
        else:
            # Legacy: use HookBus
            try:
                queue = self.hook_bus.register(channel_name)
                
                while True:
                    try:
                        # Wait for data with a timeout to allow graceful shutdown
                        data = await asyncio.wait_for(queue.get(), timeout=self._timeout)
                        
                        if consume_type == "flow" and (hasattr(plugin, "on_flow") or hasattr(plugin, "scan")):
                            async for result in self._handle_flow(plugin, data):
                                if result is not None:
                                    await self._publish_results(plugin, result)
                        
                        elif consume_type == "finding" and hasattr(plugin, "on_finding"):
                            result = await plugin.on_finding(data)
                            if result is not None:
                                await self._publish_results(plugin, result)
                        
                        elif consume_type == "surface" and hasattr(plugin, "on_surface"):
                            result = await plugin.on_surface(data)
                            if result is not None:
                                await self._publish_results(plugin, result)
                        
                        elif consume_type == "evidence" and hasattr(plugin, "on_evidence"):
                            result = await plugin.on_evidence(data)
                            if result is not None:
                                await self._publish_results(plugin, result)
                        
                        else:
                            logger.warning("Plugin %s has no handler for %s", plugin.metadata.name, consume_type)
                    
                    except asyncio.CancelledError:
                        logger.debug("Consumer cancelled for %s on %s", plugin.metadata.name, channel_name)
                        raise
                    except asyncio.TimeoutError:
                        # Timeout indicates no data; loop again to check for cancellation
                        continue
                    except Exception as e:
                        logger.error("Error in consumer %s on %s: %s", plugin.metadata.name, channel_name, e)
                        break
            
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error("Failed to start consumer %s on %s: %s", plugin.metadata.name, channel_name, e)

    async def _handle_flow(self, plugin: PwnPlugin, flow: Flow) -> AsyncGenerator[Any, None]:
        """Handle flow data - either through new on_flow() or legacy scan() method."""
        if hasattr(plugin, "on_flow"):
            # New-style plugin
            async for result in plugin.on_flow(flow):
                yield result
        elif hasattr(plugin, "scan"):
            # Legacy plugin - migrate scan() to on_flow()
            try:
                async for result in plugin.scan(flow):
                    yield result
            except Exception as e:
                logger.error("Legacy scan() failed for %s: %s", plugin.metadata.name, e)
                # skip erroneous result

    async def _publish_results(self, plugin: PwnPlugin, result: Any) -> None:
        """Publish plugin results to appropriate channels."""
        if result is None:
            return
            
        for produce_type in plugin.metadata.produces:
            channel_name = produce_type  # Default mapping
            self.hook_bus.publish(channel_name, result)

    async def discover_scanners(self, scanners_path: str | None = None) -> None:
        """Auto-discover ScannerPlugin subclasses from the scanners directory."""
        path = scanners_path or self._scanners_path
        if path is None:
            from pwnproxy import __file__ as _pwnproxy_init
            path = str(Path(_pwnproxy_init).parent / "plugins" / "scanners")
            self._scanners_path = path
        scanners_dir = Path(path)
        if not scanners_dir.is_dir():
            logger.warning("Scanners directory not found: %s", path)
            return

        for entry in sorted(scanners_dir.iterdir()):
            if not entry.is_dir():
                continue
            plugin_file = entry / "plugin.py"
            if not plugin_file.exists():
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    f"{entry.name}.plugin", str(plugin_file)
                )
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for name, obj in vars(module).items():
                    if isinstance(obj, type) and issubclass(obj, ScannerPlugin) and obj is not ScannerPlugin:
                        plugin_instance = obj()
                        await self.load_builtin(plugin_instance)
                        logger.info("Auto-discovered scanner: %s", plugin_instance.metadata.name)
                        break
            except Exception as e:
                logger.warning("Failed to load scanner from %s: %s", entry.name, e)

    async def start(self, name: Optional[str] = None) -> None:
        """Start consumer tasks for plugins and wire FindingStorage to HookBus."""
        # Auto-discover scanners from filesystem
        await self.discover_scanners()

        # Existing plugin consumer startup
        plugins_to_start: Dict[str, PwnPlugin] = {}
        if name is not None:
            plugin = self._plugins.get(name)
            if plugin:
                plugins_to_start[name] = plugin
        else:
            plugins_to_start = dict(self._plugins)
        
        for pname, plugin in plugins_to_start.items():
            implicit_consumes = _implicit_consumes(plugin)
            all_consumes = list(plugin.metadata.consumes) + implicit_consumes
            for consume_type in all_consumes:
                channel_name = consume_type
                task = asyncio.create_task(self._run_consumer(plugin, consume_type, channel_name))
                self._plugin_tasks[f"{pname}_{consume_type}"] = task
        
        # Wire FindingStorage to the "finding" channel if session manager is available
        try:
            session_manager = getattr(self, "_session_manager", None)
            if session_manager is None:
                # attempt to get from hook_bus app state if running under FastAPI
                session_manager = getattr(self.hook_bus, "app", None) and getattr(self.hook_bus.app, "state", None) and getattr(self.hook_bus.app.state, "session_manager", None)
            if session_manager:
                from pwnproxy.shared.findings.storage import FindingStorage
                sm = session_manager
                # Ensure findings table exists in current engine
                tmp = FindingStorage(sm.get_scanner_engine())
                await tmp.create_table()
                async def _consume_findings():
                    q = self.hook_bus.register("finding")
                    while True:
                        finding = await q.get()
                        try:
                            storage = FindingStorage(sm.get_scanner_engine())
                            await storage.save(finding)
                        except Exception as e:
                            logger.error("Failed to save finding: %s", e)
                asyncio.create_task(_consume_findings())
        except Exception as e:
            logger.error("Failed to wire FindingStorage: %s", e)




    async def unload(self, name: str) -> None:
        """Unload a plugin and stop its consumer tasks."""
        plugin = self._plugins.get(name)
        if plugin is None:
            return
        
        # Cancel consumer tasks
        for task_key in list(self._plugin_tasks.keys()):
            if task_key.startswith(f"{name}_"):
                task = self._plugin_tasks.pop(task_key)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        # Call plugin unload hook
        try:
            await plugin.on_unload()
        except Exception as e:
            logger.error("Error during plugin unload %s: %s", name, e)
        
        del self._plugins[name]
        logger.info("Unloaded plugin: %s", name)

    def get_plugin(self, name: str) -> Optional[PwnPlugin]:
        """Get a loaded plugin by name."""
        return self._plugins.get(name)

    def list_plugins(self) -> List[str]:
        """List all loaded plugin names."""
        return list(self._plugins.keys())

    def get_plugin_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get information about a loaded plugin."""
        plugin = self._plugins.get(name)
        if plugin is None:
            return None
            
        return {
            "name": plugin.metadata.name,
            "version": plugin.metadata.version,
            "author": plugin.metadata.author,
            "category": plugin.metadata.category,
            "description": plugin.metadata.description,
            "disabled": plugin.metadata.disabled,
            "consumes": plugin.metadata.consumes,
            "produces": plugin.metadata.produces,
            "capabilities": plugin.metadata.capabilities,
            "parameters": plugin.metadata.parameters,
            "examples": plugin.metadata.examples,
            "storage": str(plugin.metadata.storage) if plugin.metadata.storage else None,
        }

    async def shutdown(self) -> None:
        """Shut down all consumer tasks and unload all plugins."""
        for name in list(self._plugins.keys()):
            await self.unload(name)


# Backward compatibility - keep the old PluginLoader interface for existing code
class PluginLoader(UniversalPluginLoader):
    """Backward compatibility wrapper for UniversalPluginLoader."""
    
    def __init__(self, hook_bus=None, bus=None):
        if hook_bus is None:
            from pwnproxy.shared.hooks import HookBus
            hook_bus = HookBus()
        super().__init__(hook_bus, bus=bus)
    
    async def load_builtin(self, plugin: PwnPlugin) -> None:
        """Load a builtin plugin and call its on_load hook."""
        await self.load(plugin)
        ctx = PluginContext(config={}, hook_bus=self.hook_bus)
        plugin.context = ctx
        await plugin.on_load()
    
    async def load_from_package(self, package_name: str) -> Optional[str]:
        """Load plugin from package (placeholder for backward compatibility)."""
        import warnings
        warnings.warn("load_from_package not implemented in new PluginLoader", UserWarning)
        logger.warning("load_from_package not implemented in new PluginLoader")
        return None
    
    async def activate(self, name: str) -> bool:
        plugin = self._plugins.get(name)
        if plugin is None:
            logger.warning("Cannot activate unknown plugin: %s", name)
            return False
        if not plugin.metadata.disabled:
            logger.debug("Plugin %s is already enabled", name)
            return True
        plugin.metadata.disabled = False
        implicit_consumes = _implicit_consumes(plugin)
        all_consumes = list(plugin.metadata.consumes) + implicit_consumes
        for consume_type in all_consumes:
            channel_name = consume_type
            task = asyncio.create_task(self._run_consumer(plugin, consume_type, channel_name))
            self._plugin_tasks[f"{name}_{consume_type}"] = task
        logger.info("Activated plugin: %s", name)
        return True
    
    def deactivate(self, name: str) -> bool:
        plugin = self._plugins.get(name)
        if plugin is None:
            logger.warning("Cannot deactivate unknown plugin: %s", name)
            return False
        if plugin.metadata.disabled:
            logger.debug("Plugin %s is already disabled", name)
            return True
        plugin.metadata.disabled = True
        for task_key in list(self._plugin_tasks.keys()):
            if task_key.startswith(f"{name}_"):
                task = self._plugin_tasks.pop(task_key)
                task.cancel()
        logger.info("Deactivated plugin: %s", name)
        return True
    
    def list_active(self) -> List[Dict[str, Any]]:
        return [self.get_plugin_info(name) for name in self.list_plugins()
                if self.get_plugin_info(name) and not self._plugins[name].metadata.disabled]
    
    def list_available(self) -> List[Dict[str, Any]]:
        """List available plugins (placeholder for backward compatibility)."""
        logger.warning("list_available not implemented in new PluginLoader")
        return []
    
    def watchdog_stats(self) -> Dict[str, Any]:
        disabled = [name for name, p in self._plugins.items() if p.metadata.disabled]
        return {"disabled": disabled}
    
    def get_scanner(self, name: str) -> Optional[PwnPlugin]:
        """Get a scanner plugin (backward compatibility)."""
        return self.get_plugin(name)
    
    def get_all_scanners(self) -> Dict[str, PwnPlugin]:
        """Get all scanner plugins (backward compatibility)."""
        return {name: plugin for name, plugin in self._plugins.items() 
                if hasattr(plugin, 'on_flow') or hasattr(plugin, 'scan')}
    
    async def run_scan(self, flow: Flow, depth: str = "fast", evasion_level: str = "none") -> List[Finding]:
        """Run a scan across loaded scanner plugins.

        This method iterates over all loaded plugins that are instances of
        ``ScannerPlugin`` and invokes their ``on_flow`` method if available,
        otherwise falls back to ``scan`` with the provided ``depth`` and
        ``evasion_level`` arguments. Findings are collected and returned as a
        list.
        """
        results: List[Finding] = []
        for plugin in self._plugins.values():
            if isinstance(plugin, ScannerPlugin):
                try:
                    if hasattr(plugin, "on_flow"):
                        async for finding in plugin.on_flow(flow):
                            if finding:
                                results.append(finding)
                    elif hasattr(plugin, "scan"):
                        async for finding in plugin.scan(flow, depth, evasion_level):
                            if finding:
                                results.append(finding)
                except Exception as e:
                    logger.error("Scan error for %s: %s", plugin.metadata.name, e)
        return results
    
    async def run_hooks_request(self, flow: Flow) -> Flow:
        """Run request hooks (placeholder for backward compatibility)."""
        logger.warning("run_hooks_request not implemented in new PluginLoader - use hook bus instead")
        return flow
    
    async def run_hooks_response(self, flow: Flow) -> Flow:
        """Run response hooks (placeholder for backward compatibility)."""
        import warnings
        warnings.warn("run_hooks_response not implemented in new PluginLoader - use hook bus instead", UserWarning)
        logger.warning("run_hooks_response not implemented in new PluginLoader - use hook bus instead")
        return flow