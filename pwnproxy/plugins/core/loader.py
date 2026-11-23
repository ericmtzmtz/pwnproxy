import asyncio
import contextlib
import logging
from collections.abc import AsyncGenerator
from typing import Any

from pwnproxy.plugins.core.base import (
    Finding,
    PluginContext,
    PluginMetadata,
    PwnPlugin,
    ScannerPlugin,
)
from pwnproxy.plugins.core.catalog import (
    SOURCE_BUILTIN,
    PluginRecord,
    discover_plugins,
)
from pwnproxy.plugins.core.config import (
    ActivationConfigError,
    load_activation,
    set_plugin_enabled,
)
from pwnproxy.shared.findings.events import publish_stored_finding
from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.models import Flow

logger = logging.getLogger(__name__)


class PluginLoadError(Exception):
    """Exception raised when a plugin fails to load."""


class PluginNotFoundError(LookupError):
    """Raised by :meth:`UniversalPluginLoader.toggle` for an unknown plugin name.

    The API maps it to ``404``: the name is not in the catalog, so there is no
    state to create.
    """

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


class PluginUnavailableError(RuntimeError):
    """Raised by :meth:`UniversalPluginLoader.toggle` when a plugin cannot run.

    Covers a plugin whose discovery failed and one whose ``on_load()`` fails at
    that moment. The API maps it to ``409`` with the reason.
    """


def _catalog_error(record: PluginRecord, error: str) -> PluginRecord:
    """Return ``record`` with ``error`` set and its factory dropped."""
    return PluginRecord(
        name=record.name,
        source=record.source,
        package=record.package,
        version=record.version,
        entry_point=record.entry_point,
        factory=None,
        error=error,
        metadata=record.metadata,
    )


def _implicit_consumes(plugin: PwnPlugin) -> list[str]:
    """Channels a plugin consumes implicitly via duck-typed handlers.

    Shared by ``load``, ``start`` and ``activate`` (3 real consumers) — the
    same computation was duplicated verbatim in all three before extraction.
    """
    implicit: list[str] = []
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
        self._plugins: dict[str, PwnPlugin] = {}
        self._plugin_tasks: dict[str, asyncio.Task] = {}
        self._timeout = 0.1  # Short timeout for consumer loop responsiveness
        # Auto-scan batch tracker (optional; wired in server startup so the
        # proxy auto-scan path reports windowed started/completed events).
        self.autoscan = None
        # Per-plugin config for auto-discovered scanners, keyed by plugin name.
        # Set by the caller before start() when a runtime value (the SSRF
        # callback port) must reach a plugin that ``start`` loads by itself.
        self.plugin_configs: dict[str, dict] = {}
        # Catalog (built-ins + installed entry points) and the activation table
        # it was resolved against. Both come from ``pwnproxy.plugins.core``;
        # the loader never walks the tree or reads the config on its own.
        self._catalog: list[PluginRecord] = []
        self._activation: dict[str, bool] = {}

    async def load(
        self, 
        plugin: PwnPlugin, 
        channel_mapping: dict[str, str] | None = None
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
        
        # Consume channels are wired when consumer tasks start in start().
        # Register the channels that the plugin produces to.

        for produce_type in plugin.metadata.produces:
            channel_name = channel_mapping.get(produce_type, produce_type)
            self.hook_bus.register_channel(channel_name)
        
        logger.info("Loaded plugin: %s with channels: %s", name, list(plugin.metadata.consumes))
        self._plugins[name] = plugin

    async def load_builtin(self, plugin: PwnPlugin, config: dict | None = None) -> None:
        """Load a builtin plugin and call its on_load hook."""
        await self.load(plugin)
        ctx = PluginContext(config=config or {}, hook_bus=self.hook_bus)
        plugin.context = ctx
        await plugin.on_load()

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
                if consume_type == "flow" and hasattr(plugin, "on_flow"):
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
        else:
            # Legacy: use HookBus
            try:
                queue = self.hook_bus.register(channel_name)
                
                while True:
                    try:
                        # Wait for data with a timeout to allow graceful shutdown
                        data = await asyncio.wait_for(queue.get(), timeout=self._timeout)
                        
                        if consume_type == "flow" and hasattr(plugin, "on_flow"):
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
                    except TimeoutError:
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
        if self.autoscan is not None:
            try:
                await self.autoscan.report_flow(flow)
            except Exception:
                logger.debug("autoscan report_flow failed", exc_info=True)
        if hasattr(plugin, "on_flow"):
            async for result in plugin.on_flow(flow):
                yield result

    def _events_session_id(self) -> str | None:
        """Return the session name outgoing events should be tagged with.

        Prefers the running scan job's session (headless scans can name a
        session explicitly, and concurrent sessions must not cross), falling
        back to the manager's active session. Never a UUID: the rest of the bus
        and the WS rooms filter by session *name*.
        """
        sid = getattr(self, "_current_scan_session", None)
        if not sid:
            sm = getattr(self, "_session_manager", None)
            if sm and getattr(sm, "active_name", None):
                sid = sm.active_name
        return sid

    async def _publish_results(self, plugin: PwnPlugin, result: Any) -> None:
        """Publish plugin results to appropriate channels."""
        if result is None:
            return

        # Tag finding/triage events with session_id where known (for WS rooms)
        # Prefer the scan job's session (for headless scans with explicit session_name)
        # over the global active_name, to handle concurrent sessions correctly.
        tagged = result
        if isinstance(result, dict) and "session_id" not in result:
            sid = self._events_session_id()
            if sid:
                tagged = {**result, "session_id": sid}

        for produce_type in plugin.metadata.produces:
            channel_name = produce_type  # Default mapping
            self.hook_bus.publish(channel_name, tagged)
            if self.autoscan is not None and produce_type == "finding":
                try:
                    await self.autoscan.report_finding()
                except Exception:
                    logger.debug("autoscan report_finding failed", exc_info=True)

    # -- Catalog -----------------------------------------------------------
    #
    # ``discover_scanners`` used to walk ``plugins/scanners/*/plugin.py`` on its
    # own; that made it a second (third, fourth...) source of truth next to the
    # hardcoded registries in the CLI and the transport layer. Discovery now
    # belongs to ``pwnproxy.plugins.core.catalog``: the loader only loads what
    # the catalog found, honouring the machine-wide activation table.

    def catalog(self) -> list[PluginRecord]:
        """Return the catalog this loader resolved (built-ins first, then installed)."""
        return list(self._catalog)

    def get_record(self, name: str) -> PluginRecord | None:
        """Return the catalog record for ``name`` (``None`` when unknown)."""
        return next((record for record in self._catalog if record.name == name), None)

    def known_names(self) -> list[str]:
        """Return every plugin name in the catalog, broken ones included."""
        return [record.name for record in self._catalog]

    def plugin_enabled(self, name: str) -> bool:
        """Return the effective state of ``name``: configured **and** able to run.

        A plugin that failed to discover/load reports ``False`` even when the
        configuration says ``true``: reporting it as enabled would promise
        scanning that is not happening.
        """
        record = self.get_record(name)
        if record is None or record.error:
            return False
        plugin = self._plugins.get(name)
        if plugin is not None and plugin.metadata is not None and plugin.metadata.disabled:
            return False
        return self._activation.get(name, record.source == SOURCE_BUILTIN)

    def disabled_names(self) -> list[str]:
        """Return the names whose effective state is off (used by one-shot scans)."""
        return [record.name for record in self._catalog if not self.plugin_enabled(record.name)]

    def _replace_record(self, record: PluginRecord) -> None:
        """Swap ``record`` into the catalog, keeping the catalog's order."""
        for index, current in enumerate(self._catalog):
            if current.name == record.name:
                self._catalog[index] = record
                return
        self._catalog.append(record)
        self._catalog.sort(key=lambda r: (0 if r.source == SOURCE_BUILTIN else 1, r.name))

    def _set_catalog_error(self, name: str, error: str) -> None:
        """Record a runtime load failure on the catalog entry for ``name``."""
        record = self.get_record(name)
        if record is not None:
            self._replace_record(_catalog_error(record, error))

    async def refresh_catalog(self, scanners_path: str | None = None) -> list[PluginRecord]:
        """Rebuild the catalog and load every enabled plugin, isolating failures.

        Args:
            scanners_path: Override for the built-in scanners directory.

        Returns:
            The new catalog. A plugin that fails to import, instantiate or run
            its ``on_load()`` gets its ``error`` recorded and is left out of the
            loaded set; the rest (and the proxy) keep working.
        """
        path = scanners_path if scanners_path is not None else self._scanners_path
        self._catalog = discover_plugins(path)
        self._activation = load_activation()
        for record in self._catalog:
            if record.error:
                logger.warning(
                    "Plugin %s (%s) is unavailable: %s", record.name, record.package, record.error
                )
                continue
            if not self.plugin_enabled(record.name):
                logger.debug("Plugin %s (%s) is disabled; not loading it", record.name, record.source)
                continue
            await self._load_record(record)
        return list(self._catalog)

    async def _load_record(self, record: PluginRecord) -> bool:
        """Load one catalog record. Returns ``False`` when it could not be loaded."""
        if record.factory is None or record.error:
            return False
        if record.name in self._plugins:
            return True
        try:
            plugin = record.factory()
        except Exception as exc:
            self._set_catalog_error(record.name, f"instantiation failed ({exc})")
            logger.warning("Plugin %s (%s) could not be instantiated: %s", record.name, record.package, exc)
            return False
        try:
            await self.load_builtin(plugin, config=self.plugin_configs.get(record.name))
        except Exception as exc:
            # ``load_builtin`` registers the plugin before ``on_load``; a
            # half-loaded plugin must not stay in the loaded set.
            self._plugins.pop(record.name, None)
            with contextlib.suppress(Exception):
                await plugin.on_unload()
            self._set_catalog_error(record.name, f"on_load failed ({type(exc).__name__}: {exc})")
            logger.warning(
                "Plugin %s (%s) failed on_load and stays disabled: %s", record.name, record.package, exc
            )
            return False
        logger.info("Loaded plugin %s (%s)", record.name, record.source)
        return True

    async def discover_scanners(self, scanners_path: str | None = None) -> None:
        """Discover and load the scanners (kept as the historical entry point).

        Kept because ``start()``, ``pwnproxy start`` and the port guard call it;
        it is now a thin alias of :meth:`refresh_catalog` so there is exactly one
        discovery path.
        """
        await self.refresh_catalog(scanners_path)

    async def retry_load(self, name: str) -> str | None:
        """Re-discover and try to load ``name`` once.

        Returns:
            ``None`` when the plugin is loaded, otherwise the reason it could
            not be (also recorded in the catalog). No automatic retries: a
            broken package must not hammer the log or the disk.
        """
        records = discover_plugins(self._scanners_path)
        fresh = next((record for record in records if record.name == name), None)
        if fresh is None:
            return f"plugin '{name}' is no longer in the catalog"
        self._replace_record(fresh)
        if fresh.error:
            return fresh.error
        if name in self._plugins:
            return None
        loaded = await self._load_record(fresh)
        if loaded:
            return None
        record = self.get_record(name)
        return record.error if record is not None else f"plugin '{name}' could not be loaded"

    async def toggle(self, name: str) -> str:
        """Enable or disable ``name`` and persist the decision.

        The decision is written to ``[plugin.activation]`` *before* the call is
        reported as done: a failed write leaves the in-memory state untouched so
        the process never disagrees with the file.

        Args:
            name: Plugin name as published by the catalog.

        Returns:
            ``"enabled"`` or ``"disabled"``.

        Raises:
            PluginNotFoundError: the name is not in the catalog.
            PluginUnavailableError: the plugin is broken (discovery failed) or
                its ``on_load()`` failed during this call; it stays disabled.
            ActivationConfigError: the config file cannot be written.
        """
        record = self.get_record(name)
        if record is None:
            raise PluginNotFoundError(name)

        if self.plugin_enabled(name):
            set_plugin_enabled(name, False)  # may raise ActivationConfigError
            self._activation[name] = False
            self.deactivate(name)
            return "disabled"

        was_loaded = name in self._plugins
        if record.error or not was_loaded:
            error = await self.retry_load(name)
            if error:
                raise PluginUnavailableError(f"plugin '{name}' cannot run: {error}")
        try:
            set_plugin_enabled(name, True)
        except ActivationConfigError:
            if not was_loaded:
                await self.unload(name)
            raise
        self._activation[name] = True
        await self.activate(name)
        return "enabled"

    async def activate(self, name: str) -> bool:
        """Start consuming for ``name`` (idempotent: no duplicate consumer tasks).

        ``metadata.disabled`` is not enough to decide this: a plugin loaded after
        ``start()`` (the ``toggle`` path) has never had consumers, yet its
        metadata says enabled. The running consumer tasks are the truth, so this
        only creates the ones that are missing.

        Args:
            name: Loaded plugin name.

        Returns:
            ``True`` when the plugin is active afterwards, ``False`` when it is
            not loaded at all.
        """
        plugin = self._plugins.get(name)
        if plugin is None:
            logger.warning("Cannot activate unknown plugin: %s", name)
            return False
        plugin.metadata.disabled = False
        implicit_consumes = _implicit_consumes(plugin)
        all_consumes = list(plugin.metadata.consumes) + implicit_consumes
        started = False
        for consume_type in all_consumes:
            task_key = f"{name}_{consume_type}"
            if task_key in self._plugin_tasks:
                continue
            task = asyncio.create_task(self._run_consumer(plugin, consume_type, consume_type))
            self._plugin_tasks[task_key] = task
            started = True
        if started:
            logger.info("Activated plugin: %s", name)
        else:
            logger.debug("Plugin %s is already consuming", name)
        return True

    def deactivate(self, name: str) -> bool:
        """Stop consuming for ``name`` by cancelling its consumer tasks.

        The plugin stays loaded so it can be re-activated without reloading.
        """
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

    def list_active(self) -> list[dict[str, Any]]:
        """Return the loaded, enabled plugins with their metadata."""
        return [self.get_plugin_info(name) for name in self.list_plugins()
                if self.get_plugin_info(name) and not self._plugins[name].metadata.disabled]

    def watchdog_stats(self) -> dict[str, Any]:
        """Return the runtime-disabled plugin names."""
        disabled = [name for name, p in self._plugins.items() if p.metadata.disabled]
        return {"disabled": disabled}

    async def start(self, name: str | None = None) -> None:
        """Start consumer tasks for plugins and wire FindingStorage to HookBus."""
        # Build the catalog (built-ins + installed entry points) and load the
        # enabled plugins. A broken plugin is recorded and skipped, never fatal.
        await self.refresh_catalog()

        # Existing plugin consumer startup
        plugins_to_start = [name] if name is not None else list(self._plugins)
        for pname in plugins_to_start:
            if pname in self._plugins:
                await self.activate(pname)
        
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
                        if isinstance(finding, dict) and "id" in finding:
                            # Already persisted by its producer (``POST
                            # /api/v1/findings`` publishes the saved row and
                            # announces it on ``finding.stored`` itself);
                            # saving it again would duplicate the finding. A
                            # dict *without* ``id`` is a raw finding from a
                            # plugin and is still stored.
                            continue
                        try:
                            storage = FindingStorage(sm.get_scanner_engine())
                            record_id = await storage.save(finding)
                            row = await storage.get(record_id)
                        except Exception as e:
                            # No row, no event: the UI must never show a finding
                            # that is not in the session database.
                            logger.error("Failed to save finding: %s", e)
                            continue
                        if row is None:
                            logger.warning(
                                "Saved finding %s could not be re-read; no live event emitted",
                                record_id,
                            )
                            continue
                        publish_stored_finding(self.hook_bus, row, self._events_session_id())
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
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        
        # Call plugin unload hook
        try:
            await plugin.on_unload()
        except Exception as e:
            logger.error("Error during plugin unload %s: %s", name, e)
        
        del self._plugins[name]
        logger.info("Unloaded plugin: %s", name)

    def get_plugin(self, name: str) -> PwnPlugin | None:
        """Get a loaded plugin by name."""
        return self._plugins.get(name)

    def list_plugins(self) -> list[str]:
        """List all loaded plugin names."""
        return list(self._plugins.keys())

    def get_plugin_info(self, name: str) -> dict[str, Any] | None:
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
    
    def get_scanner(self, name: str) -> PwnPlugin | None:
        """Get a scanner plugin (backward compatibility)."""
        return self.get_plugin(name)
    
    def get_all_scanners(self) -> dict[str, PwnPlugin]:
        """Get all scanner plugins (backward compatibility)."""
        return {name: plugin for name, plugin in self._plugins.items() if hasattr(plugin, 'on_flow')}
    
    async def run_scan(self, flow: Flow) -> list[Finding]:
        """Run a scan across loaded scanner plugins.

        Depth and evasion are load-time properties baked into the chain.
        """
        results: list[Finding] = []
        for plugin in self._plugins.values():
            if isinstance(plugin, ScannerPlugin):
                try:
                    if hasattr(plugin, "on_flow"):
                        async for finding in plugin.on_flow(flow):
                            if finding:
                                results.append(finding)
                except Exception as e:
                    logger.error("Scan error for %s: %s", plugin.metadata.name, e)
        return results
