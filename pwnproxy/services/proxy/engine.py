import asyncio
import logging
from typing import Callable, Optional

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from pwnproxy.shared.hooks import HookBus

logger = logging.getLogger(__name__)


class ProxyEngine:
    """Embedded mitmproxy engine running in an asyncio task."""

    def __init__(self, hook_bus: HookBus, db_engine=None, with_termlog: bool = True, upstream: Optional[str] = None, host: str = "127.0.0.1", port: int = 8080, ssl_insecure: bool = True):
        self.hook_bus = hook_bus
        self.db_engine = db_engine
        self._with_termlog = with_termlog
        self._upstream = upstream

        self._host = host
        self._port = port
        self._ssl_insecure = ssl_insecure
        self._master: Optional[DumpMaster] = None
        self._task: Optional[asyncio.Task] = None
        self._extra_addons: list[object] = []
        self._capture_enabled = False

    @property
    def capture_enabled(self) -> bool:
        return self._capture_enabled

    def set_capture_enabled(self, value: bool) -> None:
        self._capture_enabled = value
        logger.info(f"Proxy capture {'enabled' if value else 'disabled'}")

    async def register_addon(self, addon: object) -> None:
        self._extra_addons.append(addon)
        if self._master is not None:
            self._master.addons.add(addon)

    async def start(self) -> None:
        """Start the proxy server."""
        if self._master is not None or self._task is not None:
            raise RuntimeError("ProxyEngine is already running")
        
        # Configure options
        opts = Options(
            listen_host=self._host,
            listen_port=self._port,
            ssl_insecure=self._ssl_insecure,
            mode=[f"upstream:{self._upstream}"] if self._upstream else ["regular"],
        )

        # Initialize master (this registers default addons including TlsConfig)
        self._master = DumpMaster(opts, with_termlog=self._with_termlog, with_dumper=False)

        # Trigger TlsConfig certstore init AFTER master is created so TlsConfig
        # is subscribed to option changes. confdir default is "~/.mitmproxy" so
        # we use the expanded path to ensure it's treated as changed.
        import os
        opts.update(confdir=os.path.expanduser("~/.mitmproxy"))

        from pwnproxy.services.proxy.addons.hook_relay import HookRelayAddon
        from pwnproxy.services.proxy.addons.storage import StorageAddon

        # Register addons
        self._master.addons.add(HookRelayAddon(self.hook_bus))
        if self.db_engine:
            self._master.addons.add(StorageAddon(
                self.db_engine,
                hook_bus=self.hook_bus,
            ))
        for addon in self._extra_addons:
            self._master.addons.add(addon)

        # Start master in a task
        logger.info(f"Starting ProxyEngine on {self._host}:{self._port}")
        self._task = asyncio.create_task(self._run_master())

    async def _run_master(self) -> None:
        try:
            await self._master.run()
        except SystemExit:
            pass

    def stop(self) -> None:
        """Stop the proxy server gracefully (sync wrapper)."""
        if self._master is None:
            return

        logger.info("Stopping ProxyEngine")
        self._master.shutdown()
        self._master = None
        self._task = None

    async def astop(self) -> None:
        """Stop the proxy server and wait for it to fully shut down."""
        if self._master is None and self._task is None:
            return

        if self._master is not None:
            logger.info("Stopping ProxyEngine")
            self._master.shutdown()
            self._master = None

        if self._task is not None:
            task = self._task
            self._task = None
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    def configure(self, host: str = None, port: int = None, ssl_insecure: bool = None, upstream: Optional[str] = None, db_engine = None, capture_enabled: bool = None) -> None:
        """Update proxy configuration. Requires a restart if the proxy is already running."""
        if host is not None:
            self._host = host
        if port is not None:
            self._port = port
        if ssl_insecure is not None:
            self._ssl_insecure = ssl_insecure
        if upstream is not None: # Note: upstream could be "" to clear it, so we might need a better check if we want to clear it, but let's assume it's set properly.
            self._upstream = upstream if upstream else None
        if db_engine is not None:
            self.db_engine = db_engine
        if capture_enabled is not None:
            self._capture_enabled = capture_enabled

