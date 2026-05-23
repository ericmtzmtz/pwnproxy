import asyncio
import logging
from typing import Optional

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from pwnproxy.core.hooks import HookBus

logger = logging.getLogger(__name__)


class ProxyEngine:
    """Embedded mitmproxy engine running in an asyncio task."""

    def __init__(self, hook_bus: HookBus, db_engine=None):
        self.hook_bus = hook_bus
        self.db_engine = db_engine
        self._master: Optional[DumpMaster] = None
        self._task: Optional[asyncio.Task] = None
        self._extra_addons: list[object] = []

    async def register_addon(self, addon: object) -> None:
        self._extra_addons.append(addon)

    async def start(self, host: str = "127.0.0.1", port: int = 8080) -> None:
        """Start the proxy server."""
        if self._master is not None or self._task is not None:
            raise RuntimeError("ProxyEngine is already running")

        # Configure options
        opts = Options(
            listen_host=host,
            listen_port=port,
            ssl_insecure=True,  # Allow self-signed / insecure TLS by default
        )

        # Initialize master
        self._master = DumpMaster(opts, with_termlog=True, with_dumper=False)
        
        # We will import addons lazily or they should be injected
        # To avoid circular imports, let's load them here
        from pwnproxy.core.addons.hook_relay import HookRelayAddon
        from pwnproxy.core.addons.storage import StorageAddon

        # Register addons
        self._master.addons.add(HookRelayAddon(self.hook_bus))
        if self.db_engine:
            self._master.addons.add(StorageAddon(self.db_engine))
        for addon in self._extra_addons:
            self._master.addons.add(addon)

        # Start master in a task
        logger.info(f"Starting ProxyEngine on {host}:{port}")
        self._task = asyncio.create_task(self._run_master())

    async def _run_master(self) -> None:
        try:
            await self._master.run()
        except SystemExit:
            pass

    def stop(self) -> None:
        """Stop the proxy server gracefully."""
        if self._master is None:
            return  # No-op if not running

        logger.info("Stopping ProxyEngine")
        self._master.shutdown()
        self._master = None
        
        if self._task is not None:
            # We don't necessarily cancel it instantly unless we want a hard kill
            # shutdown() asks it to stop gracefully.
            self._task = None
