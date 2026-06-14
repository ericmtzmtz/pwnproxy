
import asyncio
from typing import Optional, Callable, Any
from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeClient
import logging
import sys
from typing import Optional

from pwnproxy.services.session.manager import ProxyConfig

logger = logging.getLogger(__name__)


class ProxyProcess:
    """Manages the proxy worker subprocess."""

    def __init__(self):
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._event_port: int = 0
        self._bridge: Optional[TcpBridgeClient] = None
        self._stderr_reader: Optional[asyncio.Task] = None
        self._ready = asyncio.Event()
        self._on_event: Optional[Callable[[str, Any], None]] = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    def set_event_callback(self, callback: Callable[[str, Any], None]) -> None:
        """Register a callback to receive events from the worker.

        The callback receives the event name and the payload object.
        """
        self._on_event = callback

    async def start(self, config: ProxyConfig, db_path: Optional[str] = None, scope: Optional[list[str]] = None) -> None:
        """Start the proxy subprocess and event bridge.

        The caller can set an event callback via ``set_event_callback`` before
        calling ``start``. The ``TcpBridgeClient`` will forward any event payload
        received from the worker to that callback.
        """
        await self.stop()

        args = [
            sys.executable, "-m", "pwnproxy.services.proxy.proxy_worker",
            "--listen-host", config.host,
            "--listen-port", str(config.port),
        ]
        if config.ssl_insecure:
            args.append("--ssl-insecure")
        if config.upstream:
            args.extend(["--upstream", config.upstream])
        if db_path:
            args.extend(["--db-path", db_path])
        if scope:
            args.append("--scope-enabled")
            for p in scope:
                args.extend(["--scope-pattern", p])

        logger.info(f"Starting proxy subprocess on {config.host}:{config.port}")
        self._proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        line = await asyncio.wait_for(self._proc.stdout.readline(), timeout=5)
        raw = line.decode().strip()
        if not raw.startswith("EVENT_PORT="):
            self._proc.terminate()
            raise RuntimeError(f"Unexpected worker output: {raw}")

        self._event_port = int(raw.split("=")[1])
        logger.info(f"Worker event port: {self._event_port}")

        # Initialize TCP bridge client for event forwarding
        self._bridge = TcpBridgeClient(
            host="127.0.0.1",
            port=self._event_port,
            on_event=self._on_event,
        )
        await self._bridge.start()
        self._stderr_reader = asyncio.create_task(self._read_stderr())

    async def _read_stderr(self) -> None:
        try:
            while self._proc and self._proc.stderr:
                try:
                    line = await asyncio.wait_for(self._proc.stderr.readline(), timeout=0.5)
                    if line:
                        logger.warning(f"[worker stderr] {line.decode().strip()}")
                except asyncio.TimeoutError:
                    continue
        except Exception as e:
            logger.debug(f"Stderr reader stopped: {e}")


    async def stop(self) -> None:
        # Stop TCP bridge if active
        if self._bridge:
            await self._bridge.stop()
            self._bridge = None
        if self._stderr_reader:
            self._stderr_reader.cancel()
            self._stderr_reader = None

        if self._proc and self._proc.returncode is None:
            logger.info("Stopping proxy subprocess")
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                logger.warning("Proxy did not exit in time, killing")
                self._proc.kill()
                await self._proc.wait()

        self._proc = None
        self._event_port = 0

    async def restart(self, config: ProxyConfig, db_path: Optional[str] = None, scope: Optional[list[str]] = None) -> None:
        await self.stop()
        await self.start(config, db_path=db_path, scope=scope)
