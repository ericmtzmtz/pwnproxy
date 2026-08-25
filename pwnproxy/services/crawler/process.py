"""Manager for the passive crawler worker subprocess.

Mirrors ``ProxyProcess``: spawns ``crawler_worker`` as a subprocess and
talks to it over TcpBridge JSON lines.

Direction of the two bridges:
- feed (main → crawler): a ``TcpBridgeServer`` owned by this manager; the
  worker connects as a client (port passed via ``--feed-port``) and
  receives ``crawler.feed`` events.
- results (crawler → main): the worker owns a ``TcpBridgeServer`` whose
  port it prints on stdout (``EVENT_PORT=``); this manager connects a
  ``TcpBridgeClient`` and forwards ``crawler.url`` events to the callback.
"""

import asyncio
import logging
import sys
from typing import Any, Callable, Optional

from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeClient, TcpBridgeServer

logger = logging.getLogger(__name__)


class CrawlerProcess:
    """Manages the passive crawler worker subprocess."""

    def __init__(self):
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._event_port: int = 0
        self._results_bridge: Optional[TcpBridgeClient] = None
        self._stderr_reader: Optional[asyncio.Task] = None
        self._feed_server = TcpBridgeServer()
        self._feed_started = False
        self._on_event: Optional[Callable[[str, Any], None]] = None
        self._last_params: Optional[tuple[str, Optional[str]]] = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    def set_event_callback(self, callback: Callable[[str, Any], None]) -> None:
        """Register a callback receiving events from the worker (e.g. ``crawler.url``)."""
        self._on_event = callback

    def status(self) -> dict:
        return {
            "running": self.running,
            "pid": self._proc.pid if self._proc else None,
            "event_port": self._event_port if self.running else 0,
            "feed_port": self._feed_server.port if self._feed_started else 0,
        }

    async def start(self, db_path: str, scope_json: Optional[str] = None) -> None:
        """Start the crawler worker (idempotent for identical parameters)."""
        params = (db_path, scope_json)
        if self.running and self._last_params == params:
            return
        await self.stop()

        if not self._feed_started:
            await self._feed_server.start()
            self._feed_started = True

        args = [
            sys.executable, "-m", "pwnproxy.services.crawler.crawler_worker",
            "--db-path", db_path,
            "--feed-port", str(self._feed_server.port),
        ]
        if scope_json:
            args.extend(["--scope-json", scope_json])

        logger.info("Starting crawler subprocess (db=%s)", db_path)
        self._proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        assert self._proc.stdout is not None
        line = await asyncio.wait_for(self._proc.stdout.readline(), timeout=15)
        raw = line.decode().strip()
        if not raw.startswith("EVENT_PORT="):
            self._proc.terminate()
            raise RuntimeError(f"Unexpected crawler worker output: {raw}")

        self._event_port = int(raw.split("=")[1])
        logger.info("Crawler event port: %s", self._event_port)

        self._results_bridge = TcpBridgeClient(
            host="127.0.0.1",
            port=self._event_port,
            on_event=self._on_event,
        )
        await self._results_bridge.start()
        self._stderr_reader = asyncio.create_task(self._read_stderr())
        self._last_params = params

    async def _read_stderr(self) -> None:
        try:
            while self._proc and self._proc.stderr:
                try:
                    line = await asyncio.wait_for(self._proc.stderr.readline(), timeout=0.5)
                    if line:
                        logger.warning("[crawler stderr] %s", line.decode().strip())
                except asyncio.TimeoutError:
                    continue
        except Exception as e:
            logger.debug("Crawler stderr reader stopped: %s", e)

    def relay_flow(self, flow_dict: dict) -> bool:
        """Forward a proxy flow dict to the worker. Best-effort: drops silently
        when the crawler is not running or no client is connected."""
        if not self.running:
            return False
        asyncio.create_task(self._feed_server.publish("crawler.feed", flow_dict))
        return True

    async def stop(self) -> None:
        if self._results_bridge:
            await self._results_bridge.stop()
            self._results_bridge = None
        if self._stderr_reader:
            self._stderr_reader.cancel()
            try:
                await self._stderr_reader
            except (asyncio.CancelledError, Exception):
                pass
            self._stderr_reader = None

        if self._proc and self._proc.returncode is None:
            logger.info("Stopping crawler subprocess")
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                logger.warning("Crawler did not exit in time, killing")
                self._proc.kill()
                await self._proc.wait()

        if self._feed_started:
            await self._feed_server.stop()
            self._feed_started = False

        self._proc = None
        self._event_port = 0
        self._last_params = None

    async def restart(self, db_path: str, scope_json: Optional[str] = None) -> None:
        await self.start(db_path=db_path, scope_json=scope_json)
