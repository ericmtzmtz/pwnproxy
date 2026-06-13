import asyncio
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
        self._event_reader: Optional[asyncio.Task] = None
        self._ready = asyncio.Event()

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    async def start(self, config: ProxyConfig) -> None:
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

        self._event_reader = asyncio.create_task(self._read_events())

    async def _read_events(self) -> None:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self._event_port),
                timeout=5,
            )
            async with aiohttp.ClientSession() as session:
                while self.running:
                    await asyncio.sleep(0.1)
                    writer.write(b"\n")
                    await writer.drain()
        except (ConnectionRefusedError, asyncio.TimeoutError, Exception) as e:
            logger.warning(f"Event connection failed: {e}")

    async def stop(self) -> None:
        if self._event_reader:
            self._event_reader.cancel()
            self._event_reader = None

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

    async def restart(self, config: ProxyConfig) -> None:
        await self.stop()
        await self.start(config)
