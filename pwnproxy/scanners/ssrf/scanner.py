import asyncio
import logging
from typing import Callable, Optional

from pwnproxy.core.hooks import HookBus
from pwnproxy.core.models import Flow
from pwnproxy.scanners.common.rate_limiter import RateLimiter
from pwnproxy.scanners.ssrf.extractor import SsrfExtractor
from pwnproxy.scanners.ssrf.listener import CallbackServer
from pwnproxy.scanners.ssrf.models import SsrfFinding
from pwnproxy.scanners.ssrf.payloads import PayloadGenerator
from pwnproxy.scanners.ssrf.replayer import SsrfReplayer
from pwnproxy.scanners.ssrf.storage import SsrfFindingStorage

logger = logging.getLogger(__name__)


class SSRFScanner:
    def __init__(
        self,
        hook_bus: HookBus,
        on_finding: Optional[Callable] = None,
        storage: Optional[SsrfFindingStorage] = None,
    ):
        self._hook_bus = hook_bus
        self._on_finding = on_finding
        self._storage = storage or SsrfFindingStorage()
        self._replayer = SsrfReplayer()
        self._extractor = SsrfExtractor()
        self._payload_gen = PayloadGenerator()
        self._rate_limiter = RateLimiter()
        self._callback_server = CallbackServer()

        self._queue: Optional[asyncio.Queue] = None
        self._consumer_task: Optional[asyncio.Task] = None
        self._scan_tasks: set[asyncio.Task] = set()
        self._pending_canaries: dict[str, SsrfFinding] = {}
        self._running = False
        self._callback_check_task: Optional[asyncio.Task] = None

        self.flows_processed = 0
        self.params_scanned = 0
        self.finding_count = 0

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def callback_server(self) -> CallbackServer:
        return self._callback_server

    def configure(
        self,
        callback_host: Optional[str] = None,
        listen_port: Optional[int] = None,
    ) -> None:
        if callback_host is not None:
            self._payload_gen.callback_host = callback_host
            self._callback_server = CallbackServer(host=callback_host, port=self._payload_gen.callback_port)
        if listen_port is not None:
            self._payload_gen.callback_port = listen_port
            self._callback_server = CallbackServer(host=self._payload_gen.callback_host, port=listen_port)

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        await self._storage.create_tables()
        await self._callback_server.start()
        self._queue = self._hook_bus.register("done")
        self._consumer_task = asyncio.create_task(self._consume_loop())
        self._callback_check_task = asyncio.create_task(self._check_callbacks())

    async def stop(self) -> None:
        self._running = False
        if self._consumer_task:
            self._consumer_task.cancel()
            self._consumer_task = None
        if self._callback_check_task:
            self._callback_check_task.cancel()
            self._callback_check_task = None
        if self._scan_tasks:
            for t in self._scan_tasks:
                t.cancel()
            await asyncio.gather(*self._scan_tasks, return_exceptions=True)
            self._scan_tasks.clear()
        await self._callback_server.stop()
        await self._replayer.close()
        self._pending_canaries.clear()

    def status(self) -> dict:
        return {
            "running": self._running,
            "flows_processed": self.flows_processed,
            "params_scanned": self.params_scanned,
            "findings": self.finding_count,
            "pending_tasks": len(self._scan_tasks),
            "listener_running": self._callback_server.is_running,
            "listener_host": self._callback_server.host,
            "listener_port": self._callback_server.port,
        }

    async def _consume_loop(self) -> None:
        while self._running:
            try:
                flow: Flow = await self._queue.get()
                self.flows_processed += 1

                redirect_params = self._extractor.extract_redirect_params(flow)
                url_params = self._extractor.extract_url_params(flow)
                seen = set()
                for point in url_params + redirect_params:
                    key = (point.host + point.path, point.name, point.location)
                    if key in seen:
                        continue
                    seen.add(key)
                    task = asyncio.create_task(self._scan_point(point))
                    self._scan_tasks.add(task)
                    task.add_done_callback(self._scan_tasks.discard)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"SSRF consumer error: {e}", exc_info=True)

    async def _scan_point(self, point) -> None:
        await self._rate_limiter.acquire(point.host)
        try:
            await self._rate_limiter.rate_limit(point.host)
            self.params_scanned += 1
            payload = self._payload_gen.generate()
            finding = SsrfFinding(
                url=point.url,
                param_name=point.name,
                param_location=point.location,
                canary=payload.value.split("/")[-1],
                payload=payload.value,
                severity="low",
            )
            self._pending_canaries[finding.canary] = finding
            await self._replayer.inject(point, payload.value)
        finally:
            await self._rate_limiter.release(point.host)

    async def _check_callbacks(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(0.5)
                for canary, finding in list(self._pending_canaries.items()):
                    hit = self._callback_server.pop_hit(canary)
                    if hit is not None:
                        finding.severity = "critical"
                        finding.callback_ip = hit.get("remote_ip")
                        finding.callback_headers = str(hit.get("headers", {}))
                        await self._save_finding(finding)
                        del self._pending_canaries[canary]
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Callback check error: {e}", exc_info=True)

    async def _save_finding(self, finding) -> None:
        self.finding_count += 1
        await self._storage.save_finding(finding)
        if self._on_finding:
            self._on_finding(finding)
