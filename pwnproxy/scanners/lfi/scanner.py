import asyncio
import logging
from typing import Callable, Optional

from pwnproxy.core.hooks import HookBus
from pwnproxy.core.models import Flow
from pwnproxy.scanners.common.params import InjectionPoint, extract as extract_params
from pwnproxy.scanners.common.rate_limiter import RateLimiter
from pwnproxy.scanners.lfi.detector import LfiDetector
from pwnproxy.scanners.lfi.replayer import LfiReplayer
from pwnproxy.scanners.lfi.storage import LfiFindingStorage

logger = logging.getLogger(__name__)


class LFIScanner:
    def __init__(
        self,
        hook_bus: HookBus,
        on_finding: Optional[Callable] = None,
        storage: Optional[LfiFindingStorage] = None,
    ):
        self._hook_bus = hook_bus
        self._on_finding = on_finding
        self._storage = storage or LfiFindingStorage()
        self._replayer = LfiReplayer()
        self._detector = LfiDetector(self._replayer)
        self._rate_limiter = RateLimiter()

        self._queue: Optional[asyncio.Queue] = None
        self._consumer_task: Optional[asyncio.Task] = None
        self._scan_tasks: set[asyncio.Task] = set()
        self._running = False

        self._dedup: set[tuple] = set()

        self.flows_processed = 0
        self.params_scanned = 0
        self.finding_count = 0

    @property
    def is_running(self) -> bool:
        return self._running

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        await self._storage.create_tables()
        self._queue = self._hook_bus.register("done")
        self._consumer_task = asyncio.create_task(self._consume_loop())

    async def stop(self) -> None:
        self._running = False
        if self._consumer_task:
            self._consumer_task.cancel()
            self._consumer_task = None
        if self._scan_tasks:
            for t in self._scan_tasks:
                t.cancel()
            await asyncio.gather(*self._scan_tasks, return_exceptions=True)
            self._scan_tasks.clear()
        await self._replayer.close()
        self._dedup.clear()

    def status(self) -> dict:
        return {
            "running": self._running,
            "flows_processed": self.flows_processed,
            "params_scanned": self.params_scanned,
            "findings": self.finding_count,
            "pending_tasks": len(self._scan_tasks),
        }

    async def _consume_loop(self) -> None:
        while self._running:
            try:
                flow: Flow = await self._queue.get()
                self.flows_processed += 1
                points = extract_params(flow)
                for point in points:
                    key = (point.host + point.path, point.name, point.location)
                    if key in self._dedup:
                        continue
                    self._dedup.add(key)
                    task = asyncio.create_task(self._scan_point(point))
                    self._scan_tasks.add(task)
                    task.add_done_callback(self._scan_tasks.discard)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Consumer error: {e}", exc_info=True)

    async def _scan_point(self, point: InjectionPoint) -> None:
        await self._rate_limiter.acquire(point.host)
        try:
            await self._rate_limiter.rate_limit(point.host)
            self.params_scanned += 1
            finding = await self._detector.check(point)
            if finding:
                await self._save_finding(finding)
        finally:
            await self._rate_limiter.release(point.host)

    async def _save_finding(self, finding) -> None:
        self.finding_count += 1
        await self._storage.save_finding(finding)
        if self._on_finding:
            self._on_finding(finding)
