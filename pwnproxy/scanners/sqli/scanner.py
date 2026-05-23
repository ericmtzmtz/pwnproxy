import asyncio
import logging
import time
from typing import Callable, Optional

from pwnproxy.core.hooks import HookBus
from pwnproxy.core.models import Flow
from pwnproxy.scanners.sqli.detector import ErrorBasedDetector, TimeBasedDetector
from pwnproxy.scanners.common.params import InjectionPoint, extract as extract_params
from pwnproxy.scanners.sqli.payloads import get_error_payloads
from pwnproxy.scanners.sqli.replayer import RequestReplayer
from pwnproxy.scanners.sqli.storage import FindingStorage

logger = logging.getLogger(__name__)


class SQLiScanner:
    def __init__(
        self,
        hook_bus: HookBus,
        on_finding: Optional[Callable] = None,
        storage: Optional[FindingStorage] = None,
    ):
        self._hook_bus = hook_bus
        self._on_finding = on_finding
        self._storage = storage or FindingStorage()
        self._replayer = RequestReplayer()

        self._queue: Optional[asyncio.Queue] = None
        self._consumer_task: Optional[asyncio.Task] = None
        self._scan_tasks: set[asyncio.Task] = set()
        self._running = False

        self._global_sem = asyncio.Semaphore(5)
        self._host_sems: dict[str, asyncio.Semaphore] = {}
        self._host_last_req: dict[str, float] = {}
        self._host_lock = asyncio.Lock()

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
        for t in list(self._scan_tasks):
            t.cancel()
        if self._scan_tasks:
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
                    key = (point.method, point.host + point.path, point.name, point.location)
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
        async with self._global_sem:
            await self._rate_limit_host(point.host)

            baseline_start = time.monotonic()
            clean_resp = await self._replayer.send_clean(point, timeout=10.0)
            baseline_ms = (time.monotonic() - baseline_start) * 1000

            err_detector = ErrorBasedDetector()
            for payload in get_error_payloads():
                self.params_scanned += 1
                resp = await self._replayer.replay(point, payload.value, timeout=3.0)
                if resp is None:
                    continue
                finding = err_detector.check(resp)
                if finding is not None:
                    finding.method = point.method
                    finding.url = point.url
                    finding.param_name = point.name
                    finding.param_location = point.location
                    finding.payload = payload.value
                    await self._save_finding(finding)
                    return

            time_detector = TimeBasedDetector(self._replayer)
            if clean_resp is not None:
                self.params_scanned += 1
                finding = await time_detector.check(point, baseline_ms)
                if finding is not None:
                    await self._save_finding(finding)

    async def _rate_limit_host(self, host: str) -> None:
        async with self._host_lock:
            if host not in self._host_sems:
                self._host_sems[host] = asyncio.Semaphore(2)
        async with self._host_sems[host]:
            async with self._host_lock:
                last = self._host_last_req.get(host, 0.0)
                now = time.monotonic()
                wait = 0.1 - (now - last)
                if wait > 0:
                    await asyncio.sleep(wait)
                self._host_last_req[host] = time.monotonic()

    async def _save_finding(self, finding) -> None:
        self.finding_count += 1
        await self._storage.save_finding(finding)
        if self._on_finding:
            self._on_finding(finding)
