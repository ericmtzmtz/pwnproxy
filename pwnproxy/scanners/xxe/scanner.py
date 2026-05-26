import asyncio
import logging
import time
from typing import Callable, Optional

from pwnproxy.core.hooks import HookBus
from pwnproxy.core.models import Flow
from pwnproxy.scanners.common.params import extract as extract_params
from pwnproxy.scanners.common.rate_limiter import RateLimiter
from pwnproxy.scanners.xxe.detector import XxeDetector
from pwnproxy.scanners.xxe.mutator import XML_CONTENT_TYPES
from pwnproxy.scanners.xxe.replayer import XxeReplayer
from pwnproxy.scanners.xxe.storage import XxeFindingStorage

logger = logging.getLogger(__name__)

JSON_CONTENT_TYPES = {"application/json"}
SCANNABLE_CONTENT_TYPES = XML_CONTENT_TYPES | JSON_CONTENT_TYPES


class XXEScanner:
    def __init__(
        self,
        hook_bus: HookBus,
        on_finding: Optional[Callable] = None,
        storage: Optional[XxeFindingStorage] = None,
    ):
        self._hook_bus = hook_bus
        self._on_finding = on_finding
        self._storage = storage or XxeFindingStorage()
        self._replayer = XxeReplayer()
        self._detector = XxeDetector(self._replayer)
        self._rate_limiter = RateLimiter()
        self._oob_domain: Optional[str] = None

        self._queue: Optional[asyncio.Queue] = None
        self._consumer_task: Optional[asyncio.Task] = None
        self._scan_tasks: set[asyncio.Task] = set()
        self._running = False
        self._paused = asyncio.Event()
        self._paused.set()

        self._dedup: set[tuple] = set()
        self._on_flow_complete: Optional[Callable] = None
        self._flow_counter: dict[str, int] = {}
        self._flow_start: dict[str, float] = {}
        self._flow_url: dict[str, str] = {}
        self._flow_method: dict[str, str] = {}
        self._flow_findings_before: dict[str, int] = {}

        self.flows_processed = 0
        self.params_scanned = 0
        self.finding_count = 0

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_paused(self) -> bool:
        return not self._paused.is_set()

    @property
    def oob_domain(self) -> Optional[str]:
        return self._oob_domain

    def configure(self, oob_domain: Optional[str] = None) -> None:
        self._oob_domain = oob_domain

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._paused.set()
        await self._storage.create_tables()
        self._queue = self._hook_bus.register("done")
        self._consumer_task = asyncio.create_task(self._consume_loop())

    async def stop(self) -> None:
        self._running = False
        self._paused.set()
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

    def pause(self) -> None:
        self._paused.clear()

    def resume(self) -> None:
        self._paused.set()

    def status(self) -> dict:
        return {
            "running": self._running,
            "paused": self.is_paused,
            "flows_processed": self.flows_processed,
            "params_scanned": self.params_scanned,
            "findings": self.finding_count,
            "pending_tasks": len(self._scan_tasks),
            "oob_domain": self._oob_domain,
        }

    async def _consume_loop(self) -> None:
        while self._running:
            try:
                flow: Flow = await self._queue.get()
                await self._paused.wait()
                self.flows_processed += 1
                fid = flow.id
                self._flow_counter[fid] = 0
                self._flow_start[fid] = time.monotonic()
                self._flow_url[fid] = flow.url
                self._flow_method[fid] = flow.method
                self._flow_findings_before[fid] = self.finding_count

                if not self._is_scannable(flow):
                    self._finalize_flow(fid)
                    continue
                points = extract_params(flow)
                for point in points:
                    key = (point.host + point.path, point.name, point.location)
                    if key in self._dedup:
                        continue
                    self._dedup.add(key)
                    self._flow_counter[fid] += 1
                    task = asyncio.create_task(self._scan_point(point, flow))
                    self._scan_tasks.add(task)
                    task.add_done_callback(lambda t, fid=fid: self._on_scan_point_done(t, fid))

                if self._flow_counter[fid] == 0:
                    self._finalize_flow(fid)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"XXE consumer error: {e}", exc_info=True)

    def _on_scan_point_done(self, task: asyncio.Task, flow_id: str) -> None:
        self._scan_tasks.discard(task)
        if flow_id not in self._flow_counter:
            return
        self._flow_counter[flow_id] -= 1
        if self._flow_counter[flow_id] <= 0:
            self._finalize_flow(flow_id)

    def _finalize_flow(self, flow_id: str) -> None:
        elapsed = (time.monotonic() - self._flow_start.get(flow_id, 0)) * 1000
        url = self._flow_url.get(flow_id, "")
        method = self._flow_method.get(flow_id, "")
        before = self._flow_findings_before.get(flow_id, self.finding_count)
        finding_count = self.finding_count - before
        if self._on_flow_complete:
            asyncio.create_task(self._on_flow_complete(flow_id, url, method, "xxe", elapsed, finding_count))
        self._flow_counter.pop(flow_id, None)
        self._flow_start.pop(flow_id, None)
        self._flow_url.pop(flow_id, None)
        self._flow_method.pop(flow_id, None)
        self._flow_findings_before.pop(flow_id, None)

    def _is_scannable(self, flow: Flow) -> bool:
        ct = flow.request_headers.get("content-type", "").lower()
        for scannable in SCANNABLE_CONTENT_TYPES:
            if scannable in ct:
                return True
        return False

    async def _scan_point(self, point, flow: Flow) -> None:
        await self._rate_limiter.acquire(point.host)
        try:
            await self._rate_limiter.rate_limit(point.host)
            self.params_scanned += 1
            finding = await self._detector.check_error_based(point)
            if finding is None:
                finding = await self._detector.check_xinclude(point)
            if finding is None and self._is_json_flow(flow):
                finding = await self._detector.check_json_mutated(point)
            if finding is None and self._oob_domain:
                finding = await self._detector.check_oob(point, self._oob_domain)
            if finding:
                await self._save_finding(finding)
        finally:
            await self._rate_limiter.release(point.host)

    def _is_json_flow(self, flow: Flow) -> bool:
        ct = flow.request_headers.get("content-type", "").lower()
        return "application/json" in ct

    async def _save_finding(self, finding) -> None:
        self.finding_count += 1
        await self._storage.save_finding(finding)
        if self._on_finding:
            self._on_finding(finding)
