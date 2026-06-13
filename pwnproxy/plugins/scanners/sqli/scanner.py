import asyncio
import logging
import time
from typing import Callable, Optional

from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint, extract as extract_params
from pwnproxy.plugins.scanners.sqli.replayer import SQLiReplayer
from pwnproxy.plugins.scanners.sqli.storage import FindingStorage
from pwnproxy.plugins.scanners.sqli.models import ScanFinding
from pwnproxy.plugins.core.chain import DetectionChain, DetectionDepth
from pwnproxy.shared.scan.stages.sqli_stages import (
    ErrorBasedStage,
    BooleanBlindStage,
    TimeBlindStage,
    OOBStage,
)

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
        self._replayer = SQLiReplayer()

        self._queue: Optional[asyncio.Queue] = None
        self._consumer_task: Optional[asyncio.Task] = None
        self._scan_tasks: set[asyncio.Task] = set()
        self._running = False
        self._paused = asyncio.Event()
        self._paused.set()

        self._global_sem = asyncio.Semaphore(5)
        self._host_sems: dict[str, asyncio.Semaphore] = {}
        self._host_last_req: dict[str, float] = {}
        self._host_lock = asyncio.Lock()

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
        for t in list(self._scan_tasks):
            t.cancel()
        if self._scan_tasks:
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

                points = extract_params(flow)
                for point in points:
                    key = (point.method, point.host + point.path, point.name, point.location)
                    if key in self._dedup:
                        continue
                    self._dedup.add(key)
                    self._flow_counter[fid] += 1
                    task = asyncio.create_task(self._scan_point(point))
                    self._scan_tasks.add(task)
                    task.add_done_callback(lambda t, fid=fid: self._on_scan_point_done(t, fid))

                if self._flow_counter[fid] == 0:
                    self._finalize_flow(fid)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Consumer error: {e}", exc_info=True)

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
            asyncio.create_task(self._on_flow_complete(flow_id, url, method, "sqli", elapsed, finding_count))
        self._flow_counter.pop(flow_id, None)
        self._flow_start.pop(flow_id, None)
        self._flow_url.pop(flow_id, None)
        self._flow_method.pop(flow_id, None)
        self._flow_findings_before.pop(flow_id, None)

    async def _scan_point(self, point: InjectionPoint, depth: str = "fast", evasion_level: str = "none") -> None:
        async with self._global_sem:
            await self._rate_limit_host(point.host)

            stages = [
                ErrorBasedStage(self._replayer, evasion_level),
                BooleanBlindStage(self._replayer, evasion_level),
                TimeBlindStage(self._replayer, evasion_level),
                OOBStage(self._replayer, evasion_level),
            ]
            chain = DetectionChain(stages, DetectionDepth(depth))

            body_bytes = point.original_body.encode() if point.original_body else None
            flow = Flow(
                id=point.flow_id,
                method=point.method,
                url=point.url,
                request_headers=dict(point.original_headers),
                request_body=body_bytes,
            )

            async for finding in chain.run(flow, [point]):
                scan_finding = _finding_to_scan_finding(point, finding)
                await self._save_finding(scan_finding)

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
        finding_data = {k: v for k, v in finding.__dict__.items() if not k.startswith("_")}
        finding_data["scanner"] = "sqli"
        self._hook_bus.publish("finding", finding_data)


def _finding_to_scan_finding(point: InjectionPoint, finding: "Finding") -> ScanFinding:
    from pwnproxy.plugins.core.base import Finding as BaseFinding
    return ScanFinding(
        method=finding.method or point.method,
        url=finding.url or point.url,
        param_name=finding.param_name or point.name,
        param_location=finding.param_location or point.location,
        technique=finding.technique,
        dbms=finding.extra.get("dbms"),
        severity=finding.severity,
        confidence=finding.confidence,
        payload=finding.payload,
        evidence=finding.evidence,
        baseline_ms=finding.extra.get("baseline_ms"),
        response_ms=finding.extra.get("response_ms"),
    )
