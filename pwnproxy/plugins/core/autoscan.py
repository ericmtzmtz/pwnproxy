"""Auto-scan batch tracker.

The proxy auto-scan path (each in-scope flow published to the "flow" channel)
runs per-plugin consumers that do NOT create TaskStore entries, so there is no
"scan" unit in the UI. This tracker groups flows into time windows and emits
``autoscan.started`` / ``autoscan.completed`` so the UI knows when a batch of
auto-scans began and finished.

Flow dedup: the same flow is consumed by every scanner plugin, so the tracker
dedups by flow.id within the active window and counts findings once.
"""

import asyncio
import logging
import time
import uuid
from typing import Optional

logger = logging.getLogger(__name__)


class AutoScanBatch:
    """One window of auto-scanned flows."""

    def __init__(self, batch_id: str):
        self.batch_id = batch_id
        self.started_at = time.monotonic()
        self.last_activity = time.monotonic()
        self.flow_ids: set[str] = set()
        self.flow_count = 0
        self.finding_count = 0

    @property
    def age_s(self) -> float:
        return time.monotonic() - self.started_at


class AutoScanTracker:
    """Group auto-scanned flows into windows and publish lifecycle events."""

    WINDOW_S = 3.0          # idle time that closes a batch
    FLUSH_INTERVAL_S = 0.5  # background sweep frequency

    def __init__(self, hook_bus=None, window_s: float = WINDOW_S):
        self._hook_bus = hook_bus
        self._window_s = window_s
        self._active: Optional[AutoScanBatch] = None
        self._last: Optional[AutoScanBatch] = None
        self._flush_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._flush_task is None or self._flush_task.done():
            self._flush_task = asyncio.create_task(self._flush_loop())

    async def stop(self) -> None:
        if self._flush_task is not None:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except (asyncio.CancelledError, Exception):
                pass
            self._flush_task = None
        await self.close_active()

    # -- reporting (called by plugin loader) --------------------------------

    async def report_flow(self, flow) -> None:
        """Register one flow in the active window (dedup by flow.id)."""
        async with self._lock:
            now = time.monotonic()
            if self._active is None or (now - self._active.last_activity) > self._window_s:
                await self._close_current(now)
                self._active = AutoScanBatch(uuid.uuid4().hex[:12])
            fid = getattr(flow, "id", None)
            if fid is not None:
                if str(fid) not in self._active.flow_ids:
                    self._active.flow_ids.add(str(fid))
                    self._active.flow_count += 1
            self._active.last_activity = now
            # Emit started only after the first flow is in the batch.
            if self._active.flow_count == 1:
                await self._emit("autoscan.started", self._active)

    async def report_finding(self) -> None:
        """Increment the finding count of the active batch (if any)."""
        async with self._lock:
            if self._active is not None:
                self._active.finding_count += 1

    # -- status (for the /workers endpoint) ----------------------------------

    def status(self) -> dict:
        active = self._active
        return {
            "running": active is not None,
            "active": self._batch_dict(active) if active else None,
            "last": self._batch_dict(self._last) if self._last else None,
        }

    # -- internals -----------------------------------------------------------

    async def _roll(self, now: float) -> None:
        """Close the current batch (if any) and open a fresh one.

        Kept for callers that want to open a new window immediately; the flush
        loop uses ``_close_current`` instead so idle time does NOT keep the
        auto-scan "running" with an empty batch.
        """
        if self._active is not None and self._active.flow_count > 0:
            await self._emit("autoscan.completed", self._active)
            self._last = self._active
        self._active = AutoScanBatch(uuid.uuid4().hex[:12])
        await self._emit("autoscan.started", self._active)

    async def _close_current(self, now: float) -> None:
        """Close the current batch (if any) without opening a new one."""
        if self._active is not None and self._active.flow_count > 0:
            await self._emit("autoscan.completed", self._active)
            self._last = self._active
        self._active = None

    async def close_active(self) -> None:
        async with self._lock:
            await self._close_current(time.monotonic())
            self._active = None

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(self.FLUSH_INTERVAL_S)
            try:
                async with self._lock:
                    if self._active is not None:
                        now = time.monotonic()
                        if (now - self._active.last_activity) > self._window_s:
                            # Close the idle batch — do NOT open a new one, so
                            # running goes False until the next flow arrives.
                            await self._close_current(now)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.debug("autoscan flush loop error", exc_info=True)

    async def _emit(self, topic: str, batch: AutoScanBatch) -> None:
        if self._hook_bus is None:
            return
        try:
            self._hook_bus.publish(topic, self._batch_dict(batch))
        except Exception:
            logger.debug("could not publish %s", topic, exc_info=True)

    @staticmethod
    def _batch_dict(batch: AutoScanBatch) -> dict:
        return {
            "batch_id": batch.batch_id,
            "flows": batch.flow_count,
            "findings": batch.finding_count,
            "duration_ms": round(batch.age_s * 1000, 1),
        }
