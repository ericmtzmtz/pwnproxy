"""Job lifecycle commands over the JobState machine.

``JobLifecycle`` is the single public entry point for job state changes.
The crawler worker is the owner of job lifecycle; the REST API uses the
same commands only as executor of last resort when the worker is dead.

Storage-level primitives (``transition_status`` / ``update_status``) stay
in ``pwnproxy.services.crawler.storage``; business callers should use this
module instead of reaching for them directly.
"""

from __future__ import annotations

import logging
from typing import Optional

from pwnproxy.services.crawler.storage import JobStorage

logger = logging.getLogger(__name__)


class JobLifecycle:
    """High-level job state commands with the machine + idempotency baked in.

    Every command persists intermediate states (CREATED→STARTING→RUNNING,
    RUNNING→STOPPING→CANCELLED) through atomic compare-and-set steps, and
    returns the resulting status string.
    """

    def __init__(self, storage: JobStorage):
        self._storage = storage

    async def start(self, job_id: int) -> str:
        """Mark the job as running (CREATED → STARTING → RUNNING persisted)."""
        return await self._storage.transition_status(job_id, "running")

    async def request_stop(self, job_id: int) -> str:
        """Stop request (RUNNING → STOPPING → CANCELLED persisted)."""
        return await self._storage.transition_status(job_id, "cancelled")

    async def complete(self, job_id: int) -> str:
        return await self._storage.transition_status(job_id, "completed")

    async def fail(self, job_id: int, error: str) -> str:
        return await self._storage.transition_status(job_id, "failed", error=error)

    async def update_stats(self, job_id: int, stats: dict) -> None:
        await self._storage.update_stats(job_id, stats)

    async def recover_stale(self) -> int:
        """Crash recovery: RUNNING jobs stuck after a restart → FAILED."""
        return await self._storage.mark_stale_running_failed()

    # ── Fire-and-forget safe variants ──────────────────────────────────

    async def safe_request_stop(self, job_id: int) -> None:
        """request_stop that never raises (used from sync stop handlers)."""
        try:
            await self.request_stop(job_id)
        except Exception:
            logger.exception("Job %s: request_stop failed", job_id)

    async def safe_fail(self, job_id: int, error: str) -> None:
        """fail that never raises (used from task exception handlers, where
        the job may already be terminal — that is not an error here)."""
        try:
            await self.fail(job_id, error)
        except Exception:
            logger.warning("Job %s: terminal transition to failed was rejected", job_id)

    async def safe_cancel(self, job_id: int) -> None:
        """CancelledError path: same as request_stop but tolerant."""
        await self.safe_request_stop(job_id)
