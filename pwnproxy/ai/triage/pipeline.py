"""FP-triage pipeline: post-save hook -> heuristic -> gray zone -> LLM judge.

Wired as FindingStorage.on_saved at server startup so every persisted finding
(API scan path and plugin-loader path alike) gets triaged exactly once.
Failures never lose the finding: it simply stays with its last known triage state.
"""
import asyncio
import logging
from typing import Callable, Optional

from pwnproxy.ai.triage.config import TriageConfig, load_triage_config
from pwnproxy.ai.triage.heuristic import HeuristicResult, score_finding
from pwnproxy.ai.triage.judge import LLMJudge

logger = logging.getLogger(__name__)

StorageFactory = Callable[[], object]  # () -> FindingStorage (fresh per call: engine may swap)


class TriagePipeline:
    def __init__(
        self,
        storage_factory: StorageFactory,
        hook_bus=None,
        judge: Optional[LLMJudge] = None,
        config: Optional[TriageConfig] = None,
    ):
        self._storage_factory = storage_factory
        self.hook_bus = hook_bus
        self.judge = judge
        self.config = config or load_triage_config()
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=self.config.queue_maxsize)
        self._worker_task: Optional[asyncio.Task] = None

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        if self._worker_task is None or self._worker_task.done():
            self._worker_task = asyncio.create_task(self._worker())

    async def stop(self) -> None:
        if self._worker_task is not None:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None

    # -- entry point (FindingStorage.on_saved signature) ----------------------

    async def handle(self, row: dict) -> None:
        if not self.config.enabled:
            return
        try:
            result = score_finding(row, self.config)
            finding_id = row["id"]
            if result.score >= self.config.auto_true:
                await self._apply(finding_id, "true_positive", "heuristic", result)
            elif result.score <= self.config.auto_false:
                await self._apply(finding_id, "false_positive", "heuristic", result)
            else:
                # Gray zone: provisional uncertain while the judge takes a look.
                await self._apply(finding_id, "uncertain", "heuristic", result)
                if self.judge is not None:
                    self._enqueue(finding_id, row, result.features)
        except Exception:
            logger.exception("triage pipeline failed for finding %s", row.get("id"))

    async def handle_human_feedback(self, finding_id: int, verdict: str, reason: str | None = None) -> Optional[dict]:
        """Persist a human verdict; used by the REST feedback endpoint."""
        return await self._set(finding_id, verdict, "human", None, reason or "human_review")

    # -- internals -------------------------------------------------------------

    def _enqueue(self, finding_id: int, row: dict, features: dict) -> None:
        snapshot = {k: row.get(k) for k in (
            "id", "scanner", "url", "method", "param_name", "param_location",
            "technique", "severity", "confidence", "payload", "evidence",
        )}
        try:
            self.queue.put_nowait((finding_id, snapshot, features))
        except asyncio.QueueFull:
            logger.warning("triage queue full; finding %s stays uncertain", finding_id)

    async def _worker(self) -> None:
        while True:
            finding_id, snapshot, features = await self.queue.get()
            try:
                verdict = await self.judge.evaluate(snapshot, features)
                await self._set(
                    finding_id, verdict.verdict, "llm",
                    verdict.confidence, verdict.reason,
                    features=features,
                )
            except Exception as e:
                # Judge unavailable: keep uncertain/heuristic, no infinite retries.
                logger.warning("triage judge unavailable for finding %s: %s", finding_id, e)
            finally:
                self.queue.task_done()

    async def _apply(self, finding_id: int, verdict: str, method: str, result: HeuristicResult) -> None:
        reason = ";".join(result.reasons) or "default"
        await self._set(finding_id, verdict, method, result.score, reason, features=result.features)

    async def _set(self, finding_id, verdict, method, score, reason, features=None) -> Optional[dict]:
        storage = self._storage_factory()
        updated = await storage.set_triage(
            finding_id, verdict=verdict, method=method, score=score, reason=reason, features=features,
        )
        if updated is not None:
            self._publish({
                "finding_id": finding_id,
                "verdict": verdict,
                "method": method,
                "score": score,
                "reason": reason,
            })
        return updated

    def _publish(self, payload: dict) -> None:
        if self.hook_bus is None:
            return
        try:
            self.hook_bus.publish("triage.updated", payload)
        except Exception:
            logger.debug("could not publish triage.updated", exc_info=True)


def make_pipeline(storage_factory: StorageFactory, hook_bus=None, llm_client=None, config=None) -> TriagePipeline:
    """Convenience factory wiring an optional LLM judge from the unified client."""
    judge = LLMJudge(llm_client) if llm_client is not None else None
    return TriagePipeline(storage_factory, hook_bus=hook_bus, judge=judge, config=config)
