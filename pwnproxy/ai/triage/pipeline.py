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
        # Per-scan LLM call budget (scan_id -> count). Findings without a
        # scan_id share the "default" bucket.
        self._llm_calls: dict[str, int] = {}

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
            confidence = str(row.get("confidence") or "").lower()

            # Gate A: hard gate — skip_llm_if_confidence levels NEVER reach the
            # judge, regardless of heuristic score. Heuristic alone decides.
            llm_eligible = (
                self.judge is not None
                and confidence not in self.config.skip_llm_if_confidence
            )

            if result.score >= self.config.auto_true:
                await self._apply(finding_id, "true_positive", "heuristic", result)
            elif result.score <= self.config.auto_false:
                await self._apply(finding_id, "false_positive", "heuristic", result)
            else:
                # Gray zone (0.3 < score < 0.7): provisional uncertain.
                await self._apply(finding_id, "uncertain", "heuristic", result)
                if llm_eligible and self._should_llm(confidence):
                    self._enqueue(finding_id, row, result.features, confidence)
        except Exception:
            logger.exception("triage pipeline failed for finding %s", row.get("id"))

    async def handle_human_feedback(self, finding_id: int, verdict: str, reason: str | None = None) -> Optional[dict]:
        """Persist a human verdict; used by the REST feedback endpoint."""
        return await self._set(finding_id, verdict, "human", None, reason or "human_review")

    def _should_llm(self, confidence: str) -> bool:
        """Decide whether a gray-zone finding may reach the LLM judge."""
        mode = self.config.mode
        if mode == "off" or mode == "heuristic":
            return False
        if mode == "legacy_gray":
            return True
        if mode == "enrich":
            # Enrich only already-strong findings; never arbitrate the gray zone.
            return confidence in ("confirmed", "inferred")
        return False

    def _scan_key(self, row: dict) -> str:
        extra = row.get("extra") or {}
        if isinstance(extra, dict) and extra.get("scan_id"):
            return str(extra["scan_id"])
        return "default"

    def _budget_available(self, scan_key: str) -> bool:
        if self.config.max_llm_per_scan <= 0:
            return False
        return self._llm_calls.get(scan_key, 0) < self.config.max_llm_per_scan

    # -- internals -------------------------------------------------------------

    def _enqueue(self, finding_id: int, row: dict, features: dict, confidence: str) -> None:
        scan_key = self._scan_key(row)
        if not self._budget_available(scan_key):
            logger.info("triage: LLM budget exhausted for scan %s; finding %s stays uncertain",
                        scan_key, finding_id)
            return
        # Reserve the LLM slot up-front so the budget is honored even when
        # many gray-zone findings arrive before the worker drains the queue.
        self._llm_calls[scan_key] = self._llm_calls.get(scan_key, 0) + 1
        snapshot = {k: row.get(k) for k in (
            "id", "scanner", "url", "method", "param_name", "param_location",
            "technique", "severity", "confidence", "payload", "evidence",
        )}
        try:
            self.queue.put_nowait((finding_id, snapshot, features, scan_key))
        except asyncio.QueueFull:
            logger.warning("triage queue full; finding %s stays uncertain", finding_id)
            # release the reserved slot
            self._llm_calls[scan_key] = max(0, self._llm_calls.get(scan_key, 0) - 1)

    async def _worker(self) -> None:
        while True:
            finding_id, snapshot, features, scan_key = await self.queue.get()
            try:
                verdict = await self.judge.evaluate(snapshot, features)
                verdict_str, reason = verdict.verdict, verdict.reason
                if self.config.mode == "enrich" and self._enrich_blocks_fp(snapshot, verdict):
                    # Enrichment must not casually downgrade a finding the
                    # scanner already marked confirmed/inferred to a false
                    # positive unless the judge is highly confident.
                    verdict_str = "uncertain"
                    reason = f"enrich fp blocked (judge confidence {verdict.confidence:.2f})"
                await self._set(
                    finding_id, verdict_str, "llm",
                    verdict.confidence, reason,
                    features=features,
                )
            except Exception as e:
                # Judge unavailable: keep uncertain/heuristic, no infinite retries.
                logger.warning("triage judge unavailable for finding %s: %s", finding_id, e)
            finally:
                self.queue.task_done()

    def _enrich_blocks_fp(self, snapshot: dict, verdict) -> bool:
        """True when enrich mode must NOT apply a judge false_positive verdict."""
        if verdict.verdict != "false_positive":
            return False
        confidence = str(snapshot.get("confidence") or "").lower()
        if confidence not in ("confirmed", "inferred"):
            return False
        return verdict.confidence < self.config.enrich_fp_threshold

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
