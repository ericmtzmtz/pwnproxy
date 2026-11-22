"""Detection stage primitives.

``DetectionStage`` / ``StageResult`` / ``DetectionDepth`` live in ``shared`` so
the concrete stages under ``shared/scan/stages`` can subclass them without
importing the plugin package. ``plugins.core.chain`` re-exports them and keeps
the orchestration pieces (``DetectionChain``, ``BudgetChain``, ``chain_from_depth``).
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum

from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.finding import Finding
from pwnproxy.shared.scan.params import InjectionPoint


class DetectionDepth(str, Enum):
    """Detection depth controls which stages run."""
    FAST = "fast"           # Error-based only
    STANDARD = "standard"   # Error + boolean + time
    DEEP = "deep"           # All stages including OOB


@dataclass
class StageResult:
    """Result from a detection stage execution."""
    findings: list[Finding] = field(default_factory=list)
    confirmed_points: set[tuple] = field(default_factory=set)


class DetectionStage(ABC):
    """Base class for detection stages.

    Each stage implements a specific detection technique and returns
    findings for confirmed injection points.
    """

    # Stage ordering - lower runs first
    order: int = 0

    # Minimum depth required to run this stage
    min_depth: DetectionDepth = DetectionDepth.FAST

    @abstractmethod
    async def execute(
        self,
        flow: Flow,
        injection_points: list[InjectionPoint],
    ) -> StageResult:
        """Execute this detection stage on the given injection points.

        Args:
            flow: The HTTP flow to test
            injection_points: Points to test (not yet confirmed)

        Returns:
            StageResult with findings and confirmed injection points
        """

    def should_run(self, depth: DetectionDepth) -> bool:
        """Check if this stage should run at the given depth."""
        depth_order = {
            DetectionDepth.FAST: 0,
            DetectionDepth.STANDARD: 1,
            DetectionDepth.DEEP: 2,
        }
        return depth_order[depth] >= depth_order[self.min_depth]

    def set_deadline(self, deadline: float | None) -> None:
        """Receive the absolute intra-stage deadline (monotonic seconds).

        ``BudgetChain`` calls this before each stage runs so stages that test
        many injection points can stop early once the wave budget is spent.
        Stores the deadline on the instance; ``_deadline_exceeded()`` checks it.
        """
        self._deadline = deadline  # type: ignore[attr-defined]

    def _deadline_exceeded(self) -> bool:
        """Return True if an absolute deadline is set and has passed."""
        deadline = getattr(self, "_deadline", None)
        if deadline is None:
            return False
        return time.monotonic() > deadline


__all__ = [
    "DetectionDepth",
    "DetectionStage",
    "StageResult",
]
