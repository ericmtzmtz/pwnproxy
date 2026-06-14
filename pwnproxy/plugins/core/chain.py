"""Detection chain framework for multi-stage vulnerability detection.

Scanners use detection chains to escalate from fast/cheap techniques to
slow/expensive ones. Each stage only runs on injection points not yet
confirmed by a previous stage.

Example:
    class SQLiChain(DetectionChain):
        stages = [
            ErrorBasedStage(),      # Fast: check for SQL errors
            BooleanBlindStage(),    # Medium: boolean-based blind
            TimeBlindStage(),       # Slow: time-based blind
            OOBStage(),             # Slowest: out-of-band callback
        ]
"""
import logging
from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.plugins.core.base import Finding

logger = logging.getLogger(__name__)


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
        pass
    
    def should_run(self, depth: DetectionDepth) -> bool:
        """Check if this stage should run at the given depth."""
        depth_order = {
            DetectionDepth.FAST: 0,
            DetectionDepth.STANDARD: 1,
            DetectionDepth.DEEP: 2,
        }
        return depth_order[depth] >= depth_order[self.min_depth]


class DetectionChain:
    """Orchestrates multiple detection stages in order.
    
    Stages run in sequence. Confirmed injection points from earlier
    stages are removed from subsequent stages to avoid redundant testing.
    """
    
    def __init__(
        self,
        stages: list[DetectionStage],
        depth: DetectionDepth = DetectionDepth.FAST,
    ):
        self.stages = sorted(stages, key=lambda s: (getattr(s, "order", 0), id(s)))
        self.depth = depth
    
    async def run(
        self,
        flow: Flow,
        injection_points: list[InjectionPoint],
    ) -> AsyncGenerator[Finding, None]:
        """Run all applicable stages and yield findings.
        
        Args:
            flow: The HTTP flow to test
            injection_points: Initial injection points to test
            
        Yields:
            Finding for each confirmed vulnerability
        """
        # Track which points have been confirmed
        confirmed_keys: set[tuple] = set()
        
        for stage in self.stages:
            # Skip stages that require deeper depth
            if not stage.should_run(self.depth):
                logger.debug(
                    "Skipping stage %s (requires %s, have %s)",
                    stage.__class__.__name__,
                    stage.min_depth.value,
                    self.depth.value,
                )
                continue
            
            try:
                # Filter out already-confirmed injection points
                remaining_points = [
                    p for p in injection_points
                    if p.key not in confirmed_keys
                ]
                
                if not remaining_points:
                    logger.debug("No remaining injection points, stopping chain")
                    break
                
                logger.debug(
                    "Running stage %s on %d injection points",
                    stage.__class__.__name__,
                    len(remaining_points),
                )
                
                result = await stage.execute(flow, remaining_points)
                
                # Yield findings
                for finding in result.findings:
                    yield finding
                
                # Track confirmed points
                confirmed_keys.update(result.confirmed_points)
                
            except Exception as e:
                logger.warning(
                    "Stage %s failed: %s",
                    stage.__class__.__name__,
                    e,
                )
                continue


# Import time for BudgetChain
import time

# Convenience function for creating chains
def create_chain(
    stages: list[DetectionStage],
    depth: str | DetectionDepth = "fast",
) -> DetectionChain:
    """Create a detection chain from stages.
    
    Args:
        stages: List of detection stages
        depth: Detection depth ("fast", "standard", "deep")
        
    Returns:
        Configured DetectionChain
    """
    if isinstance(depth, str):
        depth = DetectionDepth(depth)
    return DetectionChain(stages, depth)


class BudgetChain(DetectionChain):
    """DetectionChain with automatic wave escalation and budget tracking.
    
    Runs stages in waves by depth level. If a wave produces no findings
    and unconfirmed injection points remain, escalates to the next wave
    as long as the time budget has not been exhausted.
    """

    WAVE_BUDGET_MS = {
        DetectionDepth.FAST: 3000,
        DetectionDepth.STANDARD: 15000,
        DetectionDepth.DEEP: 30000,
    }

    def __init__(
        self,
        stages: list[DetectionStage],
        depth: DetectionDepth = DetectionDepth.FAST,
        max_depth: DetectionDepth = DetectionDepth.DEEP,
        budget_ms: int = 30000,
    ):
        super().__init__(stages, depth)
        self._max_depth = max_depth
        self._budget_ms = budget_ms

    async def run(
        self,
        flow: Flow,
        injection_points: list[InjectionPoint],
    ) -> AsyncGenerator[Finding, None]:
        confirmed_keys: set[tuple] = set()
        start = time.monotonic()
        waves_order = [DetectionDepth.FAST, DetectionDepth.STANDARD, DetectionDepth.DEEP]

        for wave_depth in waves_order:
            # Start at configured depth, escalate up to max_depth
            if not self._depth_allows(wave_depth):
                continue

            elapsed_ms = (time.monotonic() - start) * 1000
            if elapsed_ms >= self._budget_ms:
                logger.info("BudgetChain: budget exhausted at wave %s", wave_depth.value)
                break

            remaining = [p for p in injection_points if p.key not in confirmed_keys]
            if not remaining:
                break

            wave_stages = [s for s in self.stages if s.min_depth == wave_depth]
            if not wave_stages:
                continue

            wave_findings = 0
            for stage in wave_stages:
                if (time.monotonic() - start) * 1000 >= self._budget_ms:
                    break
                try:
                    result = await stage.execute(flow, remaining)
                    for finding in result.findings:
                        wave_findings += 1
                        yield finding
                    confirmed_keys.update(result.confirmed_points)
                except Exception as e:
                    logger.warning("BudgetChain: stage %s failed: %s", stage.__class__.__name__, e)

            # If wave found nothing and no points confirmed, escalate
            if wave_findings == 0 and not confirmed_keys:
                logger.debug("BudgetChain: escalating to next wave (%s)", wave_depth.value)

    def _depth_allows(self, wave_depth: DetectionDepth) -> bool:
        depth_order = {
            DetectionDepth.FAST: 0,
            DetectionDepth.STANDARD: 1,
            DetectionDepth.DEEP: 2,
        }
        return depth_order[self.depth] <= depth_order[wave_depth] <= depth_order[self._max_depth]


def chain_from_depth(stages: list[DetectionStage], depth: str = "fast", budget_ms: int | None = None) -> BudgetChain:
    """Create a BudgetChain from depth string.
    
    Starts at configured depth, escalates up to DEEP if budget permits.
    Maps depth to default budget if no explicit budget_ms provided.
    """
    if isinstance(depth, str):
        depth = DetectionDepth(depth)
    if budget_ms is None:
        budget_ms = BudgetChain.WAVE_BUDGET_MS.get(DetectionDepth.DEEP, 30000)
    return BudgetChain(stages, depth=depth, max_depth=DetectionDepth.DEEP, budget_ms=budget_ms)

