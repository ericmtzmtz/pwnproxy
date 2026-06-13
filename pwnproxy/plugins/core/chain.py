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
from pwnproxy.plugins.core.base import Finding

logger = logging.getLogger(__name__)


class DetectionDepth(str, Enum):
    """Detection depth controls which stages run."""
    FAST = "fast"           # Error-based only
    STANDARD = "standard"   # Error + boolean + time
    DEEP = "deep"           # All stages including OOB


@dataclass
class InjectionPoint:
    """A point in a request where injection is possible."""
    method: str
    host: str
    path: str
    name: str
    location: str  # "query", "body", "header", "cookie"
    original_value: str = ""
    
    @property
    def key(self) -> tuple:
        """Unique key for deduplication."""
        return (self.method, self.host + self.path, self.name, self.location)


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
        self.stages = sorted(stages, key=lambda s: s.order)
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
            
            try:
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
