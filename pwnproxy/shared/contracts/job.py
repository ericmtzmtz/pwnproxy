"""Job contract: JobState machine + Job model + typed JobStats."""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Annotated, Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ── JobState ────────────────────────────────────────────────────────────

class JobState(str, enum.Enum):
    """Canonical states for every job in the system.

    Transitions are validated by ``transition()`` (see D3 in design.md).
    """
    CREATED = "created"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# Backward-compat mapping for legacy DB status strings.
_LEGACY_MAP: dict[str, JobState] = {
    "queued": JobState.CREATED,
    "running": JobState.RUNNING,
    "completed": JobState.COMPLETED,
    "failed": JobState.FAILED,
    "stopped": JobState.CANCELLED,
}


# Legal transitions: current state → set of allowed next states.
_LEGAL_TRANSITIONS: dict[JobState, set[JobState]] = {
    JobState.CREATED:   {JobState.STARTING, JobState.CANCELLED},
    JobState.STARTING:  {JobState.RUNNING, JobState.FAILED, JobState.STOPPING},
    JobState.RUNNING:   {JobState.STOPPING, JobState.COMPLETED, JobState.FAILED},
    JobState.STOPPING:  {JobState.CANCELLED, JobState.FAILED},
    JobState.COMPLETED: set(),  # terminal
    JobState.FAILED:    set(),  # terminal
    JobState.CANCELLED: set(),  # terminal
}

TERMINAL_STATES: frozenset[JobState] = frozenset({
    JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED,
})


class InvalidJobTransition(Exception):
    """Raised when a job state transition is not allowed."""


def _resolve_state(v: Any) -> JobState:
    """Resolve a value to a JobState, handling legacy strings."""
    if isinstance(v, JobState):
        return v
    if isinstance(v, str):
        try:
            return JobState(v)
        except ValueError:
            mapped = _LEGACY_MAP.get(v)
            if mapped is not None:
                return mapped
            raise ValueError(f"Invalid job state: {v!r}")
    raise ValueError(f"Invalid job state: {v!r}")


def transition(job: "Job", new_state: JobState) -> JobState:
    """Validate and apply a state transition. Returns the new state.

    Raises ``InvalidJobTransition`` if the transition is illegal.
    The job's ``state`` field is mutated in place.
    """
    current = _resolve_state(job.state)
    allowed = _LEGAL_TRANSITIONS.get(current, set())
    if new_state not in allowed:
        raise InvalidJobTransition(
            f"Cannot transition from {current.value!r} to {new_state.value!r}"
        )
    job.state = new_state
    now = datetime.now(timezone.utc)
    if new_state == JobState.RUNNING and job.started_at is None:
        job.started_at = now
    if new_state in TERMINAL_STATES:
        job.finished_at = now
    return new_state


# ── JobStats ────────────────────────────────────────────────────────────

class CrawlStats(BaseModel):
    """Stats for active crawl jobs."""
    fetched: int = 0
    queued: int = 0
    discovered: int = 0
    errors: int = 0


class BruteforceStats(BaseModel):
    """Stats for directory bruteforce jobs."""
    probed: int = 0
    found: int = 0
    errors: int = 0
    skipped: int = 0
    soft404_filtered: int = 0
    total_planned: int = 0
    maxed: bool = False


# Union of all stat types, discriminated by job type.
JobStats = Annotated[
    Union[CrawlStats, BruteforceStats],
    Field(discriminator="fetched", default_factory=CrawlStats),
]


def stats_for_type(job_type: str) -> CrawlStats | BruteforceStats:
    """Return the appropriate stats model for a job type."""
    if job_type == "bruteforce":
        return BruteforceStats()
    return CrawlStats()


# ── Job ─────────────────────────────────────────────────────────────────

class Job(BaseModel):
    """Canonical job representation crossing storage / API / events."""
    model_config = ConfigDict(use_enum_values=True)

    id: int
    type: str  # "active", "passive", "bruteforce"
    state: JobState = JobState.CREATED
    config: dict[str, Any] = Field(default_factory=dict)
    stats: CrawlStats | BruteforceStats = Field(default_factory=CrawlStats)
    error: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, v: Any) -> JobState:
        """Accept both JobState enum values and plain strings."""
        return _resolve_state(v)
